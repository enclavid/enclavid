//! Webhooks: a consumer told that its session ended.
//!
//! A session whose consumer gave a webhook gets a notice at its creation, due at
//! its `expires_at` ([`timer`]). A write that ends the session before then — its
//! policy gave a decision, or it could not be prepared to run — puts a notice
//! due at once in its place ([`notice`]). [`Webhooks`] takes each notice once it
//! is due, reads the session it is about, and sends the webhook through the
//! hatch, one attempt at a time: a `2xx` settles the notice, anything else makes
//! it due at the next step of its schedule, and a notice past the last step is
//! dropped.
//!
//! Notices are taken as they come due: when a write here adds one, when an
//! attempt ends, and when the store says the next one is. Each then waits for
//! its consumer's turn — a few of one consumer's attempts are under way at once
//! — so an endpoint that stalls holds up only its own consumer's webhooks.
//!
//! What is sent says only that the session ended —
//! `{"type":"session.ended","data":{"consumer_ref"?,"sealed_session_id"}}`, padded
//! to one length and signed as Standard Webhooks signs. The consumer reads what
//! the session came to with its own token. How often and how soon it is sent is
//! the host's to tune ([`Settings`]); the padding is not.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use base64ct::{Base64, Encoding};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::task::JoinSet;
use tokio::time::Instant;

use enclavid_boundary::{AuthN, AuthZ, Covert, ExposedBuilder, Replay, reason};
use hatch_client::{DEFAULT_WEBHOOK_DEADLINE, Link, WebhookClient, WebhookRequest};
use session_types::{SessionMetadata, SessionStatus, Webhook};
use storage_client::boundary::Storage;
use storage_client::{
    AddNotice, Metadata, NextDue, NoticeDue, NoticeHandle, NoticeOp, SessionStore, Settle, Take,
    TakenNotice,
};
use storage_rpc::MAX_NOTICE_HOLD_SECS;
use storage_rpc::MAX_NOTICES_TAKEN;

use crate::boundary::Hatch;
use crate::clock;
use crate::compositions::principal;
use crate::semaphores::Semaphores;

/// How webhooks are sent, as the host tunes it ([`crate::settings`]).
#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    /// When a notice is due again after an attempt that did not take, in
    /// seconds from when it was first due, rising; past the last step it is
    /// dropped (`webhook-schedule-secs`).
    pub schedule: Vec<u64>,
    /// How long the hatch has to answer one attempt: past its own wait on the
    /// endpoint (`webhook-deadline-secs`).
    pub deadline: Duration,
    /// The longest a notice waits for its consumer's turn; past it, the notice
    /// is left to its hold (`webhook-turn-wait-secs`).
    pub turn_wait: Duration,
    /// The longest the store goes unasked: a notice no write here woke the
    /// taker for — one kept by a write whose answer was lost, say — is taken
    /// within it (`webhook-look-secs`).
    pub look: Duration,
    /// How many notices are held here at once — taken and not yet settled —
    /// all consumers' together (`webhooks-held`).
    pub held: usize,
    /// How many of those may be one consumer's: more of its notices are left
    /// to their hold (`webhooks-held-per-consumer`).
    pub held_per_consumer: usize,
    /// How many of one consumer's attempts are under way at once
    /// (`webhooks-sending-per-consumer`).
    pub sending_per_consumer: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            // The Standard Webhooks schedule as Svix runs it: 5 s, then 5 min,
            // 30 min, 2 h, 5 h, 10 h and 10 h after each attempt.
            schedule: vec![5, 305, 2_105, 9_305, 27_305, 63_305, 99_305],
            deadline: DEFAULT_WEBHOOK_DEADLINE,
            turn_wait: Duration::from_secs(30),
            look: Duration::from_secs(60),
            held: 1024,
            held_per_consumer: 256,
            sending_per_consumer: 4,
        }
    }
}

impl Settings {
    /// How long a notice taken is held from other takes: past the longest it
    /// waits for its turn, the attempt's deadline, and the read and settle
    /// around them.
    pub fn hold(&self) -> Duration {
        self.turn_wait + self.deadline + READ_AND_SETTLE
    }

    /// Why these settings send no webhook as they say, if they do not: a hold
    /// past the longest the store holds a notice, which would hand one out
    /// again while its attempt is under way.
    pub fn refusal(&self) -> Option<&'static str> {
        (self.hold() > Duration::from_secs(u64::from(MAX_NOTICE_HOLD_SECS))).then_some(
            "the webhook turn wait and deadline together hold a notice past what the store holds \
             one for",
        )
    }
}

/// What a notice's hold leaves for the read before its attempt and the settle
/// after it.
const READ_AND_SETTLE: Duration = Duration::from_secs(10);
/// The soonest the store is asked again after a take that found less than it
/// had room for, whatever it says is due next.
const SOONEST: Duration = Duration::from_secs(1);
/// How long after a take that failed the store is asked again.
const AFTER_FAILURE: Duration = Duration::from_secs(5);
/// The bytes a notice is kept in, whatever it holds.
const NOTICE_FRAME: usize = 512;
/// The bytes a webhook's body is sent in, whatever it says.
const BODY_BYTES: usize = 512;
/// The one kind of webhook.
const SESSION_ENDED: &str = "session.ended";

/// What a session's notice holds: what sending its webhook takes that the
/// session's metadata does not.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct NoticeBody {
    session_id: String,
    /// The consumer whose turns it waits for: a digest of the one its session
    /// counts against ([`principal`]), one size whatever its name.
    consumer: [u8; 32],
    /// When the notice was first due, in unix seconds: what the schedule counts
    /// from.
    first_due: u64,
    /// The session id sealed to the consumer's webhook key, in base64: sealed
    /// once, so every attempt carries the same bytes.
    sealed_session_id: String,
}

/// The unix time `at` on this side's clock: now, where it has passed.
fn instant(at: u64) -> Instant {
    Instant::now() + Duration::from_secs(at.saturating_sub(clock::now()))
}

/// `body` as a notice keeps it: its CBOR in [`NOTICE_FRAME`] bytes, zeros after
/// it.
fn frame(body: &NoticeBody) -> Result<Vec<u8>, String> {
    let mut frame = session_types::encode(body).map_err(|e| e.to_string())?;
    if frame.len() > NOTICE_FRAME {
        return Err(format!("a notice past {NOTICE_FRAME} bytes"));
    }
    frame.resize(NOTICE_FRAME, 0);
    Ok(frame)
}

/// The value of a notice of `session_id`, first due at `first_due`: `None`
/// where its consumer asked for no webhook, or where the session id does not
/// seal to the key it gave.
fn value(
    session_id: &str,
    metadata: &SessionMetadata,
    first_due: u64,
) -> Option<ExposedBuilder<Vec<u8>, NoticeOp, (AuthN,), Storage>> {
    let consumer = metadata.consumer.as_ref()?;
    let webhook = consumer.webhook.as_ref()?;
    let sealed = enclavid_crypto::seal_to_recipient(session_id.as_bytes(), &webhook.pubkey)
        .inspect_err(|e| safe_logger::debug!("webhooks: sealing the id of {session_id}: {e}"))
        .ok()?;
    let body = NoticeBody {
        session_id: session_id.to_owned(),
        consumer: Sha256::digest(principal(consumer)).into(),
        first_due,
        sealed_session_id: Base64::encode_string(&sealed),
    };
    Storage::expose_builder::<NoticeOp, _>(&body)
        .vouch_with(Covert::Transformed, frame)
        .inspect_err(|e| safe_logger::debug!("webhooks: the notice of {session_id}: {e}"))
        .ok()
}

/// The notice of a session that ends with the write `metadata` goes in, due at
/// once: `None` where its consumer asked for no webhook, or where the session
/// id does not seal to the key it gave — the session then ends as it would
/// without one.
pub fn notice(session_id: &str, metadata: &SessionMetadata) -> Option<AddNotice> {
    let now = clock::now();
    let value = value(session_id, metadata, now)?;
    let due = Storage::expose(NoticeDue(now))
        .vouch(reason!(
            AuthN::Indifferent,
            "the time of the write it rides in, which the host watches land"
        ))
        .vouch(reason!(
            AuthZ::NoSecret,
            "when the store hands the notice back: the time of a write it holds already"
        ))
        .vouch(reason!(
            Covert::AlreadyHeld,
            "the time of the write that ends the session, which the host watches land"
        ));
    Some(AddNotice { due, value })
}

/// The notice a session is created with, due at its `expires_at`: what tells
/// its consumer that its time ran out, unless a write that ends it first puts
/// its own notice in this one's place. `None` as for [`notice`].
pub fn timer(session_id: &str, metadata: &SessionMetadata) -> Option<AddNotice> {
    let at = metadata.expires_at;
    let value = value(session_id, metadata, at)?;
    let due = Storage::expose(NoticeDue(at))
        .vouch(reason!(
            AuthN::Indifferent,
            "when the store hands the notice back, and the session is read as it stands \
             then: before its expiry it waits, after it the webhook says what is so"
        ))
        .vouch(reason!(
            AuthZ::NoSecret,
            "the session's expires_at, which the record's deadline beside it shows already"
        ))
        .vouch(reason!(
            Covert::AlreadyHeld,
            "the consumer's expires_at: the record's deadline is it and the keep the host \
             sets itself"
        ));
    Some(AddNotice { due, value })
}

#[derive(Serialize)]
struct Payload<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    data: Data<'a>,
}

#[derive(Serialize)]
struct Data<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    consumer_ref: Option<&'a str>,
    sealed_session_id: &'a str,
}

/// The webhook of `notice` as sent at `now`: its body padded to [`BODY_BYTES`],
/// and signed under the consumer's key as Standard Webhooks signs.
fn request(notice: &NoticeBody, consumer_ref: &str, webhook: &Webhook, now: u64) -> WebhookRequest {
    let payload = Payload {
        kind: SESSION_ENDED,
        data: Data {
            consumer_ref: Some(consumer_ref).filter(|r| !r.is_empty()),
            sealed_session_id: &notice.sealed_session_id,
        },
    };
    let mut body = serde_json::to_vec(&payload).expect("a payload of strings encodes");
    if body.len() < BODY_BYTES {
        body.resize(BODY_BYTES, b' ');
    }
    let timestamp = now.to_string();
    let signature = sign(&webhook.secret, &webhook.id, &timestamp, &body);
    WebhookRequest {
        url: webhook.url.clone(),
        headers: vec![
            ("webhook-id".into(), webhook.id.clone()),
            ("webhook-timestamp".into(), timestamp),
            ("webhook-signature".into(), format!("v1,{signature}")),
        ],
        body,
    }
}

/// The Standard Webhooks signature: HMAC-SHA256 under `key` over
/// `{id}.{timestamp}.{body}`, in base64.
fn sign(key: &[u8], id: &str, timestamp: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    Base64::encode_string(&mac.finalize().into_bytes())
}

/// What becomes of a notice first due at `first_due` whose attempt at `now` did
/// not take: due at the first step of `schedule` past `now`, or dropped past
/// the last.
fn again(schedule: &[u64], first_due: u64, now: u64) -> Settle {
    schedule
        .iter()
        .map(|step| first_due.saturating_add(*step))
        .find(|due| *due > now)
        .map_or(Settle::Done, |due_unix_secs| Settle::Again {
            due_unix_secs,
        })
}

/// What becomes of a notice taken at `now` while its session runs, before its
/// `expires_at`: due at the first step of `schedule` past `now`, or at
/// `expires_at` where that comes first. Never dropped: past the last step it is
/// due at `expires_at`, when the session has ended one way or the other.
fn waiting(schedule: &[u64], first_due: u64, expires_at: u64, now: u64) -> Settle {
    let due_unix_secs = match again(schedule, first_due, now) {
        Settle::Again { due_unix_secs } => due_unix_secs.min(expires_at),
        Settle::Done => expires_at,
    };
    Settle::Again { due_unix_secs }
}

/// Sends each notice's webhook as it comes due, through the hatch.
pub struct Webhooks {
    store: Arc<SessionStore>,
    hatch: WebhookClient<Hatch>,
    settings: Settings,
    /// Each consumer's notices held here.
    held: Semaphores<[u8; 32]>,
    /// Each consumer's attempts under way.
    sending: Semaphores<[u8; 32]>,
}

impl Webhooks {
    pub fn new(store: Arc<SessionStore>, hatch: Arc<dyn Link<Hatch>>, settings: Settings) -> Self {
        Self {
            store,
            hatch: WebhookClient::new(hatch, settings.deadline),
            held: Semaphores::new(settings.held_per_consumer),
            sending: Semaphores::new(settings.sending_per_consumer),
            settings,
        }
    }

    /// Take notices as they come due and send each one's webhook, for as long as
    /// api runs.
    pub async fn run(self) {
        let this = Arc::new(self);
        let mut under_way = JoinSet::new();
        let mut next = Instant::now();
        loop {
            while under_way.len() < this.settings.held && next <= Instant::now() {
                next = this.take(&mut under_way).await;
            }
            let room = under_way.len() < this.settings.held;
            tokio::select! {
                () = this.store.notice_written() => next = Instant::now(),
                Some(ended) = under_way.join_next() => {
                    if let Ok(Some(due)) = ended {
                        next = next.min(instant(due));
                    }
                }
                () = tokio::time::sleep_until(next), if room => {}
            }
        }
    }

    /// Take as many due notices as there is room for and start each on its way
    /// in `under_way`, which ends with the unix time it is due again, if it is;
    /// when to take again.
    async fn take(self: &Arc<Self>, under_way: &mut JoinSet<Option<u64>>) -> Instant {
        let now = Instant::now();
        let room = (self.settings.held - under_way.len()).min(MAX_NOTICES_TAKEN as usize);
        let hold = self.settings.hold();
        let Take { notices, next_due } = match self.store.take_notices(room as u32, hold).await {
            Ok(take) => take,
            Err(e) => {
                safe_logger::debug!("webhooks: taking the due notices: {e}");
                return now + AFTER_FAILURE;
            }
        };
        let filled = notices.len() == room;
        for notice in notices {
            let notice = notice
                .trust(reason!(
                    AuthZ::NoPrincipal,
                    "a notice this side sealed for a session it runs: nobody's request to \
                     authorize"
                ))
                .trust(reason!(
                    Replay::Harmless,
                    "an older notice put back sends the webhook again under the id its session \
                     keeps, and the consumer reads what the session came to with its own token"
                ))
                .into_inner();
            self.start(notice, under_way);
        }
        // More may be due: taken once there is room.
        if filled {
            return now;
        }
        let NextDue(next) = next_due
            .trust(reason!(
                AuthN::Indifferent,
                "only when the store is asked again, held to between a second from now and the \
                 longest it goes unasked"
            ))
            .trust(reason!(
                Replay::Harmless,
                "an older time is held to the same bounds as any"
            ))
            .into_inner();
        let latest = now + self.settings.look;
        next.map_or(latest, instant).clamp(now + SOONEST, latest)
    }

    /// Start `notice` on its way where its consumer has room for it: it waits
    /// for its consumer's turn, then makes its attempt. One that does not read
    /// is dropped; one its consumer has no room for is left to its hold.
    fn start(self: &Arc<Self>, notice: TakenNotice, under_way: &mut JoinSet<Option<u64>>) {
        let TakenNotice { handle, value } = notice;
        let this = self.clone();
        let Ok(body) = session_types::decode::<NoticeBody>(&value) else {
            under_way.spawn(async move {
                this.settle(&handle, Settle::Done).await;
                None
            });
            return;
        };
        let Ok(place) = self.held.of(&body.consumer).try_acquire_owned() else {
            return;
        };
        let turns = self.sending.of(&body.consumer);
        let wait = self.settings.turn_wait;
        under_way.spawn(async move {
            let _place = place;
            let Ok(Ok(_turn)) = tokio::time::timeout(wait, turns.acquire_owned()).await else {
                return None;
            };
            let settle = this.attempt(&body).await;
            this.settle(&handle, settle).await;
            match settle {
                Settle::Again { due_unix_secs } => Some(due_unix_secs),
                Settle::Done => None,
            }
        });
    }

    async fn settle(&self, handle: &NoticeHandle, settle: Settle) {
        if let Err(e) = self.store.settle_notice(handle, settle).await {
            safe_logger::debug!("webhooks: settling a notice: {e}");
        }
    }

    /// One attempt at the webhook of `notice`, and what becomes of the notice.
    async fn attempt(&self, notice: &NoticeBody) -> Settle {
        let now = clock::now();
        let due_again = || again(&self.settings.schedule, notice.first_due, now);
        let ((metadata,), _version) = match self.store.read(&notice.session_id, (Metadata,)).await {
            Ok(read) => read,
            Err(e) => {
                safe_logger::debug!("webhooks: reading {}: {e}", notice.session_id);
                return due_again();
            }
        };
        let metadata = metadata
            .trust(reason!(
                AuthZ::NoPrincipal,
                "read for this side's own notice about the session, and sent to nobody but the \
                 consumer the session names"
            ))
            .trust(reason!(
                Replay::Harmless,
                "a session put back from before it ended reads as running, and the notice waits \
                 for it"
            ))
            .into_inner();
        // Gone: the store dropped it at its deadline, and the webhook with it.
        let Some(metadata) = metadata else {
            return Settle::Done;
        };
        match metadata.status {
            SessionStatus::Completed | SessionStatus::InitFailed => {}
            // Its time ran out: the webhook says it ended, and its view that it
            // expired.
            SessionStatus::Running if metadata.expired_at(now) => {}
            // A notice whose write did not land, or one taken before its write
            // did: it waits for the session to end, at the latest at its
            // `expires_at`.
            SessionStatus::Running => {
                return waiting(
                    &self.settings.schedule,
                    notice.first_due,
                    metadata.expires_at,
                    now,
                );
            }
            SessionStatus::Unspecified => return due_again(),
        }
        let Some(consumer) = metadata.consumer else {
            return Settle::Done;
        };
        let Some(webhook) = consumer.webhook else {
            return Settle::Done;
        };
        let Ok(built) =
            Hatch::expose_builder::<WebhookRequest, _>((notice, consumer.r#ref.as_str(), &webhook))
                .vouch_with(Covert::Transformed, |(notice, consumer_ref, webhook)| {
                    Ok::<_, Infallible>(request(notice, consumer_ref, webhook, now))
                });
        let request = built
            .vouch(reason!(
                AuthN::Indifferent,
                "TLS from the hatch to the endpoint the consumer named carries it, and what it \
                 holds is the consumer's own — its ref and its endpoint — or opens only with its \
                 keys: the session id sealed to its key, a signature only its secret checks"
            ))
            .build();
        let accepted = match self.hatch.send(request).await {
            Ok(answer) => answer.into_inner().accepted,
            Err(e) => {
                safe_logger::debug!("webhooks: {} got no answer: {e}", notice.session_id);
                false
            }
        };
        if accepted { Settle::Done } else { due_again() }
    }

    /// One take, and each notice it took seen to its end.
    #[cfg(test)]
    async fn step(self: &Arc<Self>) {
        let mut under_way = JoinSet::new();
        self.take(&mut under_way).await;
        while under_way.join_next().await.is_some() {}
    }
}

#[cfg(test)]
mod tests;
