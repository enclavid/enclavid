//! A webhook as it is built, and notices as the dispatcher takes and settles
//! them: a store in memory, and a hatch served over a real leg whose every
//! webhook comes to the test.

use std::sync::Mutex;

use enclavid_boundary::{Exposed, Untrusted};
use enclavid_boundary_macros::boundary;
use fleet_stream::bin;
use hatch_rpc::{
    AuthorizeError, AuthorizeRequest, BlobRequest, HatchLeg, KbsError, KbsRequest, KbsResponse,
    LegSettings, Manifest, ManifestRequest, PullError, RemoteHatchAt, Verdict, WebhookAnswer,
    WebhookError,
};
use session_types::{Consumer, ConsumerAccess};
use storage_client::memory::Disk;
use storage_client::{MetadataOp, SetMetadata};

use super::*;

boundary! {
    /// The hatch, for the test: every concern answered.
    Endpoint {
        serves: [hatch_rpc::RemoteHatch],
        observer: Test,
    }
    in (AuthN,) {
        /// test fixture
        _: AuthN::Indifferent,
        AuthorizeRequest,
        ManifestRequest,
        BlobRequest,
        KbsRequest,
        WebhookRequest,
    }
    out (AuthN,) {
        /// test fixture
        _: AuthN::Indifferent,
        Verdict,
        AuthorizeError,
        Manifest,
        PullError,
        bin::Receiver,
        KbsResponse,
        KbsError,
        WebhookAnswer,
        WebhookError,
    }
}

/// An endpoint that never answers.
const STALLS: &str = "https://stalls.example/enclavid";

/// A hatch that keeps every webhook it is sent and answers each with the next
/// of `answers` — taken or not — or with no answer once they run out. A webhook
/// to [`STALLS`] is never answered.
#[derive(Clone, Default)]
struct FakeHatch {
    sent: Arc<Mutex<Vec<WebhookRequest>>>,
    answers: Arc<Mutex<Vec<bool>>>,
}

impl FakeHatch {
    fn answering(answers: &[bool]) -> Self {
        Self {
            answers: Arc::new(Mutex::new(answers.to_vec())),
            ..Self::default()
        }
    }

    fn sent(&self) -> Vec<WebhookRequest> {
        self.sent.lock().unwrap().clone()
    }

    /// How many webhooks went to `url`.
    fn sent_to(&self, url: &str) -> usize {
        self.sent().iter().filter(|w| w.url == url).count()
    }
}

impl RemoteHatchAt<Endpoint> for FakeHatch {
    async fn authorize(
        &self,
        _req: Untrusted<AuthorizeRequest, (), Endpoint>,
    ) -> Result<Exposed<Verdict, (), Endpoint>, AuthorizeError> {
        Err(AuthorizeError("not asked here".into()))
    }

    async fn manifest(
        &self,
        _req: Untrusted<ManifestRequest, (), Endpoint>,
    ) -> Result<Exposed<Manifest, (), Endpoint>, PullError> {
        Err(PullError::NotFound)
    }

    async fn blob(
        &self,
        _req: Untrusted<BlobRequest, (), Endpoint>,
    ) -> Result<Exposed<bin::Receiver, (), Endpoint>, PullError> {
        Err(PullError::NotFound)
    }

    async fn kbs(
        &self,
        _req: Untrusted<KbsRequest, (), Endpoint>,
    ) -> Result<Exposed<KbsResponse, (), Endpoint>, KbsError> {
        Err(KbsError("not asked here".into()))
    }

    async fn webhook(
        &self,
        req: Untrusted<WebhookRequest, (), Endpoint>,
    ) -> Result<Exposed<WebhookAnswer, (), Endpoint>, WebhookError> {
        let req = req.into_inner();
        let stalls = req.url == STALLS;
        self.sent.lock().unwrap().push(req);
        if stalls {
            std::future::pending::<()>().await;
        }
        let mut answers = self.answers.lock().unwrap();
        if answers.is_empty() {
            return Err(WebhookError("the endpoint did not answer".into()));
        }
        Ok(Endpoint::expose(WebhookAnswer {
            accepted: answers.remove(0),
        }))
    }
}

/// The leg, always up.
struct Up(Arc<HatchLeg<Hatch>>);

impl Link<Hatch> for Up {
    fn leg(&self) -> Option<Arc<HatchLeg<Hatch>>> {
        Some(self.0.clone())
    }
}

/// `fake` served on one end of a connection, and the link to it from the other,
/// at api's own end of the hatch leg.
async fn hatch(fake: FakeHatch) -> Arc<dyn Link<Hatch>> {
    let (a, b) = tokio::io::duplex(64 * 1024);
    let (a_r, a_w) = tokio::io::split(a);
    let (b_r, b_w) = tokio::io::split(b);
    tokio::spawn(async move {
        hatch_rpc::serve_hatch::<Endpoint, _, _, _>(a_r, a_w, fake, 16, &LegSettings::default())
            .await
            .unwrap();
    });
    let (leg, _ended) = hatch_rpc::connect_hatch::<Hatch, _, _>(b_r, b_w, &LegSettings::default())
        .await
        .unwrap();
    Arc::new(Up(Arc::new(leg)))
}

const KEY: [u8; 32] = [7; 32];
/// The consumer's signing key: 24 bytes, the least a Standard Webhooks secret
/// has.
const SECRET: &[u8] = b"a signing key of 24 byte";
const URL: &str = "https://hooks.example/enclavid";
const WEBHOOK_ID: &str = "msg_0123456789abcdef0123456789abcdef";

/// When the sessions a test creates are dropped: far past any test's run.
const UNTIL: u64 = 4_000_000_000;

/// A store in memory, and the disk it keeps.
async fn store() -> (Arc<Disk>, Arc<SessionStore>) {
    let disk = Arc::new(Disk::default());
    let store = Arc::new(SessionStore::new(disk.connect().await, KEY));
    (disk, store)
}

/// The consumer `principal`, its webhook to `url` sealing to `pubkey`.
fn consumer(principal: &str, url: &str, pubkey: &str) -> Consumer {
    Consumer {
        access: Some(ConsumerAccess {
            principal: Some(principal.into()),
            ..ConsumerAccess::default()
        }),
        r#ref: "order-8812".into(),
        webhook: Some(Webhook {
            id: WEBHOOK_ID.into(),
            url: url.into(),
            secret: SECRET.to_vec(),
            pubkey: pubkey.into(),
        }),
        ..Consumer::default()
    }
}

/// The session `id` of `consumer` with `status`, expiring an hour from now,
/// written by one write with the notice it adds — as the write that ends a
/// session adds it.
async fn session(store: &SessionStore, id: &str, status: SessionStatus, consumer: Consumer) {
    let metadata = metadata(status, clock::now() + 3600, consumer);
    let notice = notice(id, &metadata).expect("a webhook, so a notice");
    write(store, id, &metadata, &notice).await;
}

/// A session of `consumer` with `status`, expiring at `expires_at`.
fn metadata(status: SessionStatus, expires_at: u64, consumer: Consumer) -> SessionMetadata {
    SessionMetadata {
        status,
        expires_at,
        consumer: Some(consumer),
        ..SessionMetadata::default()
    }
}

/// The session `id`, created with `metadata` and `notice`.
async fn write(store: &SessionStore, id: &str, metadata: &SessionMetadata, notice: &AddNotice) {
    let set = SetMetadata(
        Storage::expose_builder::<MetadataOp, _>(metadata)
            .vouch(reason!(Covert::NotChosen, "test fixture")),
    );
    let ops = store
        .seal(id, &[&set, notice])
        .unwrap()
        .vouch(reason!(Covert::Bounded, "test fixture"));
    store.create(UNTIL, ops).await.unwrap();
}

fn header<'a>(webhook: &'a WebhookRequest, name: &str) -> &'a str {
    &webhook
        .headers
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("{name} is sent"))
        .1
}

/// When the notices kept are due.
fn due(disk: &Disk) -> Vec<u64> {
    disk.notices
        .lock()
        .unwrap()
        .values()
        .map(|n| n.due_unix_secs)
        .collect()
}

/// Every notice kept due at once.
fn all_due(disk: &Disk) {
    disk.notices
        .lock()
        .unwrap()
        .values_mut()
        .for_each(|n| n.due_unix_secs = 0);
}

/// The dispatcher as this build defaults it, sending through `fake`.
async fn webhooks(store: &Arc<SessionStore>, fake: &FakeHatch) -> Arc<Webhooks> {
    let hatch = hatch(fake.clone()).await;
    Arc::new(Webhooks::new(store.clone(), hatch, Settings::default()))
}

/// Wait, up to a few seconds, until `done` holds.
async fn until(done: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("in time");
}

/// The signature is the one Standard Webhooks specifies, checked against its
/// own published example.
#[test]
fn the_signature_is_the_standard_one() {
    let key = Base64::decode_vec("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap();
    assert_eq!(
        sign(
            &key,
            "msg_p5jXN8AQM9LWM0D4loKWxJek",
            "1614265330",
            br#"{"test": 2432232314}"#
        ),
        "g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
    );
}

/// Whatever a consumer's ref, and with none, the body is one length and reads
/// as JSON.
#[test]
fn every_body_is_one_length() {
    let notice = NoticeBody {
        session_id: format!("ses_{}", "0".repeat(64)),
        consumer: [0; 32],
        first_due: u64::MAX,
        // What the sealed box of a session id comes to in base64.
        sealed_session_id: "A".repeat(156),
    };
    let webhook = Webhook {
        id: WEBHOOK_ID.into(),
        url: URL.into(),
        secret: SECRET.to_vec(),
        pubkey: "00".repeat(32),
    };
    let quotes = "\"".repeat(crate::limits::MAX_CONSUMER_REF_LEN);
    for consumer_ref in ["", "order-8812", quotes.as_str()] {
        let body = request(&notice, consumer_ref, &webhook, 0).body;
        assert_eq!(body.len(), BODY_BYTES, "{consumer_ref:?}");
        let read: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(read["type"], "session.ended");
        assert_eq!(
            read["data"].get("consumer_ref").and_then(|r| r.as_str()),
            Some(consumer_ref).filter(|r| !r.is_empty())
        );
    }
}

/// A notice is kept in one frame whatever it holds, and reads back as it was.
#[test]
fn a_notice_is_kept_in_one_frame() {
    let notice = NoticeBody {
        session_id: format!("ses_{}", "f".repeat(64)),
        consumer: [0xff; 32],
        first_due: u64::MAX,
        sealed_session_id: "A".repeat(156),
    };
    let kept = frame(&notice).unwrap();
    assert_eq!(kept.len(), NOTICE_FRAME);
    assert_eq!(session_types::decode::<NoticeBody>(&kept).unwrap(), notice);
}

/// A notice taken while its session runs is due at the schedule's next step, or
/// at the session's `expires_at` where that comes first — past the last step
/// too, never dropped.
#[test]
fn a_running_sessions_notice_waits_until_its_expiry_at_the_latest() {
    let schedule = Settings::default().schedule;
    let waiting = |expires_at, now| waiting(&schedule, 100, expires_at, now);
    assert_eq!(waiting(1_000, 100), Settle::Again { due_unix_secs: 105 });
    assert_eq!(waiting(300, 105), Settle::Again { due_unix_secs: 300 });
    assert_eq!(
        waiting(200_000, 99_405),
        Settle::Again {
            due_unix_secs: 200_000
        }
    );
}

/// A notice not taken is due at the schedule's next step past the attempt, and
/// dropped past its last.
#[test]
fn the_schedule_steps_then_ends() {
    let schedule = Settings::default().schedule;
    let again = |now| again(&schedule, 100, now);
    assert_eq!(again(100), Settle::Again { due_unix_secs: 105 });
    assert_eq!(again(105), Settle::Again { due_unix_secs: 405 });
    assert_eq!(
        again(99_404),
        Settle::Again {
            due_unix_secs: 99_405
        }
    );
    assert_eq!(again(99_405), Settle::Done);
}

/// The defaults hold a notice for as long as the store does at most; a wait
/// and a deadline that would hold one longer are refused.
#[test]
fn a_hold_past_the_stores_is_refused() {
    let defaults = Settings::default();
    assert_eq!(defaults.hold(), Duration::from_secs(60));
    assert_eq!(defaults.refusal(), None);
    let longer = Settings {
        turn_wait: Duration::from_secs(u64::from(MAX_NOTICE_HOLD_SECS)),
        ..Settings::default()
    };
    assert!(longer.refusal().is_some());
}

/// An ended session's webhook goes to its endpoint once: under the id its
/// session keeps, signed as its consumer checks, one length, saying only that
/// the session ended, the session's id opening with the consumer's key. Taken,
/// the notice is gone.
#[tokio::test]
async fn an_ended_session_sends_its_webhook_once() {
    let (disk, store) = store().await;
    let (secret, public) = enclavid_crypto::generate_recipient();
    let ended = SessionStatus::Completed;
    session(&store, "ses_a", ended, consumer("org-1", URL, &public)).await;
    let fake = FakeHatch::answering(&[true]);
    let webhooks = webhooks(&store, &fake).await;
    webhooks.step().await;

    let sent = fake.sent();
    assert_eq!(sent.len(), 1);
    let webhook = &sent[0];
    assert_eq!(webhook.url, URL);
    assert_eq!(header(webhook, "webhook-id"), WEBHOOK_ID);
    assert_eq!(webhook.body.len(), BODY_BYTES);
    assert_eq!(
        header(webhook, "webhook-signature"),
        format!(
            "v1,{}",
            sign(
                SECRET,
                WEBHOOK_ID,
                header(webhook, "webhook-timestamp"),
                &webhook.body
            )
        )
    );
    let body: serde_json::Value = serde_json::from_slice(&webhook.body).unwrap();
    assert_eq!(body["type"], "session.ended");
    assert_eq!(body["data"]["consumer_ref"], "order-8812");
    let sealed = Base64::decode_vec(body["data"]["sealed_session_id"].as_str().unwrap()).unwrap();
    assert_eq!(
        enclavid_crypto::open_sealed(&sealed, &secret).unwrap(),
        b"ses_a"
    );

    assert!(due(&disk).is_empty());
    webhooks.step().await;
    assert_eq!(fake.sent().len(), 1);
}

/// A webhook its endpoint does not take — refused, or no answer — is due again
/// at the schedule's first step, and goes out again under the same id.
#[tokio::test]
async fn a_webhook_not_taken_is_due_again() {
    let (disk, store) = store().await;
    let (_secret, public) = enclavid_crypto::generate_recipient();
    let before = clock::now();
    let failed = SessionStatus::InitFailed;
    session(&store, "ses_a", failed, consumer("org-1", URL, &public)).await;
    let fake = FakeHatch::answering(&[false]);
    let webhooks = webhooks(&store, &fake).await;

    webhooks.step().await;
    let after = clock::now();
    let first = due(&disk);
    assert_eq!(first.len(), 1);
    assert!((before + 5..=after + 5).contains(&first[0]), "{first:?}");

    all_due(&disk);
    webhooks.step().await;
    let sent = fake.sent();
    assert_eq!(sent.len(), 2, "sent again once due");
    assert_eq!(header(&sent[1], "webhook-id"), WEBHOOK_ID);
    assert_eq!(due(&disk).len(), 1, "no answer: still kept");
}

/// A notice about a session that has not ended — one whose write did not land
/// — sends nothing and waits; one about a session gone is dropped.
#[tokio::test]
async fn a_notice_is_sent_only_for_a_session_that_ended() {
    let (disk, store) = store().await;
    let (_secret, public) = enclavid_crypto::generate_recipient();
    let running = SessionStatus::Running;
    session(
        &store,
        "ses_running",
        running,
        consumer("org-1", URL, &public),
    )
    .await;
    let fake = FakeHatch::answering(&[true]);
    let webhooks = webhooks(&store, &fake).await;

    webhooks.step().await;
    assert!(fake.sent().is_empty());
    assert_eq!(due(&disk).len(), 1, "it waits");

    disk.records.lock().unwrap().clear();
    all_due(&disk);
    webhooks.step().await;
    assert!(fake.sent().is_empty());
    assert!(due(&disk).is_empty(), "the session is gone, and its notice");
}

/// A session is created with a notice due at its `expires_at`: taken before
/// then it waits for that time, and once the session's time is up it sends the
/// webhook as for any end, the session id sealed to the consumer's key.
#[tokio::test]
async fn a_session_whose_time_runs_out_sends_its_webhook() {
    let (disk, store) = store().await;
    let (secret, public) = enclavid_crypto::generate_recipient();
    let running = SessionStatus::Running;
    let later = clock::now() + 3600;
    let waits = metadata(running, later, consumer("org-1", URL, &public));
    let pending = timer("ses_later", &waits).expect("a webhook, so a notice");
    write(&store, "ses_later", &waits, &pending).await;
    let fake = FakeHatch::answering(&[true]);
    let webhooks = webhooks(&store, &fake).await;

    webhooks.step().await;
    assert_eq!(due(&disk), [later], "kept for its time");
    all_due(&disk);
    webhooks.step().await;
    assert!(fake.sent().is_empty());
    assert_eq!(due(&disk), [later], "taken early, it waits for its time");

    let expired = metadata(running, clock::now(), consumer("org-1", URL, &public));
    let due_now = timer("ses_now", &expired).expect("a webhook, so a notice");
    write(&store, "ses_now", &expired, &due_now).await;
    webhooks.step().await;
    let sent = fake.sent();
    assert_eq!(sent.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&sent[0].body).unwrap();
    assert_eq!(body["type"], "session.ended");
    let sealed = Base64::decode_vec(body["data"]["sealed_session_id"].as_str().unwrap()).unwrap();
    assert_eq!(
        enclavid_crypto::open_sealed(&sealed, &secret).unwrap(),
        b"ses_now"
    );
    assert_eq!(due(&disk), [later], "only the other session's is left");
}

/// A write that ends a session before its `expires_at` puts its notice in the
/// place of the one the session was created with: one webhook, sent at the end,
/// and none when the session's time would have run out.
#[tokio::test]
async fn a_session_that_ends_first_sends_one_webhook() {
    let (disk, store) = store().await;
    let (_secret, public) = enclavid_crypto::generate_recipient();
    let later = clock::now() + 3600;
    let created = metadata(
        SessionStatus::Running,
        later,
        consumer("org-1", URL, &public),
    );
    let at_expiry = timer("ses_a", &created).expect("a webhook, so a notice");
    write(&store, "ses_a", &created, &at_expiry).await;

    let ended = SessionMetadata {
        status: SessionStatus::Completed,
        ..created
    };
    let end = notice("ses_a", &ended).expect("a webhook, so a notice");
    let set = SetMetadata(
        Storage::expose_builder::<MetadataOp, _>(&ended)
            .vouch(reason!(Covert::NotChosen, "test fixture")),
    );
    let ops = store
        .seal("ses_a", &[&set, &end])
        .unwrap()
        .vouch(reason!(Covert::Bounded, "test fixture"));
    store.write(Some(1), ops).await.unwrap();
    assert_eq!(due(&disk).len(), 1, "one notice a session");

    let fake = FakeHatch::answering(&[true]);
    let webhooks = webhooks(&store, &fake).await;
    webhooks.step().await;
    assert_eq!(fake.sent().len(), 1);
    assert!(due(&disk).is_empty());
}

/// A consumer whose endpoint stalls has its own few attempts under way and no
/// more: its other notices wait their turn, and another consumer's webhook,
/// written while those stall, goes out at once — woken by its write, not by the
/// next look at the store.
#[tokio::test]
async fn a_stalled_endpoint_holds_up_only_its_own_consumer() {
    let (_disk, store) = store().await;
    let (_secret, public) = enclavid_crypto::generate_recipient();
    let ended = SessionStatus::Completed;
    let sending = Settings::default().sending_per_consumer;
    for n in 0..sending + 2 {
        let stalled = consumer("org-stalls", STALLS, &public);
        session(&store, &format!("ses_s{n}"), ended, stalled).await;
    }
    let fake = FakeHatch::answering(&[true]);
    tokio::spawn(
        Arc::into_inner(webhooks(&store, &fake).await)
            .unwrap()
            .run(),
    );
    until(|| fake.sent_to(STALLS) == sending).await;

    session(&store, "ses_other", ended, consumer("org-2", URL, &public)).await;
    until(|| fake.sent_to(URL) == 1).await;
    assert_eq!(fake.sent_to(STALLS), sending);
}
