//! How this role learns which members can take work, and how one comes back.
//!
//! ## It asks on the channel it will use
//!
//! api has a port that reports what it knows about itself, and this role does
//! not use it. That port exists for the party that runs the fleet — it says
//! whether a guest finished coming up and whether its own legs are connected,
//! which is what an operator acts on. It answers through the host, unsigned, so
//! anything concluded from it is concluded on the host's word.
//!
//! What this role needs is narrower and it can get it first-hand: would a leg to
//! this member open. That is a question about LIVENESS and nothing else — what
//! runs there is settled on every real leg by the handshake and checked again
//! when one is taken from the pool, so a member running the wrong build is
//! already indistinguishable from a member that is down: neither can complete a
//! handshake, and neither can read or write a byte.
//!
//! The probe dials the attested way regardless — see `crate::upstream::connect`
//! — not as a check of its own but because that IS how a leg opens here. A
//! cheaper probe would answer a different question: a plain connection succeeds
//! while the host is carrying bytes, which says nothing about whether the leg
//! this member would actually be given could be established, and a member
//! returned on that answer would fail its next request and be marked again.
//! Nothing is sent on the connection; it is opened and dropped.
//!
//! ## A failure marks, a dial unmarks
//!
//! A member is marked unwell by the request that met it failing, which costs
//! one request rather than a poll. It is not asked about again until
//! [`COOL_OFF`] has passed, and then a probe dial — not a caller's request —
//! decides whether it comes back. That is the pairing every mature proxy ends
//! up with: learn from real traffic, recover by asking.
//!
//! Members that are well are not polled at all. A fleet of well members costs
//! nothing here, and the first sign of trouble arrives on the path that would
//! have suffered from it anyway.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use safe_logger::debug;
use tokio::sync::watch;

use crate::upstream::Upstreams;

/// How long a marked member is left alone before a probe tries it.
#[cfg(not(test))]
const COOL_OFF: Duration = Duration::from_secs(10);
#[cfg(test)]
const COOL_OFF: Duration = Duration::from_millis(20);

/// How often the marked ones are looked at.
#[cfg(not(test))]
const INTERVAL: Duration = Duration::from_secs(5);
#[cfg(test)]
const INTERVAL: Duration = Duration::from_millis(10);

/// How long one probe dial may take.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Bring marked members back, for ever.
///
/// Await this on the role's own task rather than spawning it: a role that
/// stopped probing would leave every member it ever marked marked, and slide
/// into refusing new sessions with no way back. That is a state to end the
/// process over rather than serve through.
pub async fn probe_forever(table: watch::Receiver<Arc<Upstreams>>) -> ! {
    // When each marked member was last tried, so one that has just been marked
    // is left alone for a while and one that keeps failing is not hammered.
    let mut tried: HashMap<String, Instant> = HashMap::new();
    loop {
        let now = Instant::now();
        let current = table.borrow().clone();
        for member in current.members() {
            if member.ready.get() {
                tried.remove(&member.addr);
                continue;
            }
            if tried
                .get(&member.addr)
                .is_some_and(|last| now.duration_since(*last) < COOL_OFF)
            {
                continue;
            }
            tried.insert(member.addr.clone(), now);

            if dial(&current, &member).await {
                debug!("member at {} answered and is taken back", member.addr);
                member.ready.set(true);
                tried.remove(&member.addr);
            }
        }
        // Addresses no longer declared stop being remembered, so a member that
        // comes back under a later push starts clean.
        tried.retain(|addr, _| current.members().iter().any(|m| &m.addr == addr));

        tokio::time::sleep(INTERVAL).await;
    }
}

/// One attested handshake and nothing else. Success means the member answers,
/// is still the build it was declared to be, and is on its group's part — the
/// same checks a request's own leg makes, which is why this answer means what a
/// request needs it to.
async fn dial(table: &Upstreams, member: &crate::upstream::Member) -> bool {
    let addr = &member.addr;
    match tokio::time::timeout(
        TIMEOUT,
        crate::upstream::connect(addr, &member.measurement, &member.part, table.tls()),
    )
    .await
    {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            debug!("probing {addr}: {e}");
            false
        }
        Err(_) => {
            debug!("probing {addr} did not finish within the timeout");
            false
        }
    }
}

#[cfg(all(test, not(feature = "vsock")))]
mod tests {
    use super::*;

    use crate::upstream::tests::{A, FIRST, SECOND, pushed};

    /// A listener that accepts and says nothing: enough for a dial to succeed,
    /// which is all a probe asks.
    async fn answering() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                // Held so the connection is not closed under the prober.
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    drop(stream);
                });
            }
        });
        addr
    }

    fn table(addr: &str) -> Arc<Upstreams> {
        let body = format!(
            r#"{{
              "groups": {{ "one": {{ "measurement": "{A}" }} }},
              "names": {{
                "{FIRST}": {{ "one": ["{addr}"] }},
                "{SECOND}":  {{ "one": ["{addr}"] }} }},
              "affinity": {{ "key": "{}", "ttl_seconds": 600 }} }}"#,
            "0".repeat(64)
        );
        Arc::new(Upstreams::empty().replaced(&pushed(&body)))
    }

    /// A member that was marked and answers again is taken back.
    #[tokio::test]
    async fn a_member_that_answers_comes_back() {
        let addr = answering().await;
        let current = table(&addr);
        current.mark(&addr, false);

        let (_tx, rx) = watch::channel(current.clone());
        tokio::spawn(probe_forever(rx));

        let back = tokio::time::timeout(Duration::from_secs(5), async {
            while !current.members()[0].ready.get() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(back.is_ok(), "a member that answers is taken back");
    }

    /// One that does not answer stays out, however long it is probed.
    #[tokio::test]
    async fn a_member_that_does_not_answer_stays_out() {
        let current = table("127.0.0.1:1");
        current.mark("127.0.0.1:1", false);

        let (_tx, rx) = watch::channel(current.clone());
        tokio::spawn(probe_forever(rx));

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!current.members()[0].ready.get());
    }

    /// A well member is never dialled: a probe that touched everything would
    /// cost an attested handshake per member per interval, for nothing.
    #[tokio::test]
    async fn the_well_are_left_alone() {
        // Nothing listens at this address, so a dial would fail and mark it —
        // if anything dialled it, which is the point.
        let current = table("127.0.0.1:1");
        let (_tx, rx) = watch::channel(current.clone());
        tokio::spawn(probe_forever(rx));

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(current.members()[0].ready.get(), "still ready, never asked");
    }
}
