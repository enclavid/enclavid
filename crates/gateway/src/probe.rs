//! What this role asks each api about itself, and what it does with the answer.
//!
//! ## Why the gateway asks, and not the host
//!
//! Whether a machine may be given a NEW session is a conclusion, and the party
//! that draws it should be the one acting on it. api reports facts about
//! itself — it is up and listening, each of its legs is connected, the hatch
//! answers — and says nothing about whether traffic should arrive; see
//! `fleet_transport::health`. This role is what places sessions, so this role
//! concludes. The host keeps its own conclusions for its own actions.
//!
//! ## The port it asks is not attested, and that is fine
//!
//! The answer arrives through the host like everything else, and nothing signs
//! it. A forged "healthy" sends new sessions to a machine that cannot run them,
//! which the host can cause anyway by not carrying bytes; a forged "unwell"
//! steers them elsewhere, which is the host's own balancing. What it cannot do
//! is substitute a build: identity is proved on every data connection, not here.
//!
//! ## Ready means every fact api reports is good
//!
//! Not just `healthy`. A node whose storage leg is down accepts connections and
//! completes the attested handshake, and still cannot run a session — which is
//! exactly the case a connection-level probe would call well.
//!
//! Two answers in a row change a verdict, so a single lost poll does not empty
//! a machine and a single lucky one does not refill it. A failed data
//! connection marks a node at once, without waiting for the next poll — see
//! `crate::serve`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use safe_logger::debug;
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio::sync::watch;

use crate::upstream::Upstreams;

/// How often each node is asked, and how long an answer may take.
#[cfg(not(test))]
const INTERVAL: Duration = Duration::from_secs(5);
#[cfg(test)]
const INTERVAL: Duration = Duration::from_millis(20);
const TIMEOUT: Duration = Duration::from_secs(3);

/// How many answers in a row move a verdict.
const IN_A_ROW: u32 = 2;

/// api's answer, as `enclavid_api::health` renders it.
///
/// Unknown fields are ignored rather than refused: this is a hint for placing
/// new sessions, and a newer api that reports more about itself should not
/// become unplaceable to an older gateway.
#[derive(Deserialize)]
struct Answer {
    healthy: bool,
    peers: HashMap<String, bool>,
    hatch: bool,
}

impl Answer {
    fn ready(&self) -> bool {
        self.healthy && self.hatch && self.peers.values().all(|up| *up)
    }
}

/// Ask every declared node, for ever, and keep the table's verdicts current.
///
/// Await this on the role's own task rather than spawning it: a gateway that
/// stopped asking would go on placing new sessions on whatever it last
/// believed, and that is a state to end the process over rather than serve
/// through.
pub async fn poll_forever(mut table: watch::Receiver<Arc<Upstreams>>) -> ! {
    // Streaks by address, so a node that goes away and comes back starts over
    // rather than inheriting a verdict from a previous table.
    let mut streaks: HashMap<String, (u32, bool)> = HashMap::new();
    loop {
        let nodes = table.borrow().to_poll();
        let mut seen = HashMap::new();
        for (addr, ready) in nodes {
            let answered = ask(&addr).await;
            let (count, last) = streaks.get(&addr).copied().unwrap_or((0, answered));
            let count = if answered == last { count + 1 } else { 1 };
            if answered != ready.get() && count >= IN_A_ROW {
                debug!(
                    "node at {addr} is now {}",
                    if answered { "ready" } else { "not ready" }
                );
                ready.set(answered);
            }
            seen.insert(addr, (count, answered));
        }
        streaks = seen;

        // Woken by a push as well as by the clock: a table that just gained a
        // machine should be asked about it now, not up to an interval later.
        tokio::select! {
            _ = tokio::time::sleep(INTERVAL) => {}
            _ = table.changed() => {}
        }
    }
}

/// One question, and no bytes sent: the port answers and closes, and a prober
/// that speaks first can have its own answer reset away — see
/// `fleet_transport::health`.
async fn ask(addr: &str) -> bool {
    let answer = tokio::time::timeout(TIMEOUT, async {
        let mut stream = fleet_transport::dial(addr).await?;
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await?;
        Ok::<_, std::io::Error>(body)
    })
    .await;

    match answer {
        Ok(Ok(body)) => match serde_json::from_slice::<Answer>(&body) {
            Ok(answer) => answer.ready(),
            Err(e) => {
                debug!("health answer from {addr} did not parse: {e}");
                false
            }
        },
        Ok(Err(e)) => {
            debug!("health at {addr}: {e}");
            false
        }
        Err(_) => {
            debug!("health at {addr} did not answer within the timeout");
            false
        }
    }
}

#[cfg(all(test, not(feature = "vsock")))]
mod tests {
    use super::*;

    use tokio::io::AsyncWriteExt;

    /// A stand-in for api's health port: answers whatever the flag says, then
    /// closes, reading nothing.
    async fn port(healthy: Arc<std::sync::atomic::AtomicBool>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let up = healthy.load(std::sync::atomic::Ordering::Relaxed);
                let body = format!(
                    r#"{{"healthy":{up},"peers":{{"storage":{up},"compile_worker":{up},"execution_worker":{up}}},"hatch":{up}}}"#
                );
                let _ = stream.write_all(body.as_bytes()).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn an_answer_decides_and_takes_two_to_change_its_mind() {
        let healthy = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let addr = port(healthy.clone()).await;
        assert!(
            ask(&addr).await,
            "a node that says everything is up is ready"
        );

        healthy.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(!ask(&addr).await, "a leg down is not ready");
    }

    #[tokio::test]
    async fn a_node_that_does_not_answer_is_not_ready() {
        // Nothing listening: the dial fails and the verdict is the honest one.
        assert!(!ask("127.0.0.1:1").await);
    }

    #[tokio::test]
    async fn the_table_learns_and_unlearns() {
        let healthy = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let addr = port(healthy.clone()).await;

        let table = Upstreams::empty("verify.example.com".into(), "api.example.com".into())
            .replaced(crate::upstream::tests::pushed(vec![
                crate::config::Upstream {
                    node: "one".into(),
                    measurement: "a".repeat(96),
                    applicant: "127.0.0.1:1".into(),
                    client: "127.0.0.1:2".into(),
                    health: addr.clone(),
                },
            ]));
        let table = Arc::new(table);
        let (_tx, rx) = watch::channel(table.clone());
        tokio::spawn(poll_forever(rx));

        // Declared ready, said unwell twice: taken out.
        let out = tokio::time::timeout(Duration::from_secs(5), async {
            while table
                .assign(crate::upstream::Surface::Consumer, &"a".repeat(96))
                .is_ok()
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(out.is_ok(), "an unwell node stops taking new sessions");

        healthy.store(true, std::sync::atomic::Ordering::Relaxed);
        let back = tokio::time::timeout(Duration::from_secs(5), async {
            while table
                .assign(crate::upstream::Surface::Consumer, &"a".repeat(96))
                .is_err()
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(back.is_ok(), "and takes them again once it says so");
    }
}
