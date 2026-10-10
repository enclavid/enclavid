//! How many registry requests one consumer's sessions may have under way at
//! once — manifests and blob streams alike, through the hatch every guest on
//! this host shares.
//!
//! The hatch fetches a bounded number at once for the whole host and cannot
//! tell whose request is whose; the consumer is known only here, from the session's sealed
//! metadata. Without this, one consumer pinning artifacts on a registry that
//! answers slowly, and connecting its own sessions over and over, holds every
//! turn, and every other consumer's sessions wait behind it until their pulls
//! time out. With it, that consumer holds at most its own share, and the rest
//! of its requests wait in its own queue.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Registry requests one consumer may have under way at once, unless the host
/// says otherwise (`registry-requests-per-consumer`). A session's first round
/// asks for every pinned manifest at once, and four lets a handful of them go
/// in one or two waves. The hatch fetches many times this many manifests at
/// once, so it takes that many consumers to hold them all; it streams fewer
/// blobs, which only a cold compile asks for.
pub const DEFAULT_REGISTRY_REQUESTS_PER_CONSUMER: usize = 4;

/// Every consumer's queue, made when its first request comes and gone when its
/// last one ends.
pub struct ConsumerTurns {
    each: usize,
    wait: Duration,
    queues: Mutex<HashMap<String, Weak<Semaphore>>>,
}

impl ConsumerTurns {
    /// `each` turns per consumer; a request that has none within `wait` is
    /// given up on.
    pub fn new(each: usize, wait: Duration) -> Self {
        Self {
            each,
            wait,
            queues: Mutex::new(HashMap::new()),
        }
    }

    /// The queue `consumer`'s requests take their turns from.
    pub fn of(&self, consumer: &str) -> Turns {
        let mut queues = self.queues.lock().unwrap_or_else(PoisonError::into_inner);
        let semaphore = match queues.get(consumer).and_then(Weak::upgrade) {
            Some(semaphore) => semaphore,
            None => {
                // No request of anyone's holds or awaits a queue whose `Weak`
                // is dead, so dropping those loses nothing.
                queues.retain(|_, queue| queue.strong_count() > 0);
                let semaphore = Arc::new(Semaphore::new(self.each));
                queues.insert(consumer.to_owned(), Arc::downgrade(&semaphore));
                semaphore
            }
        };
        Turns {
            semaphore,
            wait: self.wait,
        }
    }
}

/// One consumer's queue.
#[derive(Clone)]
pub struct Turns {
    semaphore: Arc<Semaphore>,
    wait: Duration,
}

impl Turns {
    /// A turn, held until it is dropped; `None` when none came in time.
    pub async fn take(&self) -> Option<OwnedSemaphorePermit> {
        tokio::time::timeout(self.wait, self.semaphore.clone().acquire_owned())
            .await
            .ok()?
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A consumer holding all its turns waits for its own, and another
    /// consumer is not held up by it.
    #[tokio::test]
    async fn one_consumer_holds_only_its_own_turns() {
        let turns = ConsumerTurns::new(2, Duration::from_millis(50));
        let busy = turns.of("busy");
        let _a = busy.take().await.expect("a first turn");
        let _b = busy.take().await.expect("a second turn");
        assert!(busy.take().await.is_none(), "a third waits past its time");
        assert!(turns.of("other").take().await.is_some());
    }

    /// A turn given back is taken by the next request of the same consumer.
    #[tokio::test]
    async fn a_turn_given_back_is_taken_again() {
        let turns = ConsumerTurns::new(1, Duration::from_millis(50));
        let queue = turns.of("c");
        drop(queue.take().await.expect("a turn"));
        assert!(queue.take().await.is_some());
    }

    /// A consumer with nothing under way leaves nothing behind.
    #[tokio::test]
    async fn an_idle_consumer_leaves_no_queue() {
        let turns = ConsumerTurns::new(1, Duration::from_millis(50));
        drop(turns.of("gone").take().await);
        let _other = turns.of("other");
        let queues = turns.queues.lock().unwrap();
        assert!(!queues.contains_key("gone"));
    }
}
