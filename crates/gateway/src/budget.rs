//! Every descriptor a caller can make this process spend, counted against what
//! it has.
//!
//! A push is refused if its own numbers could need more descriptors than the
//! process got at boot — see `crate::config::push`. That bounds each tuning
//! alone, not a change from one to the next. A connection keeps the numbers it
//! was accepted under until it closes, so after a push the old connections and
//! the new ones are open side by side, each by its own tuning, and together
//! they can need more than either did.
//!
//! So every public connection and every leg to api also takes one permit from
//! here, for as long as it holds its descriptor. Within one tuning the push
//! check keeps this from running out; across a change, this is what holds.
//! What it refuses when it does is new work — a connection, a leg — and never
//! the configuration and health ports, whose descriptors are counted apart.

use tokio::sync::{Semaphore, SemaphorePermit};

use crate::config::{MOST_DESCRIPTORS, OWN_DESCRIPTORS};

/// A permit for every descriptor a caller can make this process spend: as many
/// as the largest tuning could need, until [`limit`] says what the process has.
static DESCRIPTORS: Semaphore = Semaphore::const_new(MOST_DESCRIPTORS as usize);

/// Hold the permits to what the process got, less what it keeps for itself.
/// Once, at boot, before anything takes one.
pub fn limit(available: u64) {
    limit_to(&DESCRIPTORS, available);
}

/// One descriptor's permit, or none if the process has none to spare.
pub fn take() -> Option<SemaphorePermit<'static>> {
    DESCRIPTORS.try_acquire().ok()
}

fn limit_to(descriptors: &Semaphore, available: u64) {
    let spendable = available
        .saturating_sub(OWN_DESCRIPTORS)
        .min(MOST_DESCRIPTORS);
    descriptors.forget_permits((MOST_DESCRIPTORS - spendable) as usize);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the process got, less its own, is what callers may spend — and a
    /// descriptor given back can be spent again.
    #[test]
    fn callers_spend_what_the_process_got_less_its_own() {
        static COUNTED: Semaphore = Semaphore::const_new(MOST_DESCRIPTORS as usize);
        limit_to(&COUNTED, OWN_DESCRIPTORS + 2);

        let first = COUNTED.try_acquire().unwrap();
        let _second = COUNTED.try_acquire().unwrap();
        assert!(
            COUNTED.try_acquire().is_err(),
            "none past what the process got"
        );

        drop(first);
        assert!(COUNTED.try_acquire().is_ok(), "a descriptor given back");
    }

    /// A process that got fewer than its own needs has none for callers,
    /// rather than wrapping round to all of them.
    #[test]
    fn fewer_than_its_own_leaves_nothing_for_callers() {
        static COUNTED: Semaphore = Semaphore::const_new(MOST_DESCRIPTORS as usize);
        limit_to(&COUNTED, OWN_DESCRIPTORS / 2);
        assert!(COUNTED.try_acquire().is_err());
    }
}
