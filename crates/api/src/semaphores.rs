//! A semaphore per key: made when first asked for, gone once nothing holds or
//! awaits it. Each consumer's registry turns are one ([`crate::turns`]), the one
//! compile at a time of a composition another ([`crate::compositions`]).

use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use tokio::sync::Semaphore;

/// The semaphores, by key, of `permits` each.
///
/// The map holds them weakly: a semaphore lives as long as someone holds a
/// permit of it or waits for one, so what the map keeps is what is in use and
/// no more.
pub struct Semaphores<K> {
    permits: usize,
    each: Mutex<HashMap<K, Weak<Semaphore>>>,
}

impl<K: Hash + Eq> Semaphores<K> {
    pub fn new(permits: usize) -> Self {
        Self {
            permits,
            each: Mutex::new(HashMap::new()),
        }
    }

    /// The semaphore of `key`: the one in use, or a new one.
    pub fn of<Q>(&self, key: &Q) -> Arc<Semaphore>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ToOwned<Owned = K> + ?Sized,
    {
        let mut each = self.each.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(semaphore) = each.get(key).and_then(Weak::upgrade) {
            return semaphore;
        }
        // Nothing holds or awaits a semaphore whose `Weak` is dead, so dropping
        // those loses nothing.
        each.retain(|_, semaphore| semaphore.strong_count() > 0);
        let semaphore = Arc::new(Semaphore::new(self.permits));
        each.insert(key.to_owned(), Arc::downgrade(&semaphore));
        semaphore
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    /// One semaphore per key: asked for again while in use, the same one;
    /// another key's is another.
    #[test]
    fn one_semaphore_per_key() {
        let semaphores = Semaphores::<String>::new(1);
        let a = semaphores.of("a");
        assert!(Arc::ptr_eq(&a, &semaphores.of("a")));
        assert!(!Arc::ptr_eq(&a, &semaphores.of("b")));
        assert_eq!(a.available_permits(), 1);
    }

    /// A key nothing holds or awaits leaves nothing behind.
    #[test]
    fn an_idle_key_leaves_nothing() {
        let semaphores = Semaphores::<String>::new(1);
        drop(semaphores.of("gone"));
        let _held = semaphores.of("other");
        let each = semaphores.each.lock().unwrap();
        assert!(!each.contains_key("gone"));
        assert_eq!(each.len(), 1);
    }

    /// A permit held by work abandoned part-way — its task gone — is given
    /// back, so nobody waits on work nobody is doing.
    #[tokio::test]
    async fn an_abandoned_holder_gives_its_permit_back() {
        let semaphores = Semaphores::<String>::new(1);
        let held = semaphores
            .of("k")
            .try_acquire_owned()
            .expect("nobody held it");
        let abandoned = tokio::spawn(async move {
            let _held = held;
            std::future::pending::<()>().await;
        });
        abandoned.abort();
        let semaphore = semaphores.of("k");
        assert!(
            tokio::time::timeout(Duration::from_secs(5), semaphore.acquire())
                .await
                .is_ok(),
            "the permit comes back with the abandoned work"
        );
    }
}
