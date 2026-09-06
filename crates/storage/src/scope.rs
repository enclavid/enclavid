//! Whose records a call may reach.
//!
//! This node accepts any attested guest. It cannot pin api's measurement without
//! a cycle — api's digest is a function of the three it pins, so the leaves are
//! built first — which means "the caller is the orchestrator" is something the
//! acceptor hopes rather than checks. Anything that rested on that premise
//! rested on nothing.
//!
//! So the premise stops being assumed and becomes structural: every record name
//! is derived from the CALLER's launch digest together with the name it asked
//! for, and a caller cannot choose that digest. It comes from a report the AMD
//! Secure Processor signed, bound to the very TLS key the caller proved it holds
//! — replaying api's report would need api's ephemeral private key, which never
//! leaves api's encrypted memory and does not outlive one connection. A foreign
//! caller lands under its own digest, always.
//!
//! **What it costs is nothing, which is why it is the answer here.** Every
//! payload arrives sealed under a `tee_seal_key` the chip derives from (chip,
//! measurement), so a guest of a different image could never have opened these
//! bytes to begin with: the partition is drawn exactly where the key domain
//! already ended. Nothing becomes unreachable that was reachable before — an api
//! rebuild already orphaned its own sealed records, digest or no digest.
//!
//! Note what this is NOT: it decides nothing about who may call, and no list
//! anywhere names api. It only stops callers reaching each other — the same move
//! the child sandbox makes, where untrusted code is contained rather than
//! identified.

use sha2::{Digest, Sha256};

/// Session records. Domain-separated from [`BLOB`] so one caller's two stores
/// cannot be made to collide by a chosen key, independently of the fact that
/// they are different backends today.
const SESSION: &str = "session";
/// L2 cache blobs.
const BLOB: &str = "cache";

/// One caller's namespace: everything it stores, and everything it can address.
/// Built once per connection, from the digest that connection proved.
#[derive(Clone)]
pub(crate) struct Scope {
    /// The peer's launch measurement, as verified hex.
    measurement: String,
}

/// A record name inside one [`Scope`] — 64 lowercase hex characters.
///
/// What the type guarantees is that a name cannot be FORGED: the field is
/// private to this module, so the only way to hold one is to have derived it,
/// and every `Name` in existence therefore belongs to some caller's partition.
/// It does not guarantee that call sites use one — the tiers below take `&str`,
/// because they are a KV over opaque strings and coupling them to this would
/// buy nothing. That every served call derives first is enforced one level up,
/// by [`crate::Caller`] being the only implementor of the RPC traits.
pub(crate) struct Name(String);

impl Name {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl Scope {
    pub(crate) fn new(measurement: String) -> Scope {
        Scope { measurement }
    }

    /// The name a session's record is stored under, for the wire `session_id`.
    pub(crate) fn session(&self, id: &str) -> Name {
        self.derive(SESSION, id)
    }

    /// The name an L2 cache blob is stored under, for the wire cache key.
    pub(crate) fn blob(&self, key: &str) -> Name {
        self.derive(BLOB, key)
    }

    /// Length-prefixed rather than concatenated. Digests are fixed-width today,
    /// so two callers whose bytes differ only in where the boundary falls cannot
    /// occur — but that is a property of the current attestation backend, not of
    /// this function, and the prefix is what keeps it from being one.
    fn derive(&self, domain: &str, key: &str) -> Name {
        let mut h = Sha256::new();
        h.update((domain.len() as u64).to_le_bytes());
        h.update(domain.as_bytes());
        h.update((self.measurement.len() as u64).to_le_bytes());
        h.update(self.measurement.as_bytes());
        // Last, so it needs no length of its own.
        h.update(key.as_bytes());
        Name(hex::encode(h.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_key_under_different_callers_is_a_different_name() {
        let a = Scope::new("aa".repeat(48));
        let b = Scope::new("bb".repeat(48));
        assert_ne!(a.session("s").as_str(), b.session("s").as_str());
        assert_ne!(a.blob("k").as_str(), b.blob("k").as_str());
    }

    #[test]
    fn a_caller_reaches_its_own_records_across_connections() {
        // Two Scopes, one digest: a reconnecting api must find what it wrote.
        let first = Scope::new("aa".repeat(48));
        let again = Scope::new("aa".repeat(48));
        assert_eq!(first.session("s").as_str(), again.session("s").as_str());
    }

    #[test]
    fn the_two_stores_do_not_share_a_name() {
        let s = Scope::new("aa".repeat(48));
        assert_ne!(s.session("x").as_str(), s.blob("x").as_str());
    }

    #[test]
    fn a_name_is_always_a_safe_filename() {
        // The tiers below turn a name into a path; nothing a caller sends can
        // make one that is not 64 lowercase hex characters.
        let s = Scope::new("aa".repeat(48));
        for key in ["", "../../etc/passwd", "a/b", &"x".repeat(10_000)] {
            let n = s.session(key);
            assert_eq!(n.as_str().len(), 64);
            assert!(
                n.as_str()
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
        }
    }

    #[test]
    fn the_boundary_between_digest_and_key_cannot_be_moved() {
        // Without the length prefix these two would hash the same bytes.
        let a = Scope::new("aabb".to_string());
        let b = Scope::new("aa".to_string());
        assert_ne!(a.session("cc").as_str(), b.session("bbcc").as_str());
    }
}
