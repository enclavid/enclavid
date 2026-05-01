//! `Untrusted<T>`: type-level marker for values that came from a source
//! the TEE does not trust on content (host gRPC responses, registry
//! pulls, etc.). The inner `T` is inaccessible until the caller passes a
//! verification predicate to `trust(...)` / `trust_if(...)` — no field
//! accessors, no `Deref`, no `into_inner`. Compiler enforces that any
//! use of host-mediated data is gated by an explicit trust step;
//! reviewers / auditors can grep for `.trust(` to find every gate.
//!
//! Pair this with sources that DO authenticate themselves (e.g., a
//! decrypted blob whose decryption is the verification step) — those
//! don't need wrapping. The marker is for content the TEE genuinely
//! cannot independently authenticate.

/// Wrapper for a value originating from an untrusted source. The inner
/// `T` cannot be inspected without an explicit trust gate.
#[derive(Debug)]
pub struct Untrusted<T>(T);

impl<T> Untrusted<T> {
    /// Construct an `Untrusted<T>` from a raw value. Call sites that
    /// produce data from untrusted sources (host-mediated stores) use
    /// this — the wrapping IS the marker that says "needs verification
    /// before use".
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Establish trust by running a verification predicate. The closure
    /// inspects the value and returns `Ok(())` to accept or `Err(E)` to
    /// reject. On accept, returns the inner `T`; on reject, propagates
    /// the error. The closure body is the single point reviewers
    /// scrutinise to understand WHAT is being trusted.
    pub fn trust<E, F>(self, check: F) -> Result<T, E>
    where
        F: FnOnce(&T) -> Result<(), E>,
    {
        check(&self.0)?;
        Ok(self.0)
    }

    /// Unwrap WITHOUT verification. Use only when the security model
    /// explicitly delegates trust elsewhere (e.g. host-mediated identity
    /// where the K_client backstop bounds damage; an applicant flow that
    /// gates on a separate cryptographic claim check). Each call site
    /// must justify the delegation in a comment — reviewers grep for
    /// `trust_unchecked` to find every blanket-accept.
    pub fn trust_unchecked(self) -> T {
        self.0
    }

    /// Map the inner value while preserving the untrusted marker. Use
    /// when you need to project / transform a field but still cannot
    /// vouch for the result. Most call sites should reach for
    /// `trust(...)` instead — `map` is here for the rare case where
    /// the projection is itself opaque (e.g., re-wrapping bytes).
    pub fn map<U, F>(self, f: F) -> Untrusted<U>
    where
        F: FnOnce(T) -> U,
    {
        Untrusted(f(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    struct Meta {
        owner: String,
        version: u32,
    }

    #[test]
    fn trust_accepts_when_predicate_returns_ok() {
        let u = Untrusted::new(Meta {
            owner: "alice".into(),
            version: 2,
        });
        let m = u
            .trust::<&'static str, _>(|m| {
                if m.owner == "alice" {
                    Ok(())
                } else {
                    Err("wrong owner")
                }
            })
            .unwrap();
        assert_eq!(
            m,
            Meta {
                owner: "alice".into(),
                version: 2
            }
        );
    }

    #[test]
    fn trust_propagates_predicate_error() {
        let u = Untrusted::new(Meta {
            owner: "mallory".into(),
            version: 2,
        });
        let err = u
            .trust(|m| {
                if m.owner == "alice" {
                    Ok(())
                } else {
                    Err("not alice")
                }
            })
            .unwrap_err();
        assert_eq!(err, "not alice");
    }

    #[test]
    fn trust_unchecked_just_unwraps() {
        let u = Untrusted::new(7u32);
        assert_eq!(u.trust_unchecked(), 7);
    }

    #[test]
    fn map_preserves_marker() {
        let u: Untrusted<Meta> = Untrusted::new(Meta {
            owner: "alice".into(),
            version: 2,
        });
        let mapped: Untrusted<u32> = u.map(|m| m.version);
        // Still wrapped — must call trust(_unchecked) to escape.
        let v = mapped.trust_unchecked();
        assert_eq!(v, 2);
    }
}
