//! Type-level markers for values crossing the TEE ↔ host trust
//! boundary. Two dual wrappers, one per direction:
//!
//! `Untrusted<T>` — INBOUND: value came from a source the TEE doesn't
//! trust (host gRPC response, registry pull, etc.). Cannot be
//! inspected until caller passes a verification predicate to
//! `trust(...)` or explicitly delegates via `trust_unchecked()`.
//! Reviewers grep for `.trust(` to find every gate.
//!
//! `Exposed<T>` — OUTBOUND: value being released to the host. The
//! wrapping IS the marker — caller acknowledges via
//! `Exposed::expose(...)` that this batch of bytes leaves the trust
//! boundary. Transport unwraps via `release()` only at the point of
//! handing to the wire. Reviewers grep for `Exposed::expose` to find
//! every release point. Sealing (AEAD, age) happens in the WriteField
//! impls / persister BEFORE the wrap; `Exposed<T>` is documentary,
//! not load-bearing for confidentiality.
//!
//! Pair this with sources that DO authenticate themselves (e.g., a
//! decrypted blob whose decryption is the verification step) — those
//! don't need wrapping. The markers are for content the TEE genuinely
//! cannot independently authenticate (incoming) / for the architectural
//! visibility of releases (outgoing).

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

/// Marker for values being released across the TEE → host boundary.
/// Constructed via `Exposed::expose(...)` at call sites that hand
/// data to the host; unwrapped via `release()` only inside the
/// transport layer at the point of placing on the wire. The wrap is
/// the audit trail — every release of TEE-side data is a `expose(`
/// grep away.
#[derive(Debug)]
pub struct Exposed<T>(T);

impl<T> Exposed<T> {
    /// Wrap a value being released to the host. Sealing (encryption,
    /// integrity protection) must already have happened upstream —
    /// `Exposed<T>` is documentary, not cryptographic. The act of
    /// calling `expose` is the explicit acknowledgment that this
    /// value is leaving the trust boundary.
    pub fn expose(value: T) -> Self {
        Self(value)
    }

    /// Unwrap at the point of handing to the wire. Used inside the
    /// transport layer right before the gRPC send. Outside that layer,
    /// callers should not need to release — the value's purpose is to
    /// be sent.
    pub fn release(self) -> T {
        self.0
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

    #[test]
    fn exposed_round_trips() {
        let e = Exposed::expose(vec![1u8, 2, 3]);
        assert_eq!(e.release(), vec![1, 2, 3]);
    }
}
