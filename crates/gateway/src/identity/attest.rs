//! What this role proves about itself, and where it says it.
//!
//! ## Why an endpoint exists at all
//!
//! A caller is asked to trust this role with one decision: which api build it
//! ends up talking to. It names a measurement, and this role proves that
//! measurement at the handshake with api — see `crate::upstream`. That whole
//! delegation rests on the caller first establishing WHAT it is talking to here,
//! and the public certificate cannot carry that: it is an ordinary certificate,
//! authenticated by a name, with no room for a quote a browser would refuse to
//! parse anyway.
//!
//! So the quote is served, and bound to the certificate. Its `report_data` is
//! the same binding RA-TLS uses between peers — a hash over the
//! `SubjectPublicKeyInfo` of the key in front of the caller — so a caller that
//! compares it against the certificate it actually validated has tied the
//! attestation to ITS OWN channel. Without that comparison the quote proves only
//! that some genuine guest exists somewhere, which any intermediary could relay
//! while holding a different key.
//!
//! What the caller then learns is the measurement: the digest of this image,
//! which it can recompute from the source it audited. It learns the machine
//! too: the report names the chip it was signed on, and a caller needs that to
//! fetch the certificate that endorses it. Nor is anything else about this
//! guest's reach kept back — the public certificate lists every name it
//! serves to whoever completes a handshake. Neither is a secret from the host,
//! which chose the chip and pushed the names.
//!
//! ## Minted once, at boot
//!
//! The quote binds the key, and the key is settled once per process, so the
//! quote is minted once too — and outlives every certificate minted over that
//! key as the pushed names change. A quote per request would let a caller
//! decide how often this guest asks the Secure Processor to sign something, and
//! would prove nothing more: what is bound is a key, not a moment.
//!
//! ## CBOR, and the same shape RA-TLS embeds
//!
//! The body is the evidence `enclavid_ra_tls::evidence` makes — what an RA-TLS
//! certificate carries in its extension, made by the same call, so the two
//! cannot drift and one decoder reads both.
//!
//! What it does not carry is AMD's chain. This guest has no egress to fetch the
//! certificate that endorses its own report, so the quote goes out bare — see
//! `crate::identity`. A caller checking it fetches that certificate itself, for
//! the chip and the firmware versions the report names, and checks it up to
//! AMD's root; nothing it needs comes from this role.
//!
//! That is also why it is not JSON. One type with two representations would mean
//! a verifier that has to read both, and a certificate extension is a DER octet
//! string, where bytes are what belongs. A readable body would invite reading
//! the envelope's `measurement` and `chip_id`, which are the sender's
//! unauthenticated claim — the values that count are inside the signed blob.
//!
//! The media type NAMES the schema rather than only the encoding, because a
//! path is stable and a schema might not be: the `+cbor` suffix keeps ordinary
//! CBOR tooling working, and the type ahead of it is what a verifier that knows
//! only this shape can refuse on rather than misparse.

use std::sync::Arc;

use bytes::Bytes;
use enclavid_attestation::Attestor;

/// The one path this role answers for itself.
///
/// Under `/.well-known/` because that is the reserved space for exactly this —
/// something about the server rather than about what it serves — and because it
/// cannot collide with a path the host later configures as api's.
pub const PATH: &str = "/.well-known/enclavid-attestation";

/// The `Content-Type` the body carries.
///
/// Part of the wire, not a detail of this build: a verifier written against this
/// shape reads it. See the module docs for why it names the schema.
pub const CONTENT_TYPE: &str = "application/vnd.enclavid.attestation+cbor";

/// This role's evidence about itself, ready to serve.
///
/// Held as `Bytes` because every request hands back the same body: cloning one
/// is a refcount, where re-encoding per request would be work a caller chooses
/// the rate of.
pub type Evidence = Bytes;

/// Mint the evidence that binds `spki`, as it will be served.
pub fn evidence(spki: Vec<u8>, attestor: &Arc<dyn Attestor>) -> Result<Evidence, String> {
    enclavid_ra_tls::evidence(spki, &**attestor)
        .map(Bytes::from)
        .map_err(|e| format!("mint the evidence for the serving key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both are the wire, so a change to either is a change a verifier outside
    /// this build has to be told about. Written out rather than compared to
    /// themselves, which is what a test against the constants would do.
    #[test]
    fn the_path_and_the_media_type_are_what_a_verifier_was_written_against() {
        assert_eq!(PATH, "/.well-known/enclavid-attestation");
        assert_eq!(CONTENT_TYPE, "application/vnd.enclavid.attestation+cbor");
    }
}
