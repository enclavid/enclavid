//! Attestation: produces and verifies hardware-signed quotes that bind
//! session metadata to a specific TEE measurement.
//!
//! The protocol-level shape is fixed:
//!
//! ```text
//! report_data = sha256(tag || field ...)    one tag per protocol; see ReportData::hash
//! quote       = Sign(measurement || report_data)
//! ```
//!
//! Per-instance binding (TLS cert hash → TEE measurement) is a separate
//! attestation produced at TEE boot and verified by the client during
//! TLS handshake — that step is what authenticates the recipient TEE
//! identity. Per-session quotes returned in `POST /sessions` only
//! bind session-specific data (session_id, policy_digest) to the
//! same measurement.
//!
//! The signing/verification backend is pluggable. Real production uses
//! AMD SEV-SNP (VCEK→ARK→AMD root chain). The `mock` feature swaps in a
//! software Ed25519 signer for dev / CI / pre-hardware milestones — same
//! shape over the wire, same call sites in callers, only the trust value
//! of a passing `verify()` differs.
//!
//! Callers MUST treat any quote whose `format` is not `sev-snp` as
//! development-only and refuse it in production builds. See `Quote::format`.

mod error;

pub use error::AttestationError;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Wire format for an attestation quote returned to clients.
///
/// Stable shape across backends — clients verify by computing their own
/// `report_data` from the session response and asking the matching backend
/// (mock vs sev-snp) to validate `quote_blob` carries that value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
    /// Identifies the signing backend. Production clients refuse anything
    /// other than `"sev-snp"`. Currently `"mock-ed25519"` for dev.
    pub format: String,
    /// Backend-defined signed payload. For mock: JSON-encoded
    /// `MockSignedReport` plus a 64-byte Ed25519 signature, base64 wrapped
    /// at the outer envelope. For sev-snp: a CBOR envelope holding the
    /// firmware's report bytes plus the VCEK and ASK that endorse them.
    ///
    /// `serde_bytes` so CBOR carries it as one byte string. Left to serde, a
    /// `Vec<u8>` is a sequence, and ciborium writes it as an array of integers —
    /// up to twice the size, on every RA-TLS handshake. Reading is lenient and
    /// takes that array too, which is how a quote captured before this reads
    /// back; the envelope is not what is signed, so accepting either costs
    /// nothing.
    #[serde(with = "serde_bytes")]
    pub quote_blob: Vec<u8>,
    /// Hex-encoded TEE launch digest. Clients pin this in their config: only
    /// the platform releases they trust. Backends that verify a real report
    /// must confirm this matches the signed measurement inside `quote_blob` —
    /// otherwise it is the sender's unauthenticated claim.
    /// In mock mode, set from a CI-provided value or zeroed.
    pub measurement: String,
    /// Hex-encoded identifier of the PART that signed the report — which machine,
    /// where `measurement` says which image.
    ///
    /// Carried for the same reason and with the same caveat as `measurement`: a
    /// backend verifying a real report must confirm it matches the signed value
    /// inside `quote_blob`, or it is the sender's unauthenticated claim. It
    /// exists because a verifier holding no endorsement of its own reads the
    /// certificate chain out of the peer's quote, and a chain is only evidence
    /// that SOME genuine part signed — a peer on another machine passes every
    /// other check. A verifier that holds an endorsement never needed this: the
    /// signature is checked against ITS OWN VCEK, which is chip-specific, so a
    /// foreign part fails at the signature.
    pub chip_id: String,
}

/// What a quote attests to: one variant per protocol that asks for a quote.
/// Any change here is a wire-protocol change.
///
/// An enum, so that a quote binds the fields of exactly one protocol. What
/// keeps the protocols apart is [`ReportData::hash`], which gives every variant
/// its own preimage — a quote minted for one is never evidence in another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportData {
    /// An ordinary per-session quote, returned from `POST /sessions`.
    Session {
        session_id: String,
        policy_digest: String,
    },
    /// The TEE's ephemeral public key, bound for a key-release request. Nothing
    /// in this workspace mints one outside tests: the Trustee handshake binds a
    /// value of its own — see [`ReportData::for_kbs`].
    Kbs { ephemeral_pubkey: Vec<u8> },
    /// The DER `SubjectPublicKeyInfo` of an ephemeral RA-TLS certificate, so the
    /// quote authenticates "this measurement owns this TLS key" during the
    /// handshake.
    Ratls { spki_der: Vec<u8> },
}

/// Opens a session preimage. No tag is a prefix of another: this and
/// [`KBS_TAG`] part at their last word, and neither begins with the NUL that
/// [`RATLS_TAG`] does.
const SESSION_TAG: &[u8] = b"enclavid/report-data/session\x00";
/// Opens a KBS preimage.
const KBS_TAG: &[u8] = b"enclavid/report-data/kbs\x00";
/// Opens an RA-TLS preimage. The two leading NULs look arbitrary, and they stay
/// exactly as they are: a quote a real part signed binds these bytes
/// (`tests/from-a-real-part/`), and only hardware can mint another.
const RATLS_TAG: &[u8] = b"\x00\x00ratls-spki\x00";

impl ReportData {
    /// Report data for an ordinary per-session quote.
    pub fn session(session_id: String, policy_digest: String) -> Self {
        Self::Session {
            session_id,
            policy_digest,
        }
    }

    /// Report data binding an ephemeral public key for an artifact-key request.
    ///
    /// Not what the Trustee handshake binds. A Trustee KBS recomputes its
    /// `report_data` by its own rule — SHA-384 over the JSON it rebuilds from
    /// the attestation request, which `enclavid-kbs-client` produces — and that
    /// value is 48 bytes where this hash is 32, and never passes through
    /// [`ReportData::hash`]. So the bytes here are enclavid's to define, and are
    /// tagged and length-prefixed like the others.
    pub fn for_kbs(ephemeral_pubkey: Vec<u8>) -> Self {
        Self::Kbs { ephemeral_pubkey }
    }

    /// Report data for an RA-TLS cert: binds the DER `SubjectPublicKeyInfo` of
    /// the ephemeral TLS cert, so the peer's quote authenticates the TLS key it
    /// presents during the handshake. Nothing about a session — RA-TLS gates on
    /// measurement + the TLS key — so both ends recompute this from the cert
    /// alone.
    pub fn for_ratls(spki_der: Vec<u8>) -> Self {
        Self::Ratls { spki_der }
    }

    /// Canonical 32-byte hash that lands in the SEV-SNP `report_data` slot.
    /// Every backend calls this one function to mint and to verify, so the two
    /// sides cannot compute different things.
    ///
    /// Injective over every variant, which is what keeps one protocol's quote
    /// out of another. Each preimage opens with its variant's tag, and no tag is
    /// a prefix of another, so the tag alone says which variant it is. After
    /// that, every field is its length (u64, big-endian) followed by its bytes,
    /// so a NUL inside a session id cannot move where one field ends. The one
    /// exception is RA-TLS, whose only field runs to the end of the preimage: a
    /// fixed tag and a single trailing field already leave nothing to split.
    pub fn hash(&self) -> [u8; 32] {
        fn field(h: &mut Sha256, bytes: &[u8]) {
            h.update((bytes.len() as u64).to_be_bytes());
            h.update(bytes);
        }

        let mut h = Sha256::new();
        match self {
            ReportData::Session {
                session_id,
                policy_digest,
            } => {
                h.update(SESSION_TAG);
                field(&mut h, session_id.as_bytes());
                field(&mut h, policy_digest.as_bytes());
            }
            ReportData::Kbs { ephemeral_pubkey } => {
                h.update(KBS_TAG);
                field(&mut h, ephemeral_pubkey);
            }
            ReportData::Ratls { spki_der } => {
                h.update(RATLS_TAG);
                h.update(spki_der);
            }
        }
        h.finalize().into()
    }
}

/// Backend trait — all signing/verification details live behind this.
pub trait Attestor: Send + Sync {
    /// Mint a quote binding `data`. Backend handles measurement injection,
    /// signing-key access, and quote formatting.
    fn mint(&self, data: &ReportData) -> Result<Quote, AttestationError>;

    /// Verify `quote` carries `expected` as its bound report_data and was
    /// signed by a key the backend trusts.
    ///
    /// On success returns `()`; on failure returns a typed error indicating
    /// which check failed (signature, binding mismatch, format).
    fn verify(&self, quote: &Quote, expected: &ReportData) -> Result<(), AttestationError>;
}

// A build that signs with real hardware must not also carry a software signer.
// Cargo features are additive and arrive through the whole dependency graph, so
// a single edge that takes this crate with its defaults would re-arm one — which
// is how `mock` stayed in a binary whose own manifest asked only for `sev-snp`.
// Failing here catches it at any depth, not just at the manifest a reader
// happens to be looking at.
//
// This crate is a leaf, so it is also the FIRST thing to fail, ahead of the same
// check written in each binary. That makes its wording the one a reader acts on,
// and the common cause is not the graph at all: a role whose own manifest says
// `default = ["dev-attestation"]` brings it along unless the build says
// otherwise. `--features guest-hardening` reaches here that way. Naming the
// likely cause first is the difference between reading a command line and
// searching a dependency tree that has nothing wrong with it.
#[cfg(all(feature = "sev-snp", any(feature = "mock", feature = "snp-dev")))]
compile_error!(
    "a software attestation backend (`mock` / `snp-dev`) is enabled alongside `sev-snp`. \
     Usually the build kept the role's own defaults: `sev-snp` needs \
     `--no-default-features`, or `default = [\"dev-attestation\"]` arrives with it. \
     If the build already says that, then some dependency edge is taking \
     enclavid-attestation with default features instead"
);

#[cfg(feature = "mock")]
mod mock;
#[cfg(feature = "mock")]
pub use mock::{DEV_FLEET_MEASUREMENT, MockAttestor};

#[cfg(feature = "snp-dev")]
mod snp_dev;
#[cfg(feature = "snp-dev")]
pub use snp_dev::SnpDevAttestor;

#[cfg(feature = "sev-snp")]
mod snp;
#[cfg(feature = "sev-snp")]
pub use snp::{MILAN_ASK, PRODUCT_LINE, verify_quote, verify_quote_supplied};
/// Minting and reading one's own endorsement parameters need
/// `/dev/sev-guest`; verification does not, so only this half is Linux-gated.
#[cfg(all(feature = "sev-snp", target_os = "linux"))]
pub use snp::{SnpAttestor, VcekIdentity, derive_seal_key, vcek_identity};

#[cfg(test)]
mod tests {
    use super::*;

    /// The collision the tags exist to prevent. With every variant hashed into
    /// one untagged stream, a KBS key that began with `ratls-spki\0` — the
    /// RA-TLS marker less the NUL a field separator supplied — produced the
    /// preimage of the certificate that followed it: a key-release quote that
    /// verified as RA-TLS evidence. A session whose digest began the same way
    /// did too.
    #[test]
    fn no_other_variant_reaches_an_ratls_preimage() {
        let spki = b"a-subject-public-key-info".to_vec();
        let ratls = ReportData::for_ratls(spki.clone()).hash();

        let kbs = ReportData::for_kbs([b"ratls-spki\x00".as_slice(), &spki].concat());
        assert_ne!(kbs.hash(), ratls);

        let digest = String::from_utf8([b"\x00ratls-spki\x00".as_slice(), &spki].concat()).unwrap();
        let session = ReportData::session(String::new(), digest);
        assert_ne!(session.hash(), ratls);
    }

    /// A session id is chosen outside this crate and may hold a NUL. Were the
    /// fields separated by one, `("a\0b", "c")` and `("a", "b\0c")` would be the
    /// same bytes; a length in front of each field is what tells them apart.
    #[test]
    fn a_nul_in_a_session_id_cannot_move_the_split() {
        let one = ReportData::session("a\x00b".into(), "c".into());
        let other = ReportData::session("a".into(), "b\x00c".into());
        assert_ne!(one.hash(), other.hash());
    }

    /// Each variant's hash, pinned. The values were computed outside Rust, from
    /// the layout [`ReportData::hash`] documents, so a change to the layout —
    /// deliberate or not — fails here rather than as a quote no peer accepts.
    #[test]
    fn each_variant_hashes_to_its_known_answer() {
        let session = ReportData::session("ses_01HF7K".into(), "sha256:7e93fba".into());
        assert_eq!(
            hex::encode(session.hash()),
            "747d204813283c5cd23e5c70e2dc1ef0ea44cfd377f1e3dafd8ef1e1979fca88"
        );

        let kbs = ReportData::for_kbs(vec![9u8; 32]);
        assert_eq!(
            hex::encode(kbs.hash()),
            "b3d6e0234d31726fdd7f2cdffb8c5632b3d1540abd972164792cdafe1899b1cf"
        );

        // The one a real part's quote binds; see `RATLS_TAG`.
        let ratls = ReportData::for_ratls(vec![1, 2, 3]);
        assert_eq!(
            hex::encode(ratls.hash()),
            "01900136a12b12142e1160a33d48f867dfeabc8d5e1a2cac66c09128a3b2344c"
        );
    }

    /// The blob crosses the wire as a CBOR byte string, not an array of
    /// integers, and reads back as the same bytes.
    #[test]
    fn the_quote_blob_is_a_cbor_byte_string() {
        let quote = Quote {
            format: "any".into(),
            quote_blob: vec![0x00, 0x01, 0xff],
            measurement: String::new(),
            chip_id: String::new(),
        };
        let mut encoded = Vec::new();
        ciborium::into_writer(&quote, &mut encoded).unwrap();

        let value: ciborium::Value = ciborium::from_reader(encoded.as_slice()).unwrap();
        let blob = value
            .as_map()
            .unwrap()
            .iter()
            .find(|(key, _)| key.as_text() == Some("quote_blob"))
            .map(|(_, blob)| blob)
            .unwrap();
        assert_eq!(blob, &ciborium::Value::Bytes(vec![0x00, 0x01, 0xff]));

        let decoded: Quote = ciborium::from_reader(encoded.as_slice()).unwrap();
        assert_eq!(decoded.quote_blob, quote.quote_blob);
    }
}
