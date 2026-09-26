//! Checking a quote the way a consumer has to, against one a real part signed.
//!
//! Every other test in this crate verifies something this crate also minted,
//! with a software key. This one holds bytes that came off an AMD Milan part in
//! the fleet: the gateway's own quote — captured while `quote_blob` was still
//! written as an array of integers, which the decoder still reads — the
//! certificate AMD's key service issued
//! for that chip at that TCB, and the public key of the certificate the
//! connection presented. Nothing here can be produced by running the tests —
//! the material was captured once and checked in.
//!
//! What it pins is the whole consumer-side path, which no other test reaches:
//! a guest with no egress carries no endorsement, so the verifier fetches one
//! and brings it. That path existed in this crate but had no way in until
//! [`verify_quote_supplied`], and nothing had ever run it against a real part.
//!
//! The fixtures are in `tests/from-a-real-part/`. They are not secret: a quote
//! is a signed statement about a public image, the certificate is AMD's, and
//! the key is the public half of one that is gone with the process that held
//! it.

#![cfg(all(feature = "sev-snp", not(feature = "mock"), not(feature = "snp-dev")))]

use enclavid_attestation::{MILAN_ASK, ReportData, verify_quote, verify_quote_supplied};

const QUOTE: &[u8] = include_bytes!("from-a-real-part/quote.cbor");
const VCEK: &[u8] = include_bytes!("from-a-real-part/vcek.der");
const SPKI: &[u8] = include_bytes!("from-a-real-part/spki.der");

/// The measurement the image this quote came from was built to, computed by
/// `nix-build image -A measurements.gateway-debug` at the time of capture. A
/// change to the gateway moves it, and this test is not about the gateway —
/// so it asserts only that the quote says the same thing twice: in the field a
/// reader looks at, and in the report the signature covers.
const CAPTURED: &str = "c957424436f6f4651421d429ec87290a2a67a34a339e2ae9289a58a981595b46f75bba58f200ae597618916bc3238c0e";

fn quote() -> enclavid_attestation::Quote {
    ciborium::from_reader(QUOTE).expect("the captured quote decodes")
}

/// The check a consumer performs, end to end: AMD's chain signs the report, the
/// platform posture is acceptable, and the report binds the key the connection
/// presented.
#[test]
fn a_quote_from_a_real_part_verifies_against_the_certificate_amd_issued() {
    verify_quote_supplied(
        &quote(),
        &ReportData::for_ratls(SPKI.to_vec()),
        MILAN_ASK,
        VCEK,
    )
    .expect("a real quote, a real certificate, and the key it was minted over");
}

/// And the binding is what carries the weight: the same quote against another
/// key is refused, or the check above would pass for any connection at all.
#[test]
fn the_same_quote_does_not_verify_against_another_key() {
    let another = vec![0u8; SPKI.len()];
    assert!(
        verify_quote_supplied(&quote(), &ReportData::for_ratls(another), MILAN_ASK, VCEK).is_err()
    );
}

/// A guest with no egress cannot obtain its own certificate, so its quote
/// carries none — and the entry point that expects one refuses it. This is why
/// [`verify_quote_supplied`] exists, and the refusal is worth pinning: it is
/// the difference between "no endorsement" and "endorsement that did not
/// check".
#[test]
fn the_self_endorsed_entry_point_refuses_a_certless_quote() {
    let refused = verify_quote(&quote(), &ReportData::for_ratls(SPKI.to_vec()))
        .expect_err("it carries no chain to check");
    assert!(
        format!("{refused}").contains("carries no endorsement"),
        "{refused}"
    );
}

/// The measurement a reader takes off the quote is the one the signature
/// covers. Without this the field is the sender's word about a signed value.
#[test]
fn the_measurement_field_is_the_signed_one() {
    let quote = quote();
    assert_eq!(quote.measurement, CAPTURED);

    // Verification compares the two itself, so a quote whose field was edited
    // fails — which is what makes reading the field safe.
    let mut edited = quote.clone();
    edited.measurement = "0".repeat(96);
    assert!(
        verify_quote_supplied(
            &edited,
            &ReportData::for_ratls(SPKI.to_vec()),
            MILAN_ASK,
            VCEK
        )
        .is_err()
    );
}

/// The same for the part: a verifier holding a certificate learns which chip
/// signed, and the field must agree with it.
#[test]
fn the_chip_field_is_the_signed_one() {
    let mut edited = quote();
    edited.chip_id = "0".repeat(128);
    assert!(
        verify_quote_supplied(
            &edited,
            &ReportData::for_ratls(SPKI.to_vec()),
            MILAN_ASK,
            VCEK
        )
        .is_err()
    );
}
