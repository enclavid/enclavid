//! End-to-end `kbs` key_source path, crypto + wire DTOs + stub KBS.
//!
//! Mirrors the real flow minus the HTTP relay transport (thin typed
//! plumbing): CLI-style encrypt → seal layer key to the KBS → build the
//! attested key request → stub `release` → TEE unseal → ocicrypt decrypt.

use std::collections::HashSet;
use std::sync::Arc;

use broker_protocol::{KbsKeyRequest, KbsKeyResponse, SealedBlob};
use enclavid_attestation::{Attestor, MockAttestor, ReportData};
use enclavid_crypto::{kbswrap, ocicrypt};
use enclavid_kbs_stub::{KbsConfig, release};

const MEASUREMENT: &str = "deadbeefcafe";

fn attestor() -> Arc<dyn Attestor> {
    Arc::new(MockAttestor::from_seed([7u8; 32], MEASUREMENT.to_string()))
}

/// Build the artifact side exactly as `enclavid oci push --encrypt kbs`
/// does: encrypt, then seal the private opts to the KBS public key. Returns
/// (ciphertext, public opts, wrapped-priv-opts bytes for the annotation).
fn encrypt_for_kbs(
    plaintext: &[u8],
    kbs_pub: &[u8; 32],
) -> (Vec<u8>, ocicrypt::PublicLayerBlockCipherOptions, Vec<u8>) {
    let (ct, public, private) = ocicrypt::encrypt(plaintext);
    let priv_json = ocicrypt::privopts_to_json(&private).unwrap();
    let sealed = kbswrap::seal(kbs_pub, &priv_json).unwrap();
    let blob = SealedBlob {
        sender_pub: sealed.sender_pub.to_vec(),
        nonce: sealed.nonce.to_vec(),
        ciphertext: sealed.ciphertext,
    };
    (ct, public, broker_protocol::encode(&blob).unwrap())
}

/// Build the TEE-side request as `keyprovider::kbs_release` does.
fn tee_request(
    attestor: &dyn Attestor,
    token: &str,
    wrapped: Vec<u8>,
) -> ([u8; 32], Vec<u8>) {
    let (eph_secret, eph_public) = kbswrap::generate_keypair();
    let quote = attestor
        .mint(&ReportData::for_kbs(eph_public.to_vec()))
        .unwrap();
    let req = KbsKeyRequest {
        quote: serde_json::to_vec(&quote).unwrap(),
        tee_ephemeral_pubkey: eph_public.to_vec(),
        token: token.to_string(),
        wrapped_priv_opts: wrapped,
    };
    (eph_secret, broker_protocol::encode(&req).unwrap())
}

fn cfg(secret: [u8; 32], tokens: Option<HashSet<String>>) -> KbsConfig {
    KbsConfig {
        secret,
        attestor: attestor(),
        expected_measurement: MEASUREMENT.to_string(),
        allowed_tokens: tokens,
    }
}

#[test]
fn kbs_release_round_trip() {
    let plaintext = b"proprietary plugin component bytes".repeat(50);
    let (kbs_secret, kbs_public) = enclavid_kbs_stub::generate_keypair();

    let (ct, public, wrapped) = encrypt_for_kbs(&plaintext, &kbs_public);
    let (eph_secret, request) = tee_request(attestor().as_ref(), "lic-bank-1", wrapped);

    let resp_bytes = release(&request, &cfg(kbs_secret, None)).unwrap();
    let resp: KbsKeyResponse = broker_protocol::decode(&resp_bytes).unwrap();

    // TEE unseals to its ephemeral secret → private opts → decrypt.
    let sealed = kbswrap::Sealed {
        sender_pub: resp.sealed.sender_pub.try_into().unwrap(),
        nonce: resp.sealed.nonce.try_into().unwrap(),
        ciphertext: resp.sealed.ciphertext,
    };
    let priv_json = kbswrap::open(&eph_secret, &sealed).unwrap();
    let private = ocicrypt::privopts_from_json(&priv_json).unwrap();
    let out = ocicrypt::decrypt(&ct, &public, &private).unwrap();
    assert_eq!(out, plaintext);
}

#[test]
fn unauthorized_token_denied() {
    let plaintext = b"secret";
    let (kbs_secret, kbs_public) = enclavid_kbs_stub::generate_keypair();
    let (_ct, _public, wrapped) = encrypt_for_kbs(plaintext, &kbs_public);
    let (_eph, request) = tee_request(attestor().as_ref(), "not-licensed", wrapped);

    let allowed = HashSet::from(["lic-bank-1".to_string()]);
    assert!(release(&request, &cfg(kbs_secret, Some(allowed))).is_err());
}

#[test]
fn wrong_measurement_denied() {
    let (kbs_secret, kbs_public) = enclavid_kbs_stub::generate_keypair();
    let (_ct, _public, wrapped) = encrypt_for_kbs(b"secret", &kbs_public);
    let (_eph, request) = tee_request(attestor().as_ref(), "lic-bank-1", wrapped);

    let bad_cfg = KbsConfig {
        secret: kbs_secret,
        attestor: attestor(),
        expected_measurement: "0000".to_string(),
        allowed_tokens: None,
    };
    assert!(release(&request, &bad_cfg).is_err());
}

#[test]
fn forged_quote_denied() {
    // A quote minted by a different attestor (different signing key) must
    // not verify against the KBS's attestor.
    let (kbs_secret, kbs_public) = enclavid_kbs_stub::generate_keypair();
    let (_ct, _public, wrapped) = encrypt_for_kbs(b"secret", &kbs_public);
    let foreign: Arc<dyn Attestor> =
        Arc::new(MockAttestor::from_seed([9u8; 32], MEASUREMENT.to_string()));
    let (_eph, request) = tee_request(foreign.as_ref(), "lic-bank-1", wrapped);

    assert!(release(&request, &cfg(kbs_secret, None)).is_err());
}
