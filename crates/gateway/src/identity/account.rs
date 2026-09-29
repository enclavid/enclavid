//! The ACME account this role holds, and why it is held here rather than by
//! whoever asks an issuer for this role's certificate.
//!
//! ## What an account decides
//!
//! An issuer certifies a key for a name to whichever account proves it can
//! answer for the name — and whoever carries the traffic to this role's port
//! can prove that: the host, or anything in front of it. Any of them could
//! open an account of its own and have a certificate issued for a key of its
//! own. A name's CAA record can narrow issuance to named accounts (RFC 8657's
//! `accounturi`), and that narrows it to whoever holds an account's key.
//!
//! So the key is this role's. It is derived from the chip's key, as the serving
//! key is and under a purpose of its own: the same at every boot of this build
//! on this part, another for another build or another part, and never anywhere
//! but this guest's memory — see `crate::identity::key`.
//!
//! ## What it signs
//!
//! Only what `crate::config::acme` writes: a few kinds of request, whose one
//! request for a certificate is for the serving key. So every certificate this
//! account can be issued is one only this role can present — whoever carries
//! the requests to the issuer, and whoever asks for them to be signed.
//!
//! ## What anyone may see of it
//!
//! Its public key, as a JWK (RFC 7517), served beside the quote — see [`PATH`]
//! — over a connection on the key the quote binds.
//!
//! A CAA record names an account by its URL, which only the issuer maps to a
//! key, so the URL the host reports is the host's word. Whoever writes the
//! record checks it with this key: a `new-account` request this role signs,
//! over a nonce they took from the issuer themselves, carries the key in its
//! header, and the issuer, sent that request, answers with the URL of the
//! account the key holds.
//!
//! The key is held once, for the life of the process, by the library that
//! signs with it. The PKCS#8 bytes it is loaded from are wiped as they go.

use base64ct::{Base64UrlUnpadded, Encoding};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

/// What this key is derived FOR — the serving key is derived for another.
const PURPOSE: &[u8] = b"enclavid.gateway.acme-account.v1";

/// Where the account's public key is served, beside the quote.
pub const PATH: &str = "/.well-known/enclavid-acme-account";

/// The `Content-Type` it is served with.
pub const CONTENT_TYPE: &str = "application/jwk+json";

/// The ACME account key this process signs with.
pub struct Account {
    key: EcdsaKeyPair,
    random: SystemRandom,
    /// The public key as a JWK, in RFC 7638's form: its required members only,
    /// in order, with no whitespace — what its thumbprint is taken over.
    jwk: String,
    thumbprint: String,
    /// Whether anyone can compute this key — see [`Account::public`].
    public: bool,
}

impl Account {
    /// The account key this (part, build) holds, arrived at again at every boot.
    pub fn derived(chip: &[u8; 32]) -> Result<Account, String> {
        let pkcs8 = super::key::derived_pkcs8(chip, PURPOSE)?;
        Account::holding(pkcs8.as_bytes())
    }

    /// A developer build's: derived as the attested one is, from a value in the
    /// source, and so [`public`](Account::public).
    #[cfg(not(feature = "sev-snp"))]
    pub fn no_chip() -> Result<Account, String> {
        let mut account = Account::derived(&super::key::NO_CHIP)?;
        account.public = true;
        Ok(account)
    }

    /// A key nothing derived, for a test that wants one it can sign with.
    #[cfg(test)]
    pub fn generated() -> Result<Account, String> {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .map_err(|_| "generate an account key".to_string())?;
        Account::holding(pkcs8.as_ref())
    }

    fn holding(pkcs8: &[u8]) -> Result<Account, String> {
        let random = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &random)
            .map_err(|e| format!("the derived bytes are not an account key: {e}"))?;
        // The point, uncompressed: 0x04, then x and y, 32 bytes each.
        let (x, y) = key.public_key().as_ref()[1..].split_at(32);
        let jwk = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            base64url(x),
            base64url(y)
        );
        let thumbprint =
            base64url(ring::digest::digest(&ring::digest::SHA256, jwk.as_bytes()).as_ref());
        Ok(Account {
            key,
            random,
            jwk,
            thumbprint,
            public: false,
        })
    }

    /// The public key, as a JWK.
    pub fn jwk(&self) -> &str {
        &self.jwk
    }

    /// The JWK's thumbprint (RFC 7638), which a challenge's key authorization
    /// ends with.
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// Whether anyone can compute this key: a developer build's, derived from a
    /// value in its source. It signs nothing — an account whose key anyone can
    /// compute is anyone's account.
    pub fn public(&self) -> bool {
        self.public
    }

    /// `protected` and `payload` signed with ES256 (RFC 7518), as the flattened
    /// JWS (RFC 7515) an ACME server takes for a request's body.
    ///
    /// Only `crate::config::acme` calls this, with what it wrote itself — see
    /// the module docs.
    pub(crate) fn sign(&self, protected: &[u8], payload: &[u8]) -> Result<String, String> {
        let protected = base64url(protected);
        let payload = base64url(payload);
        let signature = self
            .key
            .sign(&self.random, format!("{protected}.{payload}").as_bytes())
            .map_err(|_| "the account key did not sign".to_string())?;
        Ok(format!(
            r#"{{"protected":"{protected}","payload":"{payload}","signature":"{}"}}"#,
            base64url(signature.as_ref())
        ))
    }
}

/// `bytes` in base64url without padding, the one encoding JOSE uses.
pub fn base64url(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A JWS this key signed, checked against its JWK: its protected header
    /// and payload, decoded, if the signature holds.
    pub(crate) fn opened(account: &Account, jws: &str) -> (serde_json::Value, Vec<u8>) {
        let jws: serde_json::Value = serde_json::from_str(jws).unwrap();
        let field = |name: &str| jws[name].as_str().unwrap().to_owned();
        let decode = |text: &str| Base64UrlUnpadded::decode_vec(text).unwrap();
        let jwk: serde_json::Value = serde_json::from_str(account.jwk()).unwrap();
        let point = [
            &[4u8][..],
            &decode(jwk["x"].as_str().unwrap()),
            &decode(jwk["y"].as_str().unwrap()),
        ]
        .concat();
        ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, point)
            .verify(
                format!("{}.{}", field("protected"), field("payload")).as_bytes(),
                &decode(&field("signature")),
            )
            .expect("the signature holds under the account's JWK");
        (
            serde_json::from_slice(&decode(&field("protected"))).unwrap(),
            decode(&field("payload")),
        )
    }

    /// The same chip key gives the same account at every boot — which is what
    /// lets a CAA record name it — and another chip key another account.
    #[test]
    fn the_same_chip_key_gives_the_same_account() {
        let first = Account::derived(&[7; 32]).unwrap();
        assert_eq!(first.jwk(), Account::derived(&[7; 32]).unwrap().jwk());
        assert_ne!(first.jwk(), Account::derived(&[8; 32]).unwrap().jwk());
    }

    /// Derived from the same chip key as the serving key, and still another
    /// key: the two are derived for different purposes.
    #[test]
    fn the_account_key_is_not_the_serving_key() {
        let account = Account::derived(&[7; 32]).unwrap();
        let serving = crate::identity::key::Identity::derived(&[7; 32]).unwrap();
        let jwk: serde_json::Value = serde_json::from_str(account.jwk()).unwrap();
        let x = Base64UrlUnpadded::decode_vec(jwk["x"].as_str().unwrap()).unwrap();
        assert!(
            !serving.spki().windows(x.len()).any(|w| w == x),
            "the serving key's point is not the account's"
        );
    }

    /// The JWK is in RFC 7638's form and the thumbprint is taken over exactly
    /// it: what a key authorization ends with, and what an issuer computes.
    #[test]
    fn the_thumbprint_is_taken_over_the_canonical_jwk() {
        let account = Account::generated().unwrap();
        let jwk: serde_json::Value = serde_json::from_str(account.jwk()).unwrap();
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap()
        );
        assert_eq!(account.jwk(), canonical);
        assert_eq!(
            account.thumbprint(),
            base64url(ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes()).as_ref())
        );
        assert_eq!(account.thumbprint().len(), 43);
    }

    /// What it signs verifies under its JWK, as an issuer checks it.
    #[test]
    fn a_signature_verifies_under_the_jwk() {
        let account = Account::generated().unwrap();
        let jws = account.sign(br#"{"alg":"ES256"}"#, b"{}").unwrap();
        let (protected, payload) = opened(&account, &jws);
        assert_eq!(protected["alg"], "ES256");
        assert_eq!(payload, b"{}");
    }

    /// A developer build's account is the same everywhere and marked as one
    /// anyone can compute.
    #[cfg(not(feature = "sev-snp"))]
    #[test]
    fn a_developer_build_s_account_is_marked_public() {
        let developer = Account::no_chip().unwrap();
        assert!(developer.public());
        assert!(!Account::derived(&[7; 32]).unwrap().public());
        assert!(!Account::generated().unwrap().public());
    }
}
