//! The requests to an ACME issuer this role signs, and the only ones.
//!
//! ## The host speaks ACME; this role signs
//!
//! This guest has no network, so the protocol runs on the host: it reads the
//! issuer's directory, keeps the nonces, follows the order and fetches what is
//! issued. What it cannot do is sign, because the account's key is this
//! role's — see `crate::identity::account`. So for each request it asks this
//! role, on the configuration port, naming the kind of request and the
//! issuer's values that go into it — a URL, a nonce, the account's URL, the
//! names — and gets the request back whole, a JWS ready to send.
//!
//! ## What a request says is written here
//!
//! Five kinds, each built here from typed values and never from the host's
//! bytes:
//!
//! - `new-account`: this account, agreeing to the issuer's terms, with the key
//!   itself in the header — RFC 8555 §7.3;
//! - `new-order`: a certificate wanted for some names, as the renewal of one
//!   certificate and under one profile if the host says — §7.4, and the
//!   `replaces` of ACME Renewal Information;
//! - `post-as-get`: an empty payload, which is how ACME reads a resource —
//!   §6.3;
//! - `challenge-ready`: `{}`, which tells the issuer to validate — §7.5.1;
//! - `finalize`: the request for a certificate over some names, built here for
//!   the serving key — §7.4.
//!
//! Nothing else can be signed. A request that rolls the account's key over,
//! deactivates something or revokes a certificate carries members none of
//! these ever holds, and the host fills in string values only, so it cannot
//! add one. The one request for a certificate is for the key only this role
//! holds, so a certificate issued to this account is one only this role can
//! present — which a name's CAA record, naming this account alone, then makes
//! true of every certificate for that name.
//!
//! What the host still decides is where each request goes, with which nonce,
//! and for which names. A request sent to another URL than its kind's is
//! refused there, or reads what it is sent to; a certificate for names the host
//! chose is still for this role's key. All of that is the host's to decide in
//! any case: it carries every connection.
//!
//! ## What is checked of the host's values
//!
//! Each is checked to be what it is — a URL, a nonce, a name — and a request
//! carrying anything more is refused. That keeps what a signature covers
//! legible; it is not what makes a signature safe to give, which is that
//! everything else in the request is written here.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_rustls::rustls::pki_types::DnsName;

use crate::identity::account::{Account, base64url};
use crate::identity::key::Identity;
use crate::identity::tls;

/// The most names one request may carry: as many as a public issuer puts in
/// one certificate.
pub const MOST_NAMES: usize = 100;

/// The longest URL taken — the issuer's, or the account's.
const MOST_URL: usize = 512;

/// The longest nonce taken.
const MOST_NONCE: usize = 256;

/// A request to sign, by kind: the one member of the object the host sends.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Asked {
    NewAccount(ToDirectory),
    NewOrder(Ordering),
    PostAsGet(ToAccount),
    ChallengeReady(ToAccount),
    Finalize(Finalizing),
}

/// A request made before there is an account to name: it names the key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToDirectory {
    url: String,
    nonce: String,
}

/// A request made as the account, which `kid` names.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToAccount {
    url: String,
    nonce: String,
    kid: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ordering {
    url: String,
    nonce: String,
    kid: String,
    names: Vec<String>,
    /// The certificate this order renews, as ACME Renewal Information names
    /// one.
    #[serde(default)]
    replaces: Option<String>,
    /// Which of the issuer's kinds of certificate — its lifetime, chiefly.
    #[serde(default)]
    profile: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Finalizing {
    url: String,
    nonce: String,
    kid: String,
    names: Vec<String>,
}

/// What is written, as it is written: structs rather than maps, so that the
/// members come out in the order declared here whichever map the JSON library
/// was built with.
#[derive(Serialize)]
struct Protected<'a> {
    alg: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    nonce: &'a str,
    url: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NewAccount {
    terms_of_service_agreed: bool,
}

#[derive(Serialize)]
struct NewOrder<'a> {
    identifiers: Vec<Identifier<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replaces: Option<&'a str>,
}

#[derive(Serialize)]
struct Identifier<'a> {
    r#type: &'static str,
    value: &'a str,
}

#[derive(Serialize)]
struct Finalize {
    csr: String,
}

/// Why an account anyone can compute signs nothing.
const PUBLIC_ACCOUNT: &str = "this build's account key is derived from a value in its source, so \
                              anyone can compute it; it signs no request to an issuer";

/// The request `body` asks for, signed by `account`, as the JWS to send; or why
/// it is not signed, for the sender to read.
pub fn signed(identity: &Identity, account: &Account, body: &[u8]) -> Result<String, String> {
    if account.public() {
        return Err(PUBLIC_ACCOUNT.into());
    }
    let asked: Asked = serde_json::from_slice(body).map_err(|e| {
        format!(
            "not a request this role signs — one of new-account, new-order, post-as-get, \
             challenge-ready or finalize: {e}"
        )
    })?;
    let (protected, payload) = match &asked {
        Asked::NewAccount(to) => {
            let jwk: Value = serde_json::from_str(account.jwk())
                .map_err(|e| format!("the account's JWK: {e}"))?;
            (
                header(&to.url, &to.nonce, Some(jwk), None)?,
                written(&NewAccount {
                    terms_of_service_agreed: true,
                }),
            )
        }
        Asked::NewOrder(order) => {
            let names = checked(&order.names)?;
            if let Some(replaces) = &order.replaces
                && !certificate_id(replaces)
            {
                return Err(
                    "replaces is not a certificate's identifier, base64url.base64url".into(),
                );
            }
            if let Some(profile) = &order.profile
                && !token(profile, 64, |b| {
                    b.is_ascii_alphanumeric() || b"._-".contains(&b)
                })
            {
                return Err("profile is not a profile's name".into());
            }
            (
                header(&order.url, &order.nonce, None, Some(&order.kid))?,
                written(&NewOrder {
                    identifiers: names
                        .iter()
                        .map(|name| Identifier {
                            r#type: "dns",
                            value: name,
                        })
                        .collect(),
                    profile: order.profile.as_deref(),
                    replaces: order.replaces.as_deref(),
                }),
            )
        }
        Asked::PostAsGet(to) => (header(&to.url, &to.nonce, None, Some(&to.kid))?, Vec::new()),
        Asked::ChallengeReady(to) => (
            header(&to.url, &to.nonce, None, Some(&to.kid))?,
            b"{}".to_vec(),
        ),
        Asked::Finalize(order) => {
            let names = checked(&order.names)?;
            let request = tls::request(identity, names)?;
            (
                header(&order.url, &order.nonce, None, Some(&order.kid))?,
                written(&Finalize {
                    csr: base64url(&request),
                }),
            )
        }
    };
    account.sign(&protected, &payload)
}

/// A request's protected header: ES256, the nonce and URL checked to be ones,
/// and the account named by its key before it exists, by its URL after.
fn header(
    url: &str,
    nonce: &str,
    jwk: Option<Value>,
    kid: Option<&str>,
) -> Result<Vec<u8>, String> {
    if !https(url) {
        return Err(format!(
            "url is not an https URL of at most {MOST_URL} characters"
        ));
    }
    if !token(nonce, MOST_NONCE, base64url_byte) {
        return Err(format!(
            "nonce is not base64url of at most {MOST_NONCE} characters"
        ));
    }
    if let Some(kid) = kid
        && !https(kid)
    {
        return Err(format!(
            "kid is not an https URL of at most {MOST_URL} characters"
        ));
    }
    Ok(written(&Protected {
        alg: "ES256",
        jwk,
        kid,
        nonce,
        url,
    }))
}

/// One of the structs above, as JSON. Strings, bools and sequences of them,
/// which always serialise.
fn written<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).expect("strings and bools serialise")
}

/// Between one and [`MOST_NAMES`] names, each checked to be a DNS name.
fn checked(names: &[String]) -> Result<&[String], String> {
    if names.is_empty() || names.len() > MOST_NAMES {
        return Err(format!("names: between 1 and {MOST_NAMES} of them"));
    }
    for name in names {
        DnsName::try_from(name.as_str()).map_err(|_| format!("`{name}` is not a DNS name"))?;
    }
    Ok(names)
}

/// An `https://` URL, of the printable ASCII a URL is written in and no longer
/// than [`MOST_URL`].
fn https(url: &str) -> bool {
    url.len() <= MOST_URL
        && url.starts_with("https://")
        && url
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"\"\\<>{}|^`".contains(&b))
}

/// Between one and `most` bytes, each one `allowed` takes.
fn token(text: &str, most: usize, allowed: impl Fn(u8) -> bool) -> bool {
    !text.is_empty() && text.len() <= most && text.bytes().all(allowed)
}

fn base64url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// A certificate's identifier as ACME Renewal Information writes it: its
/// issuer's key identifier and its serial, each in base64url, joined by a dot.
fn certificate_id(id: &str) -> bool {
    match id.split_once('.') {
        Some((key, serial)) => {
            token(key, 128, base64url_byte) && token(serial, 128, base64url_byte)
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    use crate::identity::account::tests::opened;

    const URL: &str = "https://acme.example/acme/new-order";
    const KID: &str = "https://acme.example/acme/acct/1";
    const NONCE: &str = "nOnCe_-0";

    fn keys() -> (Identity, Account) {
        (
            Identity::generated().unwrap(),
            Account::generated().unwrap(),
        )
    }

    /// `body` signed, and opened again: its header and its payload.
    fn signing(identity: &Identity, account: &Account, body: Value) -> (Value, Vec<u8>) {
        let jws = signed(identity, account, body.to_string().as_bytes()).unwrap();
        opened(account, &jws)
    }

    /// Each kind says exactly what it is written to say, whatever the host
    /// asked with — byte for byte, since these bytes are what an issuer reads.
    #[test]
    fn each_kind_writes_its_own_payload() {
        let (identity, account) = keys();
        let to_account = json!({ "url": URL, "nonce": NONCE, "kid": KID });

        let (_, payload) = signing(
            &identity,
            &account,
            json!({ "new-account": { "url": URL, "nonce": NONCE } }),
        );
        assert_eq!(payload, br#"{"termsOfServiceAgreed":true}"#);

        let (_, payload) = signing(
            &identity,
            &account,
            json!({ "new-order": { "url": URL, "nonce": NONCE, "kid": KID,
                                   "names": ["a.example", "b.example"] } }),
        );
        assert_eq!(
            payload,
            br#"{"identifiers":[{"type":"dns","value":"a.example"},{"type":"dns","value":"b.example"}]}"#
        );

        let (_, payload) = signing(
            &identity,
            &account,
            json!({ "new-order": { "url": URL, "nonce": NONCE, "kid": KID, "names": ["a.example"],
                                   "replaces": "aYhba4dGQEH.AIdlQyE", "profile": "shortlived" } }),
        );
        assert_eq!(
            payload,
            br#"{"identifiers":[{"type":"dns","value":"a.example"}],"profile":"shortlived","replaces":"aYhba4dGQEH.AIdlQyE"}"#
        );

        let (_, payload) = signing(&identity, &account, json!({ "post-as-get": to_account }));
        assert!(payload.is_empty());

        let (_, payload) = signing(
            &identity,
            &account,
            json!({ "challenge-ready": to_account }),
        );
        assert_eq!(payload, b"{}");
    }

    /// The one request for a certificate is for the serving key, over the
    /// names asked for.
    #[test]
    fn finalize_asks_for_the_serving_key() {
        use x509_parser::prelude::FromDer;

        let (identity, account) = keys();
        let (_, payload) = signing(
            &identity,
            &account,
            json!({ "finalize": { "url": URL, "nonce": NONCE, "kid": KID,
                                  "names": ["a.example", "b.example"] } }),
        );
        let payload: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(payload.as_object().unwrap().len(), 1, "the request alone");
        let der = <base64ct::Base64UrlUnpadded as base64ct::Encoding>::decode_vec(
            payload["csr"].as_str().unwrap(),
        )
        .unwrap();
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&der).unwrap();
        assert_eq!(
            csr.certification_request_info.subject_pki.raw,
            identity.spki()
        );
        assert_eq!(
            crate::identity::tls::tests::requested_names(&der),
            ["a.example", "b.example"]
        );
    }

    /// The account is named by its key before it exists and by its URL after,
    /// never both; the nonce and the URL are the ones asked for.
    #[test]
    fn the_header_names_the_account_one_way() {
        let (identity, account) = keys();
        let (header, _) = signing(
            &identity,
            &account,
            json!({ "new-account": { "url": URL, "nonce": NONCE } }),
        );
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["nonce"], NONCE);
        assert_eq!(header["url"], URL);
        assert_eq!(
            header["jwk"],
            serde_json::from_str::<Value>(account.jwk()).unwrap()
        );
        assert!(header.get("kid").is_none());

        let (header, _) = signing(
            &identity,
            &account,
            json!({ "post-as-get": { "url": URL, "nonce": NONCE, "kid": KID } }),
        );
        assert_eq!(header["kid"], KID);
        assert!(header.get("jwk").is_none());
        assert_eq!(header.as_object().unwrap().len(), 4);
    }

    /// Anything past the five kinds, and anything more than a kind's own
    /// values, is refused — and so is a value that is not what it says.
    #[test]
    fn nothing_else_is_signed() {
        let (identity, account) = keys();
        let to_account = json!({ "url": URL, "nonce": NONCE, "kid": KID });
        let with = |extra: (&str, Value)| {
            let mut fields = to_account.clone();
            fields[extra.0] = extra.1;
            fields
        };
        for (body, said) in [
            (json!({ "key-change": to_account }), "unknown variant"),
            (json!({ "revoke-cert": to_account }), "unknown variant"),
            (json!({ "deactivate": to_account }), "unknown variant"),
            (
                json!({ "post-as-get": with(("status", json!("deactivated"))) }),
                "unknown field",
            ),
            (
                json!({ "challenge-ready": with(("payload", json!("{}"))) }),
                "unknown field",
            ),
            (
                json!({ "post-as-get": to_account, "challenge-ready": to_account }),
                "",
            ),
            (
                json!({ "new-account": { "url": URL, "nonce": NONCE, "kid": KID } }),
                "unknown field",
            ),
            (
                json!({ "post-as-get": with(("url", json!("http://acme.example/"))) }),
                "url is not",
            ),
            (
                json!({ "post-as-get": with(("kid", json!("https://acme.example/\"}"))) }),
                "kid is not",
            ),
            (
                json!({ "post-as-get": with(("nonce", json!("not/base64url"))) }),
                "nonce is not",
            ),
            (
                json!({ "new-order": with(("names", json!([]))) }),
                "between 1 and",
            ),
            (
                json!({ "new-order": with(("names", json!(["bad..example"]))) }),
                "is not a DNS name",
            ),
            (
                json!({ "new-order": with(("names", json!(["*.example"]))) }),
                "is not a DNS name",
            ),
            (
                json!({ "finalize": with(("names", json!(vec!["a.example"; MOST_NAMES + 1]))) }),
                "between 1 and",
            ),
            (
                json!({ "new-order": { "url": URL, "nonce": NONCE, "kid": KID,
                                       "names": ["a.example"], "replaces": "no-dot" } }),
                "replaces is not",
            ),
            (
                json!({ "new-order": { "url": URL, "nonce": NONCE, "kid": KID,
                                       "names": ["a.example"], "profile": "a\"b" } }),
                "profile is not",
            ),
        ] {
            let refused = signed(&identity, &account, body.to_string().as_bytes())
                .err()
                .unwrap_or_else(|| panic!("signed {body}"));
            assert!(refused.contains(said), "{body}: {refused}");
        }
    }

    /// An account anyone can compute signs nothing, not even the account's
    /// own creation.
    #[cfg(not(feature = "sev-snp"))]
    #[test]
    fn a_public_account_signs_nothing() {
        let identity = Identity::generated().unwrap();
        let account = Account::no_chip().unwrap();
        let refused = signed(
            &identity,
            &account,
            json!({ "new-account": { "url": URL, "nonce": NONCE } })
                .to_string()
                .as_bytes(),
        )
        .unwrap_err();
        assert!(refused.contains("anyone can compute it"), "{refused}");
    }
}
