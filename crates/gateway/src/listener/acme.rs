//! The connections an ACME validator opens, and what they are answered with.
//!
//! ## Why they reach this role at all
//!
//! TLS-ALPN-01 (RFC 8737) is validated on port 443 of the name, and behind port
//! 443 of every public name is this role: the host carries TLS through to it
//! and terminates none. A validator proves the name with a handshake and
//! nothing more — it offers one protocol, `acme-tls/1`, reads the certificate
//! and closes.
//!
//! ## Answered here, from what the host armed
//!
//! The certificate a validator reads carries a digest of the challenge's key
//! authorization (RFC 8737 §3): the challenge's token and the thumbprint of the
//! account's key, both of which the issuer hands to whoever runs the order.
//! That is the host, which runs ACME for this role — see `crate::config::acme`
//! — and it ARMS each name with its key authorization before it tells the
//! issuer to validate. The answer is built then, for that name alone, and kept
//! for [`ARMED_FOR`].
//!
//! A key authorization is no secret: the token is in what the issuer says about
//! the order, and the thumbprint is of a public key. Answering with one proves
//! only that whoever runs the order reaches the name — which the host, carrying
//! every connection, can prove in any case. So nothing more is checked of it,
//! and it need not be for this role's own account: armed with another's — a
//! newer build's, brought up beside this one — this role answers for it, and a
//! build takes over a name without the name going unanswered. Which accounts
//! may be issued a certificate for the name is the name's CAA record's to say.
//!
//! The certificate is signed by a key made for it and dropped with it, so the
//! serving key signs nothing the host had a hand in.
//!
//! ## Which connections, and who says
//!
//! Which connections are a validator's is decided here, by what each one
//! offers: `acme-tls/1` and nothing else. A browser never offers it, let alone
//! that alone, so no connection that could carry an applicant's data is
//! answered this way. One for a name nothing is armed for goes on to the
//! ordinary handshake, which refuses it with rustls's alert, as it refuses any
//! protocol this role does not speak.
//!
//! ## A handshake, and bounded as one
//!
//! A validator's connection is nothing but a handshake, so the whole of it is
//! bounded by `handshake_timeout`, as a handshake is, and closed once the
//! handshake is done: there is nothing to serve on it.
//!
//! ## The hello is read by rustls, as it arrives
//!
//! rustls reads the hello, for this role and for the handshake that follows
//! it, so the hello is parsed once, by rustls, and nothing of it by this role.
//! Whatever has arrived is handed over, up to as much as rustls itself takes at
//! once, and rustls judges each record's header as soon as it has one — so
//! what is not a record at all, another protocol or a second PROXY header, and
//! a length past what a record may hold, are refused with rustls's alert on
//! their first bytes, and a hello cut into many small records costs no more
//! here than it does inside rustls. What rustls took past the hello stays in
//! its buffer, which the handshake carries on from.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::DnsName;
use tokio_rustls::rustls::server::{Accepted, Acceptor};
use tokio_rustls::rustls::sign::{CertifiedKey, SingleCertAndKey};

use crate::identity::tls;

/// The one protocol a TLS-ALPN-01 validator offers.
const ACME_TLS: &[u8] = b"acme-tls/1";

/// The most read at a time: as much as rustls takes into its buffer at once.
const AT_ONCE: usize = 4096;

/// How long a name stays armed. An issuer validates within seconds of being
/// told to, so this is room for a slow one, and no more: past it, a name must
/// be armed again.
pub const ARMED_FOR: Duration = Duration::from_secs(10 * 60);

/// The most names held armed at once: as many as one certificate is issued
/// for, which is the most one order waits on. Arming one past it drops the
/// name armed longest ago — by then its order has moved on.
const MOST_ARMED: usize = crate::config::acme::MOST_NAMES;

/// The longest key authorization taken: a token and a thumbprint, with room.
const MOST_KEY_AUTHORIZATION: usize = 256;

/// Whether the caller that sent `hello` is a TLS-ALPN-01 validator: it offers
/// `acme-tls/1` and nothing else.
pub fn validates(hello: &Accepted) -> bool {
    let Some(mut offered) = hello.client_hello().alpn() else {
        return false;
    };
    offered.next() == Some(ACME_TLS) && offered.next().is_none()
}

/// Read a caller's hello off `stream`.
///
/// A hello rustls refuses is answered with whatever alert rustls gives for it.
pub async fn hello<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> io::Result<Accepted> {
    let mut acceptor = Acceptor::default();
    let mut arrived = vec![0u8; AT_ONCE];
    loop {
        let n = stream.read(&mut arrived).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if let Some(accepted) = handed(&mut acceptor, stream, &arrived[..n]).await? {
            return Ok(accepted);
        }
    }
}

/// Hand `bytes` to rustls, and the hello if it now has it whole. What rustls
/// refuses is answered with its alert.
async fn handed<S: AsyncWrite + Unpin>(
    acceptor: &mut Acceptor,
    stream: &mut S,
    mut bytes: &[u8],
) -> io::Result<Option<Accepted>> {
    while !bytes.is_empty() {
        // rustls takes bytes in pieces as its buffer grows, and refuses what
        // is past what it allows a hello rather than taking nothing.
        if acceptor.read_tls(&mut bytes)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a hello rustls took none of",
            ));
        }
    }
    match acceptor.accept() {
        Ok(accepted) => Ok(accepted),
        Err((e, mut alert)) => {
            let mut said = Vec::new();
            if alert.write_all(&mut said).is_ok() {
                let _ = stream.write_all(&said).await;
            }
            Err(io::Error::new(io::ErrorKind::InvalidData, e))
        }
    }
}

/// The answers this role holds for validators, by the name each is for.
pub struct Challenges(Mutex<HashMap<String, Armed>>);

/// One name's answer, and until when it is given.
struct Armed {
    until: Instant,
    answer: Arc<ServerConfig>,
}

impl Challenges {
    pub fn new() -> Challenges {
        Challenges(Mutex::new(HashMap::new()))
    }

    /// Answer a validator for `name` with `key_authorization` for the next
    /// [`ARMED_FOR`], in place of whatever `name` was armed with before.
    ///
    /// The reason for a refusal is the host's to read.
    pub fn arm(&self, name: &str, key_authorization: &str) -> Result<(), String> {
        self.arm_at(name, key_authorization, Instant::now())
    }

    fn arm_at(&self, name: &str, key_authorization: &str, now: Instant) -> Result<(), String> {
        DnsName::try_from(name).map_err(|_| format!("`{name}` is not a DNS name"))?;
        let name = name.to_ascii_lowercase();
        if !key_authorization_like(key_authorization) {
            return Err(format!(
                "key_authorization is not a token and a thumbprint, base64url.base64url, of at \
                 most {MOST_KEY_AUTHORIZATION} characters"
            ));
        }
        let answer = answer(&name, key_authorization)?;

        let mut armed = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        armed.retain(|_, one| one.until > now);
        if !armed.contains_key(&name)
            && armed.len() >= MOST_ARMED
            && let Some(oldest) = armed
                .iter()
                .min_by_key(|(_, one)| one.until)
                .map(|(name, _)| name.clone())
        {
            armed.remove(&oldest);
        }
        armed.insert(
            name,
            Armed {
                until: now + ARMED_FOR,
                answer,
            },
        );
        Ok(())
    }

    /// What a validator asking for `name` is answered with, if anything.
    pub fn answering(&self, name: Option<&str>) -> Option<Arc<ServerConfig>> {
        self.answering_at(name?, Instant::now())
    }

    fn answering_at(&self, name: &str, now: Instant) -> Option<Arc<ServerConfig>> {
        let armed = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        armed
            .get(&name.to_ascii_lowercase())
            .filter(|one| one.until > now)
            .map(|one| one.answer.clone())
    }
}

/// A token and a thumbprint, each base64url, joined by a dot.
fn key_authorization_like(text: &str) -> bool {
    let base64url = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    text.len() <= MOST_KEY_AUTHORIZATION
        && text
            .split_once('.')
            .is_some_and(|(token, thumbprint)| base64url(token) && base64url(thumbprint))
}

/// The handshake a validator for `name` is answered with: a certificate for
/// `name` alone, carrying the digest of `key_authorization` in the extension
/// RFC 8737 names, marked critical; offered under `acme-tls/1` alone.
fn answer(name: &str, key_authorization: &str) -> Result<Arc<ServerConfig>, String> {
    let digest = ring::digest::digest(&ring::digest::SHA256, key_authorization.as_bytes());
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()])
        .map_err(|e| format!("certificate parameters: {e}"))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(digest.as_ref())];
    let key = rcgen::KeyPair::generate().map_err(|e| format!("a key for the answer: {e}"))?;
    let certificate = params
        .self_signed(&key)
        .map_err(|e| format!("sign the answer: {e}"))?;
    // Handed over as it is, without the check a finished certificate gets
    // loading: that parses it as a client would, and a client refuses the
    // critical extension it knows nothing of — which is the one a validator
    // reads.
    let signer = tls::signer(&key.serialize_der())?;
    let answering = CertifiedKey::new(vec![certificate.der().clone()], signer);
    let mut config = ServerConfig::builder_with_provider(Arc::new(tls::provider()))
        .with_safe_default_protocol_versions()
        .expect("ring offers the default protocol versions")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(answering)));
    config.alpn_protocols = vec![ACME_TLS.to_vec()];
    Ok(Arc::new(config))
}

/// Answer a validator on `stream`, whose hello was `hello`, with `answer`, and
/// close it once the handshake is done.
pub async fn answered<S: AsyncRead + AsyncWrite + Unpin>(
    hello: Accepted,
    stream: S,
    answer: Arc<ServerConfig>,
) -> io::Result<()> {
    let mut shown = tokio_rustls::StartHandshake::from_parts(hello, stream)
        .into_stream(answer)
        .await?;
    // The validator closes once it has read the certificate; what is left is
    // saying goodbye, and a validator gone first is no failure.
    let _ = shown.shutdown().await;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use tokio_rustls::rustls;
    use tokio_rustls::rustls::pki_types::ServerName;

    /// The hello a client offering `protocols` sends first, in the records it
    /// sends it in.
    fn sent_by(protocols: &[&[u8]]) -> Vec<u8> {
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        config.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
        let mut client = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("verify.example.com").unwrap(),
        )
        .unwrap();
        let mut sent = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut sent).unwrap();
        }
        sent
    }

    /// `sent`, arriving on a connection, then `after`, then nothing more.
    async fn arriving(sent: &[u8], after: &[u8]) -> tokio::io::DuplexStream {
        let (near, mut far) = tokio::io::duplex(64 << 10);
        far.write_all(sent).await.unwrap();
        far.write_all(after).await.unwrap();
        drop(far);
        near
    }

    /// A validator is one that offers `acme-tls/1` alone — never one that
    /// offers it beside something else, and never one that offers nothing.
    #[tokio::test]
    async fn a_validator_offers_acme_tls_alone() {
        let offers: [(&[&[u8]], bool); 5] = [
            (&[ACME_TLS], true),
            (&[ACME_TLS, b"h2"], false),
            (&[b"h2", ACME_TLS], false),
            (&[b"h2", b"http/1.1"], false),
            (&[], false),
        ];
        for (protocols, validator) in offers {
            let mut stream = arriving(&sent_by(protocols), b"").await;
            let hello = hello(&mut stream).await.unwrap();
            assert_eq!(validates(&hello), validator, "{protocols:?}");
        }
    }

    /// A hello cut into many small records is read whole, as one in a single
    /// record is.
    #[tokio::test]
    async fn a_hello_in_many_small_records_is_read_whole() {
        let sent = sent_by(&[ACME_TLS]);
        // One record as the client sent it: its header, then the handshake.
        let (header, body) = sent.split_at(5);
        let mut cut = Vec::new();
        for piece in body.chunks(16) {
            cut.extend_from_slice(&header[..3]);
            cut.extend_from_slice(&(piece.len() as u16).to_be_bytes());
            cut.extend_from_slice(piece);
        }
        let mut stream = arriving(&cut, b"").await;
        assert!(validates(&hello(&mut stream).await.unwrap()));
    }

    /// What arrives together with the hello is not lost: it is in rustls's
    /// hands for the handshake — which here refuses it, as it is no record.
    #[tokio::test]
    async fn what_arrives_with_the_hello_is_not_lost() {
        let mut stream = arriving(&sent_by(&[b"h2"]), b"what came next").await;
        let hello = hello(&mut stream).await.unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let own = rcgen::CertificateParams::new(vec!["verify.example.com".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![own.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let mut connection = hello
            .into_connection(Arc::new(config))
            .map_err(|(e, _)| e)
            .unwrap();
        assert!(
            connection.process_new_packets().is_err(),
            "what came after the hello reached rustls"
        );
    }

    /// What is not a record at all, and a record longer than one may be, are
    /// refused on their first bytes, with rustls's alert — not waited on for
    /// the length their header would announce.
    #[tokio::test]
    async fn what_is_not_a_record_is_refused_on_its_header() {
        let starts: [(&str, &[u8]); 3] = [
            ("plain HTTP", b"GET / HTTP/1.1\r\n"),
            ("a second PROXY header", b"\r\n\r\n\x00\r\nQUIT\n"),
            ("a record past the largest", &[0x16, 0x03, 0x01, 0xff, 0xff]),
        ];
        for (what, start) in starts {
            // The far end stays open, so a read waiting on a length would wait.
            let (mut near, mut far) = tokio::io::duplex(4096);
            far.write_all(start).await.unwrap();
            let refused = tokio::time::timeout(Duration::from_secs(2), hello(&mut near))
                .await
                .unwrap_or_else(|_| panic!("{what}: waited on, not refused"));
            assert!(refused.is_err(), "{what}");
            drop(near);
            let mut said = Vec::new();
            far.read_to_end(&mut said).await.unwrap();
            assert_eq!(
                said.first(),
                Some(&0x15),
                "{what}: an alert record: {said:?}"
            );
        }
    }

    /// A hello rustls cannot read is refused, with the alert rustls gives it.
    #[tokio::test]
    async fn a_hello_that_does_not_read_is_refused_with_an_alert() {
        // A handshake record holding a ClientHello with nothing in it.
        let (mut near, mut far) = tokio::io::duplex(4096);
        far.write_all(&[0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00])
            .await
            .unwrap();
        assert!(hello(&mut near).await.is_err());
        drop(near);
        let mut said = Vec::new();
        far.read_to_end(&mut said).await.unwrap();
        assert_eq!(said.first(), Some(&0x15), "an alert record: {said:?}");
    }

    const NAME: &str = "verify.example.com";
    const KEY_AUTHORIZATION: &str =
        "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI";

    /// What a validator for [`NAME`] is shown by `answer`, over a handshake in
    /// memory: the protocol agreed, and the certificate.
    pub(crate) fn shown(answer: &Arc<ServerConfig>) -> (Option<Vec<u8>>, Vec<u8>) {
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(crate::listener::testing::AnyCertificate(
            Arc::new(rustls::crypto::ring::default_provider()),
        )))
        .with_no_client_auth();
        let mut client = {
            let mut config = client;
            config.alpn_protocols = vec![ACME_TLS.to_vec()];
            rustls::ClientConnection::new(Arc::new(config), ServerName::try_from(NAME).unwrap())
                .unwrap()
        };
        let mut server = rustls::ServerConnection::new(answer.clone()).unwrap();
        // Back and forth in memory until both are done.
        for _ in 0..10 {
            let mut bytes = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut bytes).unwrap();
            }
            server.read_tls(&mut &bytes[..]).unwrap();
            server.process_new_packets().unwrap();
            let mut bytes = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut bytes).unwrap();
            }
            client.read_tls(&mut &bytes[..]).unwrap();
            client.process_new_packets().unwrap();
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        (
            client.alpn_protocol().map(<[u8]>::to_vec),
            client.peer_certificates().unwrap()[0].to_vec(),
        )
    }

    /// What a validator checks of the certificate it is shown, RFC 8737 §3:
    /// one name, the one asked for, and the digest of the key authorization in
    /// a critical acmeIdentifier extension.
    pub(crate) fn answers_for(certificate: &[u8], name: &str, key_authorization: &str) -> bool {
        use x509_parser::extensions::GeneralName;

        let (_, parsed) = x509_parser::parse_x509_certificate(certificate).unwrap();
        let names: Vec<String> = parsed
            .subject_alternative_name()
            .unwrap()
            .map(|san| {
                san.value
                    .general_names
                    .iter()
                    .map(|name| match name {
                        GeneralName::DNSName(dns) => dns.to_string(),
                        other => format!("{other:?}"),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let identifier = parsed
            .extensions()
            .iter()
            .find(|ext| ext.oid.to_id_string() == "1.3.6.1.5.5.7.1.31");
        let digest = ring::digest::digest(&ring::digest::SHA256, key_authorization.as_bytes());
        // An OCTET STRING of 32 bytes, as the extension's value.
        let expected = [&[0x04, 0x20][..], digest.as_ref()].concat();
        names == [name] && identifier.is_some_and(|ext| ext.critical && ext.value == expected)
    }

    /// An armed name is answered as RFC 8737 asks: `acme-tls/1` agreed, and a
    /// certificate for the name alone carrying the key authorization's digest.
    #[test]
    fn an_armed_name_is_answered_as_a_validator_expects() {
        let challenges = Challenges::new();
        challenges.arm(NAME, KEY_AUTHORIZATION).unwrap();
        let answer = challenges.answering(Some("Verify.Example.com")).unwrap();
        let (agreed, certificate) = shown(&answer);
        assert_eq!(agreed.as_deref(), Some(ACME_TLS));
        assert!(answers_for(&certificate, NAME, KEY_AUTHORIZATION));
        assert!(!answers_for(&certificate, NAME, "another.authorization"));
    }

    /// A name nothing armed, and one armed longer ago than [`ARMED_FOR`], are
    /// answered with nothing; arming again replaces what was armed.
    #[test]
    fn only_a_name_armed_lately_is_answered() {
        let challenges = Challenges::new();
        let then = Instant::now();
        challenges.arm_at(NAME, KEY_AUTHORIZATION, then).unwrap();
        assert!(challenges.answering(None).is_none());
        assert!(challenges.answering(Some("api.example.com")).is_none());
        assert!(
            challenges
                .answering_at(NAME, then + ARMED_FOR - Duration::from_secs(1))
                .is_some()
        );
        assert!(challenges.answering_at(NAME, then + ARMED_FOR).is_none());

        challenges.arm(NAME, "another.authorization").unwrap();
        let (_, certificate) = shown(&challenges.answering(Some(NAME)).unwrap());
        assert!(answers_for(&certificate, NAME, "another.authorization"));
    }

    /// What is not a name or not a key authorization arms nothing, and no more
    /// names are held at once than one certificate is issued for: one past it
    /// takes the place of the name armed longest ago.
    #[test]
    fn arming_is_bounded_and_checked() {
        let challenges = Challenges::new();
        for (name, key_authorization, said) in [
            ("not a name", KEY_AUTHORIZATION, "is not a DNS name"),
            ("*.example.com", KEY_AUTHORIZATION, "is not a DNS name"),
            (NAME, "no-dot", "key_authorization is not"),
            (NAME, "a.b.c", "key_authorization is not"),
            (NAME, "token.", "key_authorization is not"),
            (
                NAME,
                &format!("{}.x", "t".repeat(MOST_KEY_AUTHORIZATION)),
                "key_authorization is not",
            ),
        ] {
            let refused = challenges.arm(name, key_authorization).unwrap_err();
            assert!(
                refused.contains(said),
                "{name} {key_authorization}: {refused}"
            );
        }

        let then = Instant::now();
        let at = |i: usize| then + Duration::from_secs(i as u64);
        for i in 0..MOST_ARMED {
            challenges
                .arm_at(&format!("n{i}.example.com"), KEY_AUTHORIZATION, at(i))
                .unwrap();
        }
        let now = at(MOST_ARMED);
        challenges
            .arm_at("n1.example.com", KEY_AUTHORIZATION, now)
            .expect("an armed name is armed again in its own place");
        assert!(challenges.answering_at("n0.example.com", now).is_some());

        challenges
            .arm_at("one-more.example.com", KEY_AUTHORIZATION, now)
            .expect("one more takes the place of the oldest");
        assert!(
            challenges
                .answering_at("one-more.example.com", now)
                .is_some()
        );
        assert!(
            challenges.answering_at("n0.example.com", now).is_none(),
            "the name armed longest ago is dropped"
        );
        assert!(challenges.answering_at("n1.example.com", now).is_some());
        assert!(challenges.answering_at("n2.example.com", now).is_some());
        assert_eq!(challenges.0.lock().unwrap().len(), MOST_ARMED);
    }
}
