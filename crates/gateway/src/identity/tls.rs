//! The identity this role presents to a browser.
//!
//! Distinct from `crates/ra-tls` and not a variant of it. RA-TLS certificates
//! are authenticated by a quote embedded in an extension and carry no name at
//! all, because both ends are ours and each verifies the other by measurement. A
//! browser can do neither: it verifies by name against a store this project does
//! not populate, and it cannot read its own channel's certificate from the page
//! to check anything further.
//!
//! So this is an ordinary certificate, and what makes terminating here worth
//! anything is not the certificate but WHERE the private key lives — inside a
//! measured guest, rather than in a host process that could then present
//! whatever it liked about the enclave behind it.
//!
//! ## Self-signed, and signed by an issuer
//!
//! The key is derived from what the chip gives this guest — the same one at
//! every boot — and never leaves this guest's encrypted memory, which is the
//! property worth having. This role's own certificate over it is self-signed,
//! and a browser refuses it; a tool that checks this role's quote does not need
//! more, since the quote binds the key.
//!
//! What a browser needs is an issuer's signature, and this role gets one
//! without ever talking to an issuer: it signs a [`request`] over some of the
//! names, the host has it issued, and the certificates come back to be checked
//! by [`issued`] — each for this key and inside its validity, and together
//! over every name. The key is the same in all of them, so the quote holds for
//! each, and a renewal changes a certificate and never the key.

use std::sync::Arc;

use tokio::sync::watch;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{
    CertificateDer, DnsName, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::{CertifiedKey, SigningKey};
use tokio_rustls::rustls::{Error as TlsError, InconsistentKeys};

use super::key::Identity;

/// The certificate over these names, self-signed by this role's key.
fn mint<S: AsRef<str>>(
    identity: &Identity,
    public_names: &[S],
) -> Result<rcgen::Certificate, String> {
    // No CA and no extension beyond the names: everything this certificate says
    // is "the holder of this key answers for these names", which is the only
    // claim a browser knows how to check.
    let mut params = subject(public_names)?;
    params.serial_number = Some(serial());
    params
        .self_signed(identity.key())
        .map_err(|e| format!("self-sign: {e}"))
}

/// A certificate's parameters over these names — as its subject alternative
/// names, where a client looks for them — each checked to be one.
///
/// Checked HERE, because rcgen does not check it. `CertificateParams::new`
/// accepts any string and writes it into a SAN verbatim, so a mistyped name
/// yields a perfectly well-formed certificate no client will ever match — and
/// this role would serve, report itself healthy, and be unreachable.
/// `crate::config` refuses one at the push as well, which is where it can still
/// be told to the sender; this is the check that cannot be skipped.
fn subject<S: AsRef<str>>(public_names: &[S]) -> Result<rcgen::CertificateParams, String> {
    if public_names.is_empty() {
        return Err("a serving certificate needs at least one name".into());
    }
    let mut names = Vec::with_capacity(public_names.len());
    for public_name in public_names {
        let public_name = public_name.as_ref();
        let name = DnsName::try_from(public_name.to_owned())
            .map_err(|_| format!("`{public_name}` is not a DNS name"))?;
        names.push(name.as_ref().to_string());
    }
    rcgen::CertificateParams::new(names).map_err(|e| format!("certificate parameters: {e}"))
}

/// A request for a certificate over these names, signed by this role's key, in
/// DER — what an issuer finalises against.
///
/// Signed by the key, because that is what proves the requester holds it: an
/// issuer that accepted a bare public key would certify it for anyone who
/// asked. Everything else a certificate needs — the issuer's own dealings, the
/// challenge, the account — happens outside this role, which never talks to an
/// issuer itself.
///
/// The names are all it asks for. rcgen gives every certificate a placeholder
/// common name, and an issuer reads a common name as one more name requested —
/// one it would refuse, taking the whole request with it — so the request
/// carries no subject at all.
///
/// A key anyone can compute asks for nothing — see [`Identity::public`].
pub fn request<S: AsRef<str>>(identity: &Identity, public_names: &[S]) -> Result<Vec<u8>, String> {
    if identity.public() {
        return Err(PUBLIC_KEY.into());
    }
    let mut params = subject(public_names)?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let request = params
        .serialize_request(identity.key())
        .map_err(|e| format!("certificate request: {e}"))?;
    Ok(request.der().to_vec())
}

/// Why a key anyone can compute is neither put forward for a certificate nor
/// given one: whoever computed it could present that certificate as this role.
const PUBLIC_KEY: &str = "this build's key is derived from a value in its source, so anyone can \
                          compute it; it is not certified by an issuer";

/// A certificate an issuer signed for this role's key, as the listener
/// presents it.
///
/// Reachable only through [`issued`], which checks it, so one in hand is for
/// this role's own key and was valid when it arrived.
///
/// `Debug` prints the certificates, which are public, and the key only as the
/// TLS library prints one — its algorithm, never its bytes.
#[derive(Clone, Debug)]
pub struct Issued {
    certified: Arc<CertifiedKey>,
}

impl Issued {
    /// Whether this certificate answers for `name`, as a client would judge it.
    pub fn covers(&self, name: &str) -> bool {
        let (Some(leaf), Ok(name)) = (
            self.certified.cert.first(),
            ServerName::try_from(name.to_owned()),
        ) else {
            return false;
        };
        webpki::EndEntityCert::try_from(leaf)
            .is_ok_and(|leaf| leaf.verify_is_valid_for_subject_name(&name).is_ok())
    }
}

/// How far ahead of this guest's clock an issued certificate may begin.
///
/// An issuer dates a certificate by its own clock, which this guest's can
/// trail, and one pushed the moment it is issued would otherwise be refused as
/// not valid yet. A caller holds the dates to its own clock in any case.
const CLOCK_SKEW: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// `pems`, certificate chains an issuer signed, checked to be ones this role
/// can present, together, for every name in `served`, at `now`. None at all is
/// this role's own certificate and no issued one — and none at all is what a
/// key anyone can compute takes; see [`Identity::public`].
///
/// The one who pushes them is not trusted, and does not need to be. A chain
/// for another key is useless without that key, and is refused here rather
/// than presented; one that has lapsed would turn callers away, and is refused
/// too, as is a set that misses one of the names — a name is never served on
/// this role's self-signed certificate while issued ones are in use. A request
/// can be had for names before they are pushed, which is what makes that
/// possible — see `crate::config::push`. What is not checked is the issuer:
/// this role trusts no issuer and has no use for one — whether it is one a
/// browser accepts is the browser's to judge.
///
/// Which names a chain is for, the chain says, in its subject alternative
/// names, as a browser reads them. A name is answered with the first chain that
/// covers it, so a chain that answers for none — covering no served name, or
/// only names one before it covers — could never be presented, and is refused
/// as the mistake it is.
///
/// `now` is this guest's clock, which its host keeps. A host that moved it
/// could have a lapsed certificate taken or a good one refused, which is
/// availability, the host's to take anyway. A certificate may begin up to
/// [`CLOCK_SKEW`] ahead of it.
///
/// The reason for a refusal begins with the chain it is about, as `[1]: …`, or
/// with `: …` when it is about them all — for the sender to put the field's
/// name in front of.
pub fn issued(
    identity: &Identity,
    pems: &[String],
    served: &[String],
    now: std::time::SystemTime,
) -> Result<Vec<Issued>, String> {
    if identity.public() && !pems.is_empty() {
        return Err(format!(": {PUBLIC_KEY}"));
    }
    let chains = pems
        .iter()
        .enumerate()
        .map(|(i, pem)| one(identity, pem.as_bytes(), now).map_err(|e| format!("[{i}]: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    if chains.is_empty() {
        return Ok(chains);
    }

    // Which chain answers for each name: the first that covers it.
    let answering: Vec<Option<usize>> = served
        .iter()
        .map(|name| chains.iter().position(|chain| chain.covers(name)))
        .collect();
    if let Some(missing) = answering.iter().position(Option::is_none) {
        return Err(format!(": none of them covers {}", served[missing]));
    }
    if let Some(idle) = (0..chains.len()).find(|i| !answering.contains(&Some(*i))) {
        return Err(format!(
            "[{idle}]: answers for no name — it covers none of them, or only names a \
             certificate before it covers"
        ));
    }
    Ok(chains)
}

/// One chain, checked to be for this role's key and inside its validity.
fn one(identity: &Identity, pem: &[u8], now: std::time::SystemTime) -> Result<Issued, String> {
    let chain = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("not a PEM certificate chain: {e}"))?;
    let leaf = chain.first().ok_or("no certificate in it")?.clone();

    let certified = CertifiedKey::new(chain, identity.signer().clone());
    // A mismatch is the one error that says the key is wrong. Any other is a leaf
    // the TLS library could not read, for whichever key.
    certified.keys_match().map_err(|e| match e {
        TlsError::InconsistentKeys(InconsistentKeys::KeyMismatch) => {
            "the certificate is for another key than this role's".to_string()
        }
        e => format!("the certificate does not parse: {e}"),
    })?;

    let (_, parsed) = x509_parser::parse_x509_certificate(&leaf)
        .map_err(|e| format!("the certificate does not parse: {e}"))?;
    let seconds = now
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "this guest's clock is before 1970".to_string())?
        .as_secs();
    let at = x509_parser::time::ASN1Time::from_timestamp(seconds as i64)
        .map_err(|e| format!("this guest's clock: {e}"))?;
    let validity = parsed.validity();
    let begun = validity.not_before.timestamp() <= at.timestamp() + CLOCK_SKEW.as_secs() as i64;
    if !begun || validity.not_after < at {
        return Err(format!(
            "the certificate is valid from {} to {}, and it is {at} here",
            validity.not_before, validity.not_after
        ));
    }

    Ok(Issued {
        certified: Arc::new(certified),
    })
}

/// A serial number of its own for each certificate.
///
/// Left unset, the library derives one from the key — the same for every
/// certificate this key is ever minted into, since the key outlives every set
/// of names. A browser that has seen one certificate refuses another from the
/// same issuer under the same serial. Twenty bytes, the most a serial may be,
/// with the top bit clear so it reads as positive.
fn serial() -> rcgen::SerialNumber {
    let mut drawn = [0u8; 20];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut drawn)
        .expect("a guest that terminates TLS has a random source");
    drawn[0] &= 0x7f;
    rcgen::SerialNumber::from_slice(&drawn)
}

/// The serving key, loaded into the TLS library from its PKCS#8 bytes.
///
/// Borrowed rather than handed over, so the caller holds the only copy of the
/// bytes and can wipe it — see `crate::identity::key`. On the same provider as
/// [`provider`], whose own loader would take the bytes by value.
pub fn signer(pkcs8: &[u8]) -> Result<Arc<dyn SigningKey>, String> {
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8));
    tokio_rustls::rustls::crypto::ring::sign::any_ecdsa_type(&der)
        .map_err(|e| format!("the TLS library would not load the key: {e}"))
}

/// The crypto provider this role's TLS runs on, NAMED rather than inferred.
///
/// `ServerConfig::builder()` picks one from whichever rustls features happen to
/// be on, which makes the choice a property of the dependency graph instead of a
/// property of this build — and in an image whose output is a published digest,
/// that is the wrong place for it to live. The config that runs the handshake
/// is built on this; the key it signs with is loaded by [`signer`], through
/// the same backend's own module rather than this value, and the two are kept
/// on one backend by hand. `crates/ra-tls` pins the same provider the same way.
pub fn provider() -> CryptoProvider {
    tokio_rustls::rustls::crypto::ring::default_provider()
}

/// The certificate and key a handshake is answered with, in the form a
/// resolver hands one out.
///
/// A value rather than a finished config, because the names change with each
/// push while the acceptor stays up — see [`Certificate`]. The key stays in
/// this guest's memory and is never written anywhere, which is the property the
/// whole role rests on.
///
/// The key is the one [`Identity`] loaded at boot, handed to every certificate
/// after, so a push costs neither a fresh copy of it nor a load. rustls is
/// still asked whether the key is the one the certificate names — which
/// nothing else on this path checks.
pub fn certified<S: AsRef<str>>(
    identity: &Identity,
    public_names: &[S],
) -> Result<Arc<CertifiedKey>, String> {
    let cert = mint(identity, public_names)?;
    let certified = CertifiedKey::new(vec![cert.der().clone()], identity.signer().clone());
    certified
        .keys_match()
        .map_err(|e| format!("the serving key does not answer for this certificate: {e}"))?;
    Ok(Arc::new(certified))
}

impl Issued {
    /// The certificate as a handshake is answered with it.
    pub fn certified(&self) -> Arc<CertifiedKey> {
        self.certified.clone()
    }
}

/// What the listener presents: this role's own certificate, or the issued ones
/// in its place.
#[derive(Debug)]
pub enum Presented {
    /// Self-signed, over every name this role serves.
    Own(Arc<CertifiedKey>),
    /// Issued, together over every name this role serves — see [`issued`] —
    /// and settled per name when they are published, not per handshake.
    Issued {
        /// Each served name, in lower case, and the first certificate that
        /// covers it.
        answering: std::collections::HashMap<String, Arc<CertifiedKey>>,
        /// The first certificate, for a caller that named no served name.
        first: Arc<CertifiedKey>,
    },
}

impl Presented {
    /// `chains` in place of this role's own, for the names in `served`; this
    /// role's own if there are none.
    pub fn issued(own: Arc<CertifiedKey>, chains: &[Issued], served: &[String]) -> Presented {
        let Some(first) = chains.first() else {
            return Presented::Own(own);
        };
        let answering = served
            .iter()
            .filter_map(|name| {
                let chain = chains.iter().find(|chain| chain.covers(name))?;
                Some((name.to_ascii_lowercase(), chain.certified()))
            })
            .collect();
        Presented::Issued {
            answering,
            first: first.certified(),
        }
    }

    /// The certificate a caller that asked for `name` is answered with.
    ///
    /// Issued ones answer by the first that covers the name. A caller that
    /// named none, or one this role does not serve, gets the first of them: no
    /// certificate is right for it, and it is refused as misdirected once it
    /// asks for anything — see `crate::route`. rustls hands the name over in
    /// lower case.
    fn for_name(&self, name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        match self {
            Presented::Own(own) => Some(own.clone()),
            Presented::Issued { answering, first } => Some(
                name.and_then(|name| answering.get(name))
                    .unwrap_or(first)
                    .clone(),
            ),
        }
    }
}

/// What answers a handshake, following what the host last declared.
///
/// A resolver rather than a finished config, because the certificates change
/// whenever a push declares different names or carries others, while the
/// listener and everything under it stays up. Without one, either would mean
/// rebuilding the acceptor and everything holding it.
///
/// `None` before the first push: there are no names yet, so there is nothing to
/// answer with, and a handshake reaching this role is refused rather than
/// answered with something misleading.
#[derive(Debug)]
pub struct Certificate(watch::Receiver<Option<Arc<Presented>>>);

impl Certificate {
    pub fn following(presented: watch::Receiver<Option<Arc<Presented>>>) -> Certificate {
        Certificate(presented)
    }
}

impl ResolvesServerCert for Certificate {
    /// By the name the caller asked for, once there are issued certificates to
    /// choose among — see [`Presented::for_name`]. This role's own covers
    /// every name, and answers whatever was asked.
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let presented = self.0.borrow().clone()?;
        presented.for_name(hello.server_name())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Minting one at all is most of what this asserts. Everything here
    /// resolves at RUN time — the crypto provider, the key derivation, the
    /// self-signature, and rustls agreeing that the key signs for the
    /// certificate — so without a test the first evidence any of it works is a
    /// guest that panicked during boot, reported over a serial port.
    #[test]
    fn a_certificate_is_minted_over_the_names() {
        let identity = Identity::generated().unwrap();
        let held = certified(&identity, &["verify.example.com", "api.example.com"])
            .expect("a certificate is minted");
        assert_eq!(held.cert.len(), 1, "one certificate covers every name");
        // The bytes a quote binds. Empty, and the endpoint that serves the quote
        // would bind nothing while still looking like it proved something.
        assert!(!identity.spki().is_empty(), "the key's SPKI is there");
    }

    /// The certificate a caller validates carries exactly the bytes the quote
    /// binds.
    ///
    /// A caller ties this role's quote to its own channel by comparing the key
    /// it parses out of the certificate in front of it with the one the quote
    /// names. Were those bytes to differ, every quote served would check out on
    /// its own and fail against the very channel it is there to vouch for.
    #[test]
    fn the_certificate_carries_the_key_the_quote_binds() {
        let identity = Identity::generated().unwrap();
        let held = certified(&identity, &["verify.example.com"]).unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(&held.cert[0]).unwrap();
        assert_eq!(parsed.public_key().raw, identity.spki());
    }

    /// Nothing is answered before the first push: there are no names, so there
    /// is no certificate, and a handshake is refused rather than answered with
    /// something misleading.
    #[test]
    fn a_resolver_holds_nothing_until_a_certificate_is_published() {
        let (publish, following) = watch::channel(None);
        let resolver = Certificate::following(following);
        assert!(resolver.0.borrow().is_none());

        let identity = Identity::generated().unwrap();
        let own = certified(&identity, &["verify.example.com"]).unwrap();
        publish.send_replace(Some(Arc::new(Presented::Own(own))));
        assert!(resolver.0.borrow().is_some(), "and it follows the push");
    }

    /// An issuer's certificate, for a key it did not generate: what a test
    /// issuer hands back for a request. `from` and `to` bound its validity.
    pub(crate) fn issued_by(
        issuer: &(rcgen::Certificate, rcgen::KeyPair),
        key: &rcgen::KeyPair,
        names: &[&str],
        from: (i32, u8, u8),
        to: (i32, u8, u8),
    ) -> String {
        let mut params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        params.not_before = rcgen::date_time_ymd(from.0, from.1, from.2);
        params.not_after = rcgen::date_time_ymd(to.0, to.1, to.2);
        let leaf = params.signed_by(key, &issuer.0, &issuer.1).unwrap();
        format!("{}{}", leaf.pem(), issuer.0.pem())
    }

    /// A certificate for `key` that a TLS client refuses to read: it carries a
    /// critical extension nobody knows.
    fn unreadable(
        issuer: &(rcgen::Certificate, rcgen::KeyPair),
        key: &rcgen::KeyPair,
        names: &[&str],
    ) -> String {
        let mut params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        params.not_before = rcgen::date_time_ymd(FROM.0, FROM.1, FROM.2);
        params.not_after = rcgen::date_time_ymd(TO.0, TO.1, TO.2);
        let mut unknown =
            rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 99999, 1], vec![5, 0]);
        unknown.set_criticality(true);
        params.custom_extensions.push(unknown);
        params.signed_by(key, &issuer.0, &issuer.1).unwrap().pem()
    }

    /// A certificate authority of the tests' own.
    pub(crate) fn issuer() -> (rcgen::Certificate, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        (params.self_signed(&key).unwrap(), key)
    }

    /// Midway through the validity every good test certificate has.
    fn midway() -> std::time::SystemTime {
        let at = rcgen::date_time_ymd(2026, 6, 1).unix_timestamp();
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(at as u64)
    }

    const FROM: (i32, u8, u8) = (2026, 1, 1);
    const TO: (i32, u8, u8) = (2027, 1, 1);

    /// The names a request in DER asks to be certified for, sorted.
    pub(crate) fn requested_names(der: &[u8]) -> Vec<String> {
        use x509_parser::prelude::FromDer;

        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(der).unwrap();
        let mut names: Vec<String> = csr
            .requested_extensions()
            .into_iter()
            .flatten()
            .filter_map(|ext| match ext {
                x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => {
                    Some(san.general_names.iter().filter_map(|name| match name {
                        x509_parser::extensions::GeneralName::DNSName(dns) => Some(dns.to_string()),
                        _ => None,
                    }))
                }
                _ => None,
            })
            .flatten()
            .collect();
        names.sort();
        names
    }

    /// A request is for this role's own key, over exactly the names asked for.
    #[test]
    fn a_request_is_for_this_key_and_these_names() {
        use x509_parser::prelude::FromDer;

        let identity = Identity::generated().unwrap();
        let der = request(&identity, &["verify.example.com", "api.example.com"]).unwrap();
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&der).unwrap();
        assert_eq!(
            csr.certification_request_info.subject_pki.raw,
            identity.spki(),
            "the key the certificate would be for is this role's"
        );
        assert_eq!(
            requested_names(&der),
            ["api.example.com", "verify.example.com"]
        );
        assert_eq!(
            csr.certification_request_info.subject.iter().count(),
            0,
            "no subject, which an issuer would read as one more name"
        );

        assert!(request(&identity, &["not a name"]).is_err());
        assert!(request::<&str>(&identity, &[]).is_err());
    }

    const VERIFY: &str = "verify.example.com";
    const API: &str = "api.example.com";

    fn served() -> [String; 2] {
        [VERIFY.to_owned(), API.to_owned()]
    }

    /// Certificates an issuer signed for this key, inside their validity and
    /// together over every served name, are taken — one over all of them, or
    /// one each — and each covers exactly its names.
    #[test]
    fn issued_certificates_for_this_key_are_taken() {
        let identity = Identity::generated().unwrap();
        let ca = issuer();
        let both = issued_by(&ca, identity.key(), &[VERIFY, API], FROM, TO);
        let taken = issued(&identity, &[both], &served(), midway()).unwrap();
        assert_eq!(taken.len(), 1);
        assert!(taken[0].covers(VERIFY));
        assert!(
            taken[0].covers("API.example.com"),
            "a name is a name in any case"
        );
        assert!(!taken[0].covers("third.example.com"));

        let each = [
            issued_by(&ca, identity.key(), &[VERIFY], FROM, TO),
            issued_by(&ca, identity.key(), &[API], FROM, TO),
        ];
        let taken = issued(&identity, &each, &served(), midway()).unwrap();
        assert!(taken[0].covers(VERIFY) && !taken[0].covers(API));
        assert!(taken[1].covers(API) && !taken[1].covers(VERIFY));

        assert!(
            issued(&identity, &[], &served(), midway())
                .unwrap()
                .is_empty(),
            "none is this role's own"
        );
    }

    /// Everything a sender could push that this role must not present is
    /// refused, and says why — and which certificate it is about.
    #[test]
    fn a_certificate_this_role_could_not_present_is_refused() {
        let identity = Identity::generated().unwrap();
        let ca = issuer();
        let both = [VERIFY, API];
        let good = issued_by(&ca, identity.key(), &both, FROM, TO);

        let other = rcgen::KeyPair::generate().unwrap();
        for (pems, says) in [
            (
                vec![issued_by(&ca, &other, &both, FROM, TO)],
                "[0]: the certificate is for another key",
            ),
            (
                vec![
                    good.clone(),
                    issued_by(&ca, identity.key(), &both, (2026, 7, 1), TO),
                ],
                "[1]: the certificate is valid from",
            ),
            (
                vec![issued_by(&ca, identity.key(), &both, FROM, (2026, 5, 1))],
                "[0]: the certificate is valid from",
            ),
            (vec!["not a certificate".to_owned()], "[0]: no certificate"),
            (vec![String::new()], "[0]: no certificate"),
            (
                vec![unreadable(&ca, identity.key(), &both)],
                "[0]: the certificate does not parse",
            ),
            (
                vec![issued_by(&ca, identity.key(), &[VERIFY], FROM, TO)],
                ": none of them covers api.example.com",
            ),
            (
                vec![
                    good.clone(),
                    issued_by(&ca, identity.key(), &[API], FROM, TO),
                ],
                "[1]: answers for no name",
            ),
            (
                vec![
                    good.clone(),
                    issued_by(&ca, identity.key(), &["third.example.com"], FROM, TO),
                ],
                "[1]: answers for no name",
            ),
        ] {
            let refused = issued(&identity, &pems, &served(), midway())
                .err()
                .unwrap_or_else(|| panic!("took certificates that should say {says}"));
            assert!(refused.starts_with(says), "{says}: {refused}");
        }
    }

    /// Issued certificates answer by the name asked for: each the first that
    /// covers it, and the first of them for a caller that named none or one
    /// this role does not serve. This role's own answers everything.
    #[test]
    fn a_caller_is_answered_with_the_certificate_for_its_name() {
        let identity = Identity::generated().unwrap();
        let ca = issuer();
        let each = [
            issued_by(&ca, identity.key(), &[VERIFY], FROM, TO),
            issued_by(&ca, identity.key(), &[API], FROM, TO),
        ];
        let taken = issued(&identity, &each, &served(), midway()).unwrap();
        let (first, second) = (taken[0].certified(), taken[1].certified());
        let own = certified(&identity, &[VERIFY, API]).unwrap();

        // Served names as the push spelled them; rustls asks in lower case.
        let spelled = ["Verify.Example.com".to_owned(), API.to_owned()];
        let presented = Presented::issued(own.clone(), &taken, &spelled);
        let answered = |name| presented.for_name(name).unwrap();
        assert!(Arc::ptr_eq(&answered(Some(VERIFY)), &first));
        assert!(Arc::ptr_eq(&answered(Some(API)), &second));
        assert!(Arc::ptr_eq(&answered(None), &first));
        assert!(Arc::ptr_eq(&answered(Some("third.example.com")), &first));

        let presented = Presented::issued(own.clone(), &[], &spelled);
        assert!(Arc::ptr_eq(&presented.for_name(Some(API)).unwrap(), &own));
    }

    /// A key anyone can compute is not put forward for a certificate and takes
    /// none, though an issuer signed it for exactly that key; it serves on its
    /// own, self-signed one.
    #[cfg(not(feature = "sev-snp"))]
    #[test]
    fn a_public_key_neither_asks_for_nor_takes_a_certificate() {
        let identity = Identity::no_chip().unwrap();
        let refused = request(&identity, &[VERIFY]).unwrap_err();
        assert!(refused.contains("anyone can compute it"), "{refused}");

        let pem = issued_by(&issuer(), identity.key(), &[VERIFY, API], FROM, TO);
        let refused = issued(&identity, &[pem], &served(), midway()).unwrap_err();
        assert!(refused.starts_with(": this build's key"), "{refused}");

        assert!(
            issued(&identity, &[], &served(), midway())
                .unwrap()
                .is_empty()
        );
        certified(&identity, &[VERIFY, API]).expect("its own, self-signed");
    }

    /// A certificate that begins a little ahead of this guest's clock — as one
    /// does when it is pushed the moment its issuer dated it — is taken, and
    /// one that begins further ahead is not.
    #[test]
    fn a_certificate_may_begin_a_little_ahead_of_this_clock() {
        let identity = Identity::generated().unwrap();
        let pem = issued_by(&issuer(), identity.key(), &[VERIFY], (2026, 6, 1), TO);
        let before = |by: std::time::Duration| midway() - by;
        assert!(one(&identity, pem.as_bytes(), before(CLOCK_SKEW)).is_ok());
        let refused = one(
            &identity,
            pem.as_bytes(),
            before(CLOCK_SKEW + std::time::Duration::from_secs(1)),
        );
        assert!(refused.is_err_and(|e| e.contains("valid from")));
    }

    /// Each certificate has a serial of its own, though the key under all of
    /// them is one — or a browser that saw the first would refuse the next.
    #[test]
    fn each_certificate_has_a_serial_of_its_own() {
        let identity = Identity::generated().unwrap();
        let serial = |names: &[&str]| {
            let held = certified(&identity, names).unwrap();
            let (_, parsed) = x509_parser::parse_x509_certificate(&held.cert[0]).unwrap();
            parsed.raw_serial().to_vec()
        };
        let first = serial(&["verify.example.com"]);
        let next = serial(&["verify.example.com", "api.example.com"]);
        let again = serial(&["verify.example.com"]);
        assert_ne!(first, next);
        assert_ne!(first, again, "not even for the same names");
    }

    /// The names change with every push; the key does not. A caller holding a
    /// quote checks it against whatever certificate is in front of it, and that
    /// only works while the key underneath stays put.
    #[test]
    fn a_new_certificate_keeps_the_key() {
        let identity = Identity::generated().unwrap();
        let before = identity.spki().to_vec();
        certified(&identity, &["verify.example.com"]).unwrap();
        certified(&identity, &["api.example.com", "third.example.com"]).unwrap();
        assert_eq!(identity.spki(), before, "the key outlives the names");
    }

    /// The check that rcgen does not do. Written after discovering that
    /// `CertificateParams::new` accepts every one of these and mints a
    /// certificate carrying it, which is why the guard is ours rather than the
    /// library's.
    #[test]
    fn a_name_that_is_not_a_name_is_refused() {
        let identity = Identity::generated().unwrap();
        for bad in ["not a dns name", "", "exa mple.com", "hos t"] {
            assert!(
                certified(&identity, &[bad]).is_err(),
                "`{bad}` reached a certificate"
            );
        }
    }

    /// One bad name among good ones fails the whole certificate. A partial
    /// answer here would be a build serving some of the names the host declared
    /// and silently not the rest.
    #[test]
    fn one_bad_name_refuses_the_whole_certificate() {
        let identity = Identity::generated().unwrap();
        assert!(certified(&identity, &["verify.example.com", "not a name"]).is_err());
        assert!(certified::<&str>(&identity, &[]).is_err());
    }

    /// The boundary of the check, so nobody later mistakes it for a stricter one
    /// and writes a rule the certificate authority already owns. An underscore
    /// is a legal DNS label and passes here; whether a CA will ISSUE for such a
    /// name is that CA's policy, and second-guessing it from inside the guest
    /// would only be a different rule, wrong in a different place.
    #[test]
    fn the_check_is_dns_validity_and_not_issuance_policy() {
        let identity = Identity::generated().unwrap();
        assert!(certified(&identity, &["with_underscore.example.com"]).is_ok());
    }
}
