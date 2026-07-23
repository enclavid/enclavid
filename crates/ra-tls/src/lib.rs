//! Intra-fleet mutual **RA-TLS** — attested TLS for the orchestrator ↔ worker hops
//! (`api` ↔ `compile-worker` / `execution-worker`).
//!
//! Each side mints an EPHEMERAL self-signed TLS cert. Its
//! `SubjectPublicKeyInfo` (SPKI) is bound into an attestation [`Quote`]
//! (`report_data = ReportData::for_ratls(spki)`), and the quote is carried in a
//! custom X.509 extension on the cert. The rustls handshake runs a CUSTOM verifier
//! that, DURING the handshake, pulls the peer's quote out of its leaf cert, recomputes
//! the SPKI binding, and asks the [`Attestor`] to verify the quote (signature, binding,
//! measurement). So a completed TLS session PROVES the peer runs a pinned measurement
//! and owns the very TLS key it presented — no CA, no KMS, no post-handshake window.
//!
//! **Dev-bypass = the attestation backend, feature-gated.** Under `mock`/`snp-dev` the
//! full RA-TLS path (mint → handshake → verify → binding) runs on a box with no SEV-SNP
//! hardware — the dev bypass. Under `sev-snp` (prod) the dev backends are COMPILE-TIME
//! excluded, so no bypass code ships. The mock backend verifies against its OWN key, so
//! the whole dev fleet shares one baked dev keypair ([`default_attestor`]) to make mutual
//! verification actually succeed; prod uses real AMD attestation and needs no shared key.
//!
//! NOT here (deferred, the hard SNP tail): the real configfs-TSM extended-report read +
//! `sev` chain verify (needs hardware), the host vsock rendezvous relay, and
//! measurement-pin distribution.

use std::fmt;
use std::sync::Arc;

use enclavid_attestation::{Attestor, Quote, ReportData};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme,
};

/// Our private-arc OID for the attestation-quote X.509 extension. A closed system
/// (both ends ours), so this need not be an IANA-registered PEN — but it must be
/// UNIQUE and OUR OWN (never a third party's, so a foreign cert can't smuggle a quote
/// under an OID we'd honour). `58888` is a placeholder enterprise number; swap for a
/// registered PEN if these certs ever face outside tooling.
const RATLS_OID_ARCS: &[u64] = &[1, 3, 6, 1, 4, 1, 58888, 1, 1];
/// Dotted form for matching the parsed peer cert's extension OID.
const RATLS_OID_DOTTED: &str = "1.3.6.1.4.1.58888.1.1";

/// Server name presented on the client side. RA-TLS authenticates by ATTESTATION, not
/// by DNS name — our verifier ignores it — but rustls requires *some* name.
const RATLS_SERVER_NAME: &str = "ratls.enclavid.internal";

/// Fixed DEV keypair seed + measurement shared across the whole fleet under `mock`, so
/// each process's `MockAttestor` (which trusts its OWN key) accepts a peer's mock quote
/// and mutual RA-TLS actually completes. DEV-ONLY: compiled only under `mock`, never in
/// a `sev-snp` prod binary — it is a trust ANCHOR for local dev, not a production secret.
#[cfg(feature = "mock")]
const DEV_SEED: [u8; 32] = *b"enclavid-ra-tls-dev-seed-v1-!!!!";
#[cfg(feature = "mock")]
const DEV_MEASUREMENT: &str = "de7de7de7de7de7de7de7de7de7de7de7de7de7de7de7de7de7de7de7de7de7d";

/// What can go wrong minting or wiring an RA-TLS config (verify-time failures surface as
/// `rustls::Error` inside the handshake, not here).
#[derive(Debug)]
pub enum RaTlsError {
    /// Minting the ephemeral cert (rcgen) or serializing the quote failed.
    Cert(String),
    /// The attestation backend failed to mint a quote.
    Attest(String),
    /// Building the rustls config failed.
    Config(String),
}

impl fmt::Display for RaTlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RaTlsError::Cert(m) => write!(f, "ra-tls cert: {m}"),
            RaTlsError::Attest(m) => write!(f, "ra-tls attest: {m}"),
            RaTlsError::Config(m) => write!(f, "ra-tls config: {m}"),
        }
    }
}
impl std::error::Error for RaTlsError {}

/// Which measurements the verifier accepts. `Pinned` is the only prod-safe choice — the
/// point of attestation is to trust ONLY the platform releases you pin. `AcceptAny` runs
/// the full path but pins nothing; use it only in dev when the measurement is a stand-in.
#[derive(Clone, Debug)]
pub enum MeasurementPolicy {
    /// Accept any measurement (dev only — pins nothing).
    AcceptAny,
    /// Accept only these hex measurements.
    Pinned(Vec<String>),
}

impl MeasurementPolicy {
    fn check(&self, measurement: &str) -> Result<(), rustls::Error> {
        match self {
            MeasurementPolicy::AcceptAny => Ok(()),
            MeasurementPolicy::Pinned(allowed) if allowed.iter().any(|m| m == measurement) => Ok(()),
            MeasurementPolicy::Pinned(_) => Err(ratls_error(format!(
                "peer measurement {measurement} is not pinned"
            ))),
        }
    }
}

/// Build a `rustls::Error` for an RA-TLS verification failure (surfaces to the peer as a
/// TLS handshake abort).
fn ratls_error(msg: impl Into<String>) -> rustls::Error {
    rustls::Error::General(format!("ra-tls: {}", msg.into()))
}

/// Mint one ephemeral self-signed cert whose SPKI is bound into an attestation quote,
/// with the quote CBOR-embedded in the [`RATLS_OID_ARCS`] extension. Returns the cert +
/// its private key for a rustls config.
fn mint_cert(attestor: &dyn Attestor) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), RaTlsError> {
    let key_pair = rcgen::KeyPair::generate().map_err(|e| RaTlsError::Cert(e.to_string()))?;
    // The DER SubjectPublicKeyInfo the peer will parse out of the cert — the exact bytes
    // the quote binds. `verify_ratls_cert` recomputes the binding from the peer cert's
    // SPKI, so both ends MUST see identical bytes (they do: this is the cert's own SPKI).
    let spki_der = key_pair.public_key_der();
    let report_data = ReportData::for_ratls(spki_der);
    let quote = attestor
        .mint(&report_data)
        .map_err(|e| RaTlsError::Attest(e.to_string()))?;

    let mut quote_cbor = Vec::new();
    ciborium::into_writer(&quote, &mut quote_cbor)
        .map_err(|e| RaTlsError::Cert(format!("encode quote: {e}")))?;

    // No SANs / no CA — the cert is authenticated by the embedded quote, not by name.
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .map_err(|e| RaTlsError::Cert(e.to_string()))?;
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(RATLS_OID_ARCS, quote_cbor));
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| RaTlsError::Cert(e.to_string()))?;

    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    Ok((cert_der, key_der))
}

/// THE shared verify step (client verifying server, or server verifying client): parse
/// the peer's leaf cert, pull the quote from our extension, recompute the SPKI binding,
/// and have the attestor verify the quote + pin the measurement. Pure, synchronous —
/// runs INSIDE the rustls handshake (verify-DURING), so there is no unverified-peer window.
fn verify_ratls_cert(
    end_entity: &CertificateDer<'_>,
    attestor: &dyn Attestor,
    policy: &MeasurementPolicy,
) -> Result<(), rustls::Error> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(end_entity.as_ref())
        .map_err(|e| ratls_error(format!("parse peer cert: {e}")))?;

    // Pull OUR quote extension.
    let ext = cert
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == RATLS_OID_DOTTED)
        .ok_or_else(|| ratls_error("peer cert carries no attestation quote"))?;
    let quote: Quote = ciborium::from_reader(ext.value)
        .map_err(|e| ratls_error(format!("decode quote: {e}")))?;

    // Recompute the binding from THE PEER CERT'S OWN SPKI (raw DER of the
    // SubjectPublicKeyInfo) — the same bytes `mint_cert` fed to `for_ratls`.
    let spki_der = cert.public_key().raw.to_vec();
    let expected = ReportData::for_ratls(spki_der);

    attestor
        .verify(&quote, &expected)
        .map_err(|e| ratls_error(format!("quote verify failed: {e}")))?;
    policy.check(&quote.measurement)?;
    Ok(())
}

/// The custom rustls verifier — one type serving BOTH roles (a client verifying the
/// server, a server verifying the client), since the RA-TLS check is identical either
/// way. Holds the attestor + measurement policy + the crypto provider (for delegating
/// the ordinary TLS handshake-signature check to the peer's SPKI).
struct RaTlsVerifier {
    attestor: Arc<dyn Attestor>,
    policy: MeasurementPolicy,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for RaTlsVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `dyn Attestor` isn't Debug; rustls requires the verifier be Debug.
        f.debug_struct("RaTlsVerifier").field("policy", &self.policy).finish_non_exhaustive()
    }
}

impl RaTlsVerifier {
    fn verify_tls12_sig(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_sig(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

impl ServerCertVerifier for RaTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        verify_ratls_cert(end_entity, &*self.attestor, &self.policy)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_tls12_sig(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_tls13_sig(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes()
    }
}

impl ClientCertVerifier for RaTlsVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        verify_ratls_cert(end_entity, &*self.attestor, &self.policy)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_tls12_sig(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_tls13_sig(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes()
    }
}

fn ring_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A rustls [`ServerConfig`] for an RA-TLS server (worker): presents an ephemeral
/// attested cert and REQUIRES the client to present one it attests too (mutual).
pub fn server_config(
    attestor: Arc<dyn Attestor>,
    policy: MeasurementPolicy,
) -> Result<ServerConfig, RaTlsError> {
    let provider = ring_provider();
    let (cert, key) = mint_cert(&*attestor)?;
    let verifier = Arc::new(RaTlsVerifier { attestor, policy, provider: provider.clone() });
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| RaTlsError::Config(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)
        .map_err(|e| RaTlsError::Config(e.to_string()))
}

/// A rustls [`ClientConfig`] for an RA-TLS client (api): presents an ephemeral attested
/// cert (mutual) and verifies the server's by attestation.
pub fn client_config(
    attestor: Arc<dyn Attestor>,
    policy: MeasurementPolicy,
) -> Result<ClientConfig, RaTlsError> {
    let provider = ring_provider();
    let (cert, key) = mint_cert(&*attestor)?;
    let verifier = Arc::new(RaTlsVerifier { attestor, policy, provider: provider.clone() });
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| RaTlsError::Config(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert], key)
        .map_err(|e| RaTlsError::Config(e.to_string()))
}

/// The fixed rustls `ServerName` an RA-TLS client presents (ignored by our verifier).
pub fn server_name() -> ServerName<'static> {
    ServerName::try_from(RATLS_SERVER_NAME).expect("static RA-TLS server name is valid")
}

/// The feature-selected attestation backend for the fleet. Under `mock` this is a FIXED
/// dev keypair shared fleet-wide so mutual RA-TLS verifies; prod (`sev-snp`) mints/verifies
/// against real AMD attestation.
#[cfg(feature = "mock")]
pub fn default_attestor() -> Arc<dyn Attestor> {
    Arc::new(enclavid_attestation::MockAttestor::from_seed(DEV_SEED, DEV_MEASUREMENT))
}

/// The feature-selected measurement policy. Under `mock`, pin the shared dev measurement
/// so the pin path is exercised end-to-end on a dev box.
#[cfg(feature = "mock")]
pub fn default_policy() -> MeasurementPolicy {
    MeasurementPolicy::Pinned(vec![DEV_MEASUREMENT.to_string()])
}

/// Fleet RA-TLS server config from the feature-selected backend + policy — the one call
/// a worker's listener makes.
#[cfg(feature = "mock")]
pub fn fleet_server_config() -> Result<ServerConfig, RaTlsError> {
    server_config(default_attestor(), default_policy())
}

/// Fleet RA-TLS client config from the feature-selected backend + policy — the one call
/// the api's dial-out makes.
#[cfg(feature = "mock")]
pub fn fleet_client_config() -> Result<ClientConfig, RaTlsError> {
    client_config(default_attestor(), default_policy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclavid_attestation::MockAttestor;

    /// Minting a cert and parsing it back yields the SAME SPKI bytes on both ends (the
    /// report_data binding footgun) AND a mock quote that verifies against that SPKI.
    #[test]
    fn mint_binds_spki_and_verifies() {
        let attestor: Arc<dyn Attestor> = Arc::new(MockAttestor::from_seed([5u8; 32], "0".repeat(64)));
        let (cert, _key) = mint_cert(&*attestor).unwrap();
        // The shared verify path accepts the freshly minted cert.
        verify_ratls_cert(&cert, &*attestor, &MeasurementPolicy::AcceptAny).unwrap();
    }

    /// A quote minted for a DIFFERENT SPKI must not verify against this cert (a host
    /// swapping the quote onto another key is rejected at the binding check).
    #[test]
    fn swapped_quote_rejected() {
        let attestor: Arc<dyn Attestor> = Arc::new(MockAttestor::from_seed([6u8; 32], "0".repeat(64)));
        let (cert_a, _) = mint_cert(&*attestor).unwrap();
        let (cert_b, _) = mint_cert(&*attestor).unwrap();
        // Graft cert_a's extension (its quote, bound to A's SPKI) onto cert_b's bytes by
        // verifying cert_a's quote against cert_b's SPKI — must fail the binding.
        use x509_parser::prelude::*;
        let (_, a) = X509Certificate::from_der(cert_a.as_ref()).unwrap();
        let ext = a
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == RATLS_OID_DOTTED)
            .unwrap();
        let quote: Quote = ciborium::from_reader(ext.value).unwrap();
        let (_, b) = X509Certificate::from_der(cert_b.as_ref()).unwrap();
        let wrong = ReportData::for_ratls(b.public_key().raw.to_vec());
        assert!(attestor.verify(&quote, &wrong).is_err(), "quote must not verify vs another SPKI");
    }

    /// A measurement not in the pin set is rejected.
    #[test]
    fn unpinned_measurement_rejected() {
        let attestor: Arc<dyn Attestor> = Arc::new(MockAttestor::from_seed([7u8; 32], "aa".repeat(32)));
        let (cert, _) = mint_cert(&*attestor).unwrap();
        let policy = MeasurementPolicy::Pinned(vec!["bb".repeat(32)]);
        assert!(verify_ratls_cert(&cert, &*attestor, &policy).is_err());
    }
}
