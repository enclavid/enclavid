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
//! ## Self-signed, and what that does and does not mean
//!
//! The key is generated at boot and never leaves this guest's encrypted memory,
//! which is the property worth having and is already true here. What is missing
//! is a signature a browser's store accepts, so a browser refuses this
//! certificate. That makes the current build servable by a tool and not by a
//! person.

use std::sync::Arc;

use tokio::sync::watch;
use tokio_rustls::rustls::pki_types::{DnsName, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;

use crate::key::Identity;

/// The certificate over these names, self-signed by this role's key.
fn mint<S: AsRef<str>>(
    identity: &Identity,
    public_names: &[S],
) -> Result<rcgen::Certificate, String> {
    if public_names.is_empty() {
        return Err("a serving certificate needs at least one name".into());
    }

    // Checked HERE, because rcgen does not check it. `CertificateParams::new`
    // accepts any string and writes it into a SAN verbatim, so a mistyped name
    // yields a perfectly well-formed certificate no client will ever match —
    // and this role would serve, report itself healthy, and be unreachable.
    // `crate::config` refuses one at the push as well, which is where it can
    // still be told to the sender; this is the check that cannot be skipped.
    let mut names = Vec::with_capacity(public_names.len());
    for public_name in public_names {
        let public_name = public_name.as_ref();
        let name = DnsName::try_from(public_name.to_owned())
            .map_err(|_| format!("`{public_name}` is not a DNS name"))?;
        names.push(name.as_ref().to_string());
    }

    // The names are the whole of the subject. There is no CA and no extension:
    // everything this certificate says is "the holder of this key answers for
    // these names", which is the only claim a browser knows how to check.
    let params =
        rcgen::CertificateParams::new(names).map_err(|e| format!("certificate parameters: {e}"))?;
    params
        .self_signed(identity.key())
        .map_err(|e| format!("self-sign: {e}"))
}

/// The serving key, in the form rustls takes one.
fn private(identity: &Identity) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key().serialize_der()))
}

/// The certificate and key a handshake is answered with, in the form the
/// proxy library's TLS layer asks for one.
///
/// The same certificate `server_config` builds — what differs is who holds it.
/// The library terminates the handshake, so the key has to reach it as a value
/// rather than as a finished config: it stays in this guest's memory and is
/// never written anywhere, which is the property the whole role rests on.
pub fn certified<S: AsRef<str>>(
    identity: &Identity,
    public_names: &[S],
) -> Result<Arc<CertifiedKey>, String> {
    let cert = mint(identity, public_names)?;
    let signing = tokio_rustls::rustls::crypto::ring::sign::any_supported_type(&private(identity))
        .map_err(|e| format!("the derived key signs nothing rustls offers: {e}"))?;
    Ok(Arc::new(CertifiedKey::new(
        vec![cert.der().clone()],
        signing,
    )))
}

/// What answers a handshake, following what the host last declared.
///
/// A resolver rather than a finished config, because the certificate changes
/// whenever a push declares different names while the listener and everything
/// under it stays up. Without one, a new name would mean rebuilding the
/// acceptor and everything holding it.
///
/// `None` before the first push: there are no names yet, so there is nothing to
/// answer with, and a handshake reaching this role is refused rather than
/// answered with something misleading.
#[derive(Debug)]
pub struct Certificate(watch::Receiver<Option<Arc<CertifiedKey>>>);

impl Certificate {
    pub fn following(names: watch::Receiver<Option<Arc<CertifiedKey>>>) -> Certificate {
        Certificate(names)
    }
}

impl ResolvesServerCert for Certificate {
    /// The `ClientHello` is not consulted. One certificate covers every name
    /// this role answers for, so there is nothing for a resolver to choose —
    /// what it is here for is that the answer may CHANGE, not that it varies by
    /// caller.
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.borrow().clone()
    }
}

#[cfg(test)]
mod tests {
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

    /// Nothing is answered before the first push: there are no names, so there
    /// is no certificate, and a handshake is refused rather than answered with
    /// something misleading.
    #[test]
    fn a_resolver_holds_nothing_until_a_certificate_is_published() {
        let (publish, following) = watch::channel(None);
        let resolver = Certificate::following(following);
        assert!(resolver.0.borrow().is_none());

        let identity = Identity::generated().unwrap();
        publish.send_replace(Some(certified(&identity, &["verify.example.com"]).unwrap()));
        assert!(resolver.0.borrow().is_some(), "and it follows the push");
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
