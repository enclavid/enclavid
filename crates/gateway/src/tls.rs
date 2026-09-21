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

use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{DnsName, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Offered ALPN protocols, most preferred first.
///
/// Both, rather than h2 alone. A browser will take h2 and the negotiation costs
/// nothing, but `http/1.1` is what a diagnostic client on the other side of a
/// byte splice is likely to speak, and refusing it would make the first thing
/// anyone tries fail at the handshake with nothing to read.
const ALPN: [&[u8]; 2] = [H2, b"http/1.1"];

/// What the handshake settles on when the caller speaks HTTP/2, which is what
/// `crate::listen` compares against to pick a path without guessing.
pub const H2: &[u8] = b"h2";

use crate::key::Identity;

/// Build the rustls config this role serves `public_names` with.
///
/// One certificate covering every name, rather than one per name behind a
/// resolver. This role answers for all of them and there is nothing for a
/// resolver to decide — a `ClientHello`-driven resolver added before there is a
/// choice to make is machinery whose only effect would be a place for a wrong
/// answer.
///
/// Called again whenever the names change, which is whenever the host pushes a
/// table declaring a different set. The key does not change with them.
pub fn server_config<S: AsRef<str>>(
    identity: &Identity,
    public_names: &[S],
) -> Result<ServerConfig, String> {
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
    let cert = params
        .self_signed(identity.key())
        .map_err(|e| format!("self-sign: {e}"))?;

    // The provider is named rather than resolved from crate features.
    // `builder()` would call `get_default_or_install_from_crate_features`, which
    // decides at RUN time and panics if the graph offers both backends — a boot
    // failure in a guest for a question the source can simply answer.
    // `crates/ra-tls` pins it the same way.
    let provider = std::sync::Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("protocol versions: {e}"))?
        // No client certificate is asked for, and that is a decision rather than
        // a default. The peer is a browser, or a tool on the far side of a host
        // that carried the connection in without opening it; neither can present
        // an attestation, so demanding one would refuse every real caller. Who
        // the caller IS is settled further in, by credentials travelling inside
        // the session, not by this handshake.
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key().serialize_der())),
        )
        .map_err(|e| format!("build the server config: {e}"))?;
    config.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Building the config at all is most of what this asserts. Everything here
    /// resolves at RUN time — the crypto provider, the key generation, the
    /// self-signature, the certificate/key agreement rustls checks in
    /// `with_single_cert` — so without a test the first evidence any of it works
    /// is a guest that panicked during boot, reported over a serial port.
    #[test]
    fn a_config_is_built_and_offers_both_protocols() {
        let identity = Identity::generated().unwrap();
        let config = server_config(&identity, &["verify.example.com", "api.example.com"])
            .expect("a config is built");
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        // The bytes a quote binds. Empty, and the endpoint that serves the quote
        // would bind nothing while still looking like it proved something.
        assert!(!identity.spki().is_empty(), "the key's SPKI is there");
    }

    /// The names change with every push; the key does not. A caller holding a
    /// quote checks it against whatever certificate is in front of it, and that
    /// only works while the key underneath stays put.
    #[test]
    fn a_new_certificate_keeps_the_key() {
        let identity = Identity::generated().unwrap();
        let before = identity.spki().to_vec();
        server_config(&identity, &["verify.example.com"]).unwrap();
        server_config(&identity, &["api.example.com", "third.example.com"]).unwrap();
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
                server_config(&identity, &[bad]).is_err(),
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
        assert!(server_config(&identity, &["verify.example.com", "not a name"]).is_err());
        assert!(server_config::<&str>(&identity, &[]).is_err());
    }

    /// The boundary of the check, so nobody later mistakes it for a stricter one
    /// and writes a rule the certificate authority already owns. An underscore
    /// is a legal DNS label and passes here; whether a CA will ISSUE for such a
    /// name is that CA's policy, and second-guessing it from inside the guest
    /// would only be a different rule, wrong in a different place.
    #[test]
    fn the_check_is_dns_validity_and_not_issuance_policy() {
        let identity = Identity::generated().unwrap();
        assert!(server_config(&identity, &["with_underscore.example.com"]).is_ok());
    }
}
