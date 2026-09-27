//! What the public listener presents, and how it keeps up with the pushed names.
//!
//! ## Why a resolver holds it rather than a finished config
//!
//! The key is this guest's own and never leaves its memory — see
//! `crate::identity::key`. The certificate over it is minted per set of names,
//! and the names change whenever the host pushes a different table. A finished
//! config would have to be rebuilt for each of those, and everything holding it
//! rebuilt with it; a resolver reads the current one per handshake, so the
//! listener and every connection on it stay up while the answer underneath
//! changes.
//!
//! ## And nothing is answered before the first push
//!
//! The resolver holds `None` until there are names to mint over, and a
//! handshake reaching this role then fails rather than being answered with
//! something misleading. That is the honest state: this role serves names, and
//! before a push it has none.
//!
//! ## Its own certificate, or issued ones in its place
//!
//! This role's own certificate is self-signed, and a browser refuses it. Ones
//! an issuer signed over the same key arrive in a push — see
//! `crate::config::push` — together covering every name it pushes, and are
//! presented in place of this role's own for as long as the pushes carry them,
//! each for the names it covers. Its own comes back when they stop. A caller
//! that checks this role's quote is served by any of them, since the quote
//! binds the KEY, which they all share.

use std::sync::Arc;

use safe_logger::debug;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::sign::CertifiedKey;

use crate::identity::tls::{self, Issued, Presented};
use crate::upstream::Upstreams;

/// Follow the table and the issued certificates, and keep what the listener
/// presents.
///
/// Await this on the role's own task: a role that stopped following would keep
/// presenting a certificate for names the host no longer declares.
pub async fn follow(
    mut table: watch::Receiver<Arc<Upstreams>>,
    mut issued: watch::Receiver<Vec<Issued>>,
    identity: Arc<crate::identity::key::Identity>,
    publish: watch::Sender<Option<Arc<Presented>>>,
) -> ! {
    let mut names: Vec<String> = Vec::new();
    let mut own: Option<Arc<CertifiedKey>> = None;
    loop {
        // Changed rather than every loop: minting is the expensive part and the
        // names usually did not move.
        let declared = table.borrow().served().to_vec();
        if declared != names {
            match tls::certified(&identity, &declared) {
                Ok(certificate) => {
                    names = declared;
                    own = Some(certificate);
                    debug!("serving {} name(s)", names.len());
                }
                // The push that declared these passed a stricter check than the
                // one minting makes, so this is not a caller's mistake to answer
                // — it is this role failing to act on something it accepted.
                // What was being served keeps being served.
                Err(e) => debug!("the declared names have no certificate: {e}"),
            }
        }
        // Again whenever either moved. The issued certificates, while a push
        // carries some, cover every name that push declared between them — or
        // the push was refused — so they stand in for this role's own on all.
        if let Some(own) = &own {
            let presented = Presented::issued(own.clone(), &issued.borrow(), &names);
            publish.send_replace(Some(Arc::new(presented)));
        }
        // Issued certificates that can no longer arrive leave the table to
        // follow; a table that can no longer change leaves nothing. Both
        // senders live as long as the process, so neither ends while anything
        // is still serving.
        let ended = tokio::select! {
            changed = table.changed() => changed.is_err(),
            Ok(()) = issued.changed() => false,
        };
        if ended {
            std::future::pending::<()>().await;
        }
    }
}

/// What answers a handshake: this role's key, through the resolver that follows
/// the pushed names.
///
/// One config for the life of the process. The certificate inside it changes;
/// the config does not, which is the whole reason a resolver is used rather than
/// a finished certificate.
///
/// On [`tls::provider`], the backend the certificate's key was loaded by — see
/// [`tls::signer`].
///
/// TLS 1.2 as well as 1.3, because a consumer's own servers may speak nothing
/// newer, and a caller that speaks 1.3 cannot be pushed down to 1.2 — the
/// library marks a downgrade in what it signs, and such a caller refuses it.
/// What 1.2 costs is a session id sent in the clear, which lets the host tell
/// one 1.2 client's connections apart from another's. That is accepted: only
/// such servers speak 1.2, and the host knows where they are anyway.
pub fn acceptor(certificate: watch::Receiver<Option<Arc<Presented>>>) -> TlsAcceptor {
    let mut config = ServerConfig::builder_with_provider(Arc::new(tls::provider()))
        .with_safe_default_protocol_versions()
        .expect("ring offers the default protocol versions")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(tls::Certificate::following(certificate)));
    // Both offered: a browser takes h2, and a diagnostic client on the far side
    // of a byte splice is likely to speak http/1.1.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}
