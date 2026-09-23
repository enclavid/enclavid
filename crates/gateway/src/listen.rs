//! The public door: the certificate it presents, and the name it remembers.
//!
//! ## The accept loop is not here any more
//!
//! It was, and it was the root of everything else this role used to own. The
//! proxy library listens on TCP or a unix socket and nothing else — its
//! `ServerAddress` is a closed choice, with no trait to implement for a third —
//! and this guest is reached over vsock. So the loop was ours, and from that
//! followed our own TLS termination, our own stream wrapper, and our own
//! supervision.
//!
//! `crate::bridge` ends that: it carries the fleet transport to a unix socket in
//! this guest, and the library listens on that. What is left here is the two
//! things the library asks of us.
//!
//! ## What the certificate is, and why a resolver holds it
//!
//! The key is this guest's own and never leaves its memory — see `crate::key`.
//! It reaches the library as a value rather than a path, through a resolver
//! that follows the pushed names: a table declaring different names replaces
//! the certificate under a listener that stays up, with nothing rebuilt around
//! it. See [`follow`].
//!
//! ## And why the name is remembered rather than read from the request
//!
//! Routing needs the name the caller AGREED to, not the one it claims. A
//! request carries a `Host` a caller writes; the handshake settled an SNI it
//! cannot change afterwards, and it is the one the certificate answered for.
//! Reading `Host` instead would let a caller reach an address it never
//! negotiated for.
//!
//! The library has a place for exactly this: what
//! [`TlsAccept::handshake_complete_callback`] returns is kept on the
//! connection's TLS digest, where `crate::proxy` reads it per request.

use std::any::Any;
use std::sync::Arc;

use pingora_core::listeners::tls::TlsSettings;
use pingora_core::listeners::{Listeners, ServerAddress, TlsAccept};
use pingora_core::protocols::tls::TlsRef;
use pingora_core::server::configuration::ServerConf;
use pingora_core::services::listening::Service;
use pingora_proxy::HttpProxy;
use safe_logger::debug;
use tokio::sync::watch;
use tokio_rustls::rustls::sign::CertifiedKey;

use crate::proxy::Hop;
use crate::tls;
use crate::upstream::Upstreams;

/// The name a connection settled at its handshake.
///
/// A newtype rather than a bare `String`, because what carries it is keyed by
/// type: anything else ever kept there as a `String` would take its place.
pub struct Name(pub String);

/// Keeps the settled name on the connection, and does nothing else.
struct Remember;

#[async_trait::async_trait]
impl TlsAccept for Remember {
    /// A connection with no name asked for keeps none, and `crate::proxy`
    /// answers such a request as misdirected — this role serves names, and a
    /// caller that named none has not reached one.
    async fn handshake_complete_callback(
        &self,
        ssl: &TlsRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        let name = ssl.server_name()?;
        Some(Arc::new(Name(name.to_owned())) as Arc<dyn Any + Send + Sync>)
    }
}

/// Follow the table, and keep the certificate the listener answers with.
///
/// Await this on the role's own task: a role that stopped following would keep
/// presenting a certificate for names the host no longer declares.
///
/// Nothing is served before the first push — the resolver holds `None` and a
/// handshake is refused, which is the honest answer when there are no names to
/// answer for.
pub async fn follow(
    mut table: watch::Receiver<Arc<Upstreams>>,
    identity: Arc<crate::key::Identity>,
    publish: watch::Sender<Option<Arc<CertifiedKey>>>,
) -> ! {
    let mut names: Vec<String> = Vec::new();
    loop {
        // Changed rather than every loop: minting is the expensive part and the
        // names usually did not move.
        let declared = table.borrow().served().to_vec();
        if declared != names {
            match tls::certified(&identity, &declared) {
                Ok(certificate) => {
                    names = declared;
                    publish.send_replace(Some(certificate));
                    debug!("serving {} name(s)", names.len());
                }
                // The push that declared these passed the same check, so this
                // is not a caller's mistake to answer — it is this role failing
                // to act on something it accepted. What was being served keeps
                // being served.
                Err(e) => debug!("the declared names have no certificate: {e}"),
            }
        }
        if table.changed().await.is_err() {
            // The sender lives as long as the process, so this cannot happen
            // while anything is still serving.
            std::future::pending::<()>().await;
        }
    }
}

/// The public service: one listener, the TLS that terminates on it, and the
/// proxy that carries what comes out.
///
/// Built by hand rather than through `http_proxy_service`, because that helper
/// keeps its listeners private and offers TLS only over TCP. A unix socket with
/// TLS is expressible, just not through the shortcut.
pub fn service(
    at: &std::path::Path,
    conf: &Arc<ServerConf>,
    hop: Hop,
    certificate: watch::Receiver<Option<Arc<CertifiedKey>>>,
) -> Service<HttpProxy<Hop>> {
    let mut tls =
        TlsSettings::with_callbacks(Box::new(Remember)).expect("the TLS settings take a callback");
    tls.set_cert_resolver(Arc::new(tls::Certificate::following(certificate)));
    // Both protocols offered, as before: a browser takes h2, and a diagnostic
    // client on the far side of a byte splice is likely to speak http/1.1.
    tls.enable_h2();

    let mut listeners = Listeners::new();
    listeners.add_endpoint(
        ServerAddress::Uds(at.to_string_lossy().into_owned(), None),
        Some(tls),
    );

    let mut proxy = HttpProxy::new(hop, conf.clone());
    proxy.handle_init_modules();
    Service::with_listeners("public".to_owned(), listeners, proxy)
}

/// End to end over a real socket: the library's listener, the library's TLS on
/// a certificate this role minted, and an api stand-in behind. TCP arm only,
/// because the leg to the stand-in is TCP here.
#[cfg(all(test, not(feature = "vsock")))]
mod tests {
    use super::*;

    use std::convert::Infallible;
    use std::time::Duration;

    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty, Full};
    use hyper::client::conn::http2::SendRequest;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use pingora_core::services::Service as _;
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::crypto::CryptoProvider;
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::{self, DigitallySignedStruct, SignatureScheme};

    use crate::affinity;
    use crate::attest;
    use crate::proxy::MEASUREMENT;
    use crate::upstream::tests::{A, B, FIRST, SECOND, pushed};

    const GROUP: &str = "one";
    const BODY: usize = 1 << 20;

    /// An api stand-in: HTTP/2 by prior knowledge, answering with `BODY` bytes
    /// and saying in a header which path it was asked for — which is how a test
    /// sees whether the label was taken out on the way through.
    async fn api() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        |req: Request<hyper::body::Incoming>| async move {
                            let asked = req.uri().path().to_owned();
                            let mut answer =
                                Response::new(Full::new(Bytes::from(vec![b'x'; BODY])));
                            answer
                                .headers_mut()
                                .insert("x-asked-for", asked.parse().unwrap());
                            // Said back so a test can prove what stopped here.
                            for header in [MEASUREMENT, affinity::TOKEN_HEADER] {
                                if req.headers().contains_key(header) {
                                    answer
                                        .headers_mut()
                                        .insert("x-arrived-with", header.parse().unwrap());
                                }
                            }
                            Ok::<_, Infallible>(answer)
                        },
                    );
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        addr
    }

    /// What one group running `build` at `api` looks like as a push, under both
    /// names.
    fn table(api: &str, build: &str) -> String {
        format!(
            r#"{{
              "groups": {{ "{GROUP}": {{ "measurement": "{build}" }} }},
              "names": {{
                "{FIRST}": {{ "{GROUP}": ["{api}"] }},
                "{SECOND}":  {{ "{GROUP}": ["{api}"] }} }},
              "affinity": {{ "key": "{}", "ttl_seconds": 600 }} }}"#,
            "0".repeat(64)
        )
    }

    /// This role on a unix socket of its own, with `api` as the one group
    /// declared under both names. Returns the socket, the SPKI its quote binds,
    /// and the sender a test pushes a later table through.
    async fn gateway(api: &str) -> (std::path::PathBuf, Vec<u8>, watch::Sender<Arc<Upstreams>>) {
        let at = std::env::temp_dir().join(format!(
            "gateway-test-{}-{:?}.sock",
            std::process::id(),
            std::thread::current().id()
        ));
        let at = crate::bridge::prepare(at.to_str().unwrap());

        let identity = Arc::new(crate::key::Identity::generated().unwrap());
        let spki = identity.spki().to_vec();
        let proof = attest::proof(spki.clone(), &crate::identity::attestor()).unwrap();

        let first = Upstreams::empty().replaced(&pushed(&table(api, A))).await;
        let (pushes, current) = watch::channel(Arc::new(first));

        let (certificate, presented) = watch::channel(None);
        tokio::spawn(follow(current.clone(), identity, certificate));

        let hop = Hop::new(
            current.clone(),
            proof,
            Arc::new(crate::leg::Ledger::default()),
        );
        let mut public = service(
            &at,
            &Arc::new(ServerConf::default()),
            hop,
            presented.clone(),
        );
        let (never, stop) = watch::channel(false);
        tokio::spawn(async move {
            let _never = never;
            public.start_service(None, stop, 1).await
        });

        // Nothing is answered until there is a certificate and a bound socket.
        tokio::time::timeout(Duration::from_secs(5), async {
            while presented.borrow().is_none() || !at.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the first table is acted on");

        (at, spki, pushes)
    }

    /// Accepts any certificate: what is under test is how this role carries
    /// requests, not its identity.
    #[derive(Debug)]
    struct AnyCertificate(Arc<CryptoProvider>);

    impl ServerCertVerifier for AnyCertificate {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// One public HTTP/2 connection to a name, receiving with the given window.
    ///
    /// Straight to the socket the library listens on: what the bridge does in
    /// front of it is a byte splice, and splicing bytes is not what these tests
    /// are about.
    async fn caller(at: &std::path::Path, name: &str, window: u32) -> SendRequest<Empty<Bytes>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];

        let socket = tokio::net::UnixStream::connect(at).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(name.to_owned()).unwrap(), socket)
            .await
            .unwrap();
        let (sender, driver) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .initial_stream_window_size(window)
            .initial_connection_window_size(window)
            .handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(driver);
        sender
    }

    async fn ask(
        caller: &mut SendRequest<Empty<Bytes>>,
        request: Request<Empty<Bytes>>,
    ) -> Response<hyper::body::Incoming> {
        caller.ready().await.unwrap();
        caller.send_request(request).await.unwrap()
    }

    /// The label travels in the path, is taken out on the way through, and api
    /// sees the path it published.
    #[tokio::test]
    async fn a_marked_label_routes_and_is_taken_out() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut caller = caller(&at, FIRST, 4 << 20).await;

        let answer = ask(
            &mut caller,
            Request::get(format!("https://{FIRST}/-{GROUP}/api/v1/sessions/7/status"))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(answer.status(), StatusCode::OK);
        assert_eq!(answer.headers()["x-asked-for"], "/api/v1/sessions/7/status");
    }

    /// A path with no label is not a link this role wrote, and a label nobody
    /// carries is the same answer as an upstream that would not talk.
    #[tokio::test]
    async fn a_path_without_a_label_and_a_label_nobody_has() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut caller = caller(&at, FIRST, 4 << 20).await;

        let bare = ask(
            &mut caller,
            Request::get(format!("https://{FIRST}/api/v1/sessions/7/status"))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(bare.status(), StatusCode::BAD_REQUEST);

        let elsewhere = ask(
            &mut caller,
            Request::get(format!("https://{FIRST}/-somewhere/"))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(elsewhere.status(), StatusCode::BAD_GATEWAY);
    }

    /// A caller naming a build is placed, told where, and comes back there with
    /// the token rather than with a group of its choosing.
    #[tokio::test]
    async fn a_caller_is_placed_and_comes_back_with_a_token() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut second = caller(&at, SECOND, 4 << 20).await;

        let placed = ask(
            &mut second,
            Request::get(format!("https://{SECOND}/api/v1/sessions"))
                .header(MEASUREMENT, A)
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(placed.status(), StatusCode::OK);
        assert_eq!(placed.headers()[affinity::GROUP_HEADER], GROUP);
        assert!(
            !placed.headers().contains_key("x-arrived-with"),
            "what this hop reads stops at this hop"
        );
        let token = placed.headers()[affinity::TOKEN_HEADER].clone();

        // Coming back with it needs no measurement: the token says where.
        let again = ask(
            &mut second,
            Request::get(format!("https://{SECOND}/api/v1/sessions/1"))
                .header(affinity::TOKEN_HEADER, &token)
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(again.status(), StatusCode::OK);
        assert_eq!(again.headers()[affinity::GROUP_HEADER], GROUP);

        // With neither there is nothing to place on and nothing to return to.
        let naked = ask(
            &mut second,
            Request::get(format!("https://{SECOND}/api/v1/sessions"))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(naked.status(), StatusCode::BAD_REQUEST);
    }

    /// A token binds the BUILD, not only the label — so a host re-declaring
    /// that label cannot move a caller onto something it never named.
    #[tokio::test]
    async fn a_token_does_not_survive_the_group_being_re_declared() {
        let api = api().await;
        let (at, _, pushes) = gateway(&api).await;
        let mut caller = caller(&at, SECOND, 4 << 20).await;

        let placed = ask(
            &mut caller,
            Request::get(format!("https://{SECOND}/api/v1/sessions"))
                .header(MEASUREMENT, A)
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(placed.status(), StatusCode::OK);
        let token = placed.headers()[affinity::TOKEN_HEADER].clone();

        // The host says the same label runs something else now.
        let next = Upstreams::empty().replaced(&pushed(&table(&api, B))).await;
        pushes.send_replace(Arc::new(next));

        let stale = ask(
            &mut caller,
            Request::get(format!("https://{SECOND}/api/v1/sessions"))
                .header(affinity::TOKEN_HEADER, &token)
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(
            stale.status(),
            StatusCode::BAD_REQUEST,
            "a stale token is absent, and the caller is asked to name what it needs"
        );
    }

    /// A build nobody runs is the same answer as an upstream that would not
    /// talk, and two measurements are refused rather than resolved to whichever
    /// came first.
    #[tokio::test]
    async fn a_build_nobody_runs_and_a_build_named_twice() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut second = caller(&at, SECOND, 4 << 20).await;

        let nobody = ask(
            &mut second,
            Request::get(format!("https://{SECOND}/api/v1/sessions"))
                .header(MEASUREMENT, "c".repeat(96))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(nobody.status(), StatusCode::BAD_GATEWAY);

        let twice = ask(
            &mut second,
            Request::get(format!("https://{SECOND}/api/v1/sessions"))
                .header(MEASUREMENT, A)
                .header(MEASUREMENT, A)
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(twice.status(), StatusCode::BAD_REQUEST);
    }

    /// A name this role does not answer to is told so — and the name is the one
    /// the HANDSHAKE settled, which is what makes routing by it worth anything.
    #[tokio::test]
    async fn a_name_this_role_does_not_serve_is_misdirected() {
        let (at, _, _pushes) = gateway(&api().await).await;
        let mut stranger = caller(&at, "elsewhere.example.com", 4 << 20).await;
        let answer = ask(
            &mut stranger,
            Request::get("https://elsewhere.example.com/")
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(answer.status(), StatusCode::MISDIRECTED_REQUEST);
    }

    /// And a caller that agreed to one name cannot reach another by asking for
    /// it in the request. The `Host` is the caller's to write; the name that
    /// routes is the one it negotiated a certificate for.
    #[tokio::test]
    async fn the_host_header_does_not_choose_the_name() {
        let (at, _, _pushes) = gateway(&api().await).await;
        // Negotiated for a name this role does not serve, then claims one it
        // does. If `Host` were what routed, this would be answered.
        let mut liar = caller(&at, "elsewhere.example.com", 4 << 20).await;
        let answer = ask(
            &mut liar,
            Request::get(format!("https://{FIRST}/-{GROUP}/"))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(answer.status(), StatusCode::MISDIRECTED_REQUEST);
    }

    /// The quote this role serves binds the key it is serving over, and is
    /// answered without an api behind it or a build named.
    #[tokio::test]
    async fn the_attestation_binds_the_serving_key() {
        let (at, spki, _pushes) = gateway(&api().await).await;
        let mut caller = caller(&at, FIRST, 4 << 20).await;

        let answer = ask(
            &mut caller,
            Request::get(format!("https://{FIRST}{}", attest::PATH))
                .body(Empty::new())
                .unwrap(),
        )
        .await;
        assert_eq!(answer.status(), StatusCode::OK);
        assert_eq!(
            answer.headers()[hyper::header::CONTENT_TYPE],
            attest::CONTENT_TYPE
        );

        let body = answer.into_body().collect().await.unwrap().to_bytes();
        let quote: enclavid_attestation::Quote = ciborium::from_reader(body.as_ref()).unwrap();
        crate::identity::attestor()
            .verify(
                &quote,
                &enclavid_attestation::ReportData::for_ratls(spki.clone()),
            )
            .expect("the quote binds the key this role serves over");

        // And a quote bound to some OTHER key does not pass the same check,
        // which is what makes the assertion above worth making.
        let other = crate::key::Identity::generated().unwrap();
        assert!(
            crate::identity::attestor()
                .verify(
                    &quote,
                    &enclavid_attestation::ReportData::for_ratls(other.spki().to_vec())
                )
                .is_err()
        );
    }

    /// A caller that stops reading must not stall anyone else.
    ///
    /// It opens eight streams and reads none of their bodies, each leaving up
    /// to `BODY` bytes of api's answer unread behind this role. A leg carries
    /// one request at a time, so what it holds up is eight legs and nothing
    /// else; another caller's request takes a leg of its own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_caller_that_stops_reading_does_not_stall_another() {
        let (at, _, _pushes) = gateway(&api().await).await;

        let mut attacker = caller(&at, FIRST, 65_535).await;
        let mut unread = Vec::new();
        for _ in 0..8 {
            let answer = ask(
                &mut attacker,
                Request::get(format!("https://{FIRST}/-{GROUP}/"))
                    .body(Empty::new())
                    .unwrap(),
            )
            .await;
            assert_eq!(answer.status(), StatusCode::OK);
            unread.push(answer);
        }

        let mut victim = caller(&at, FIRST, 4 << 20).await;
        let body = tokio::time::timeout(Duration::from_secs(10), async {
            let answer = ask(
                &mut victim,
                Request::get(format!("https://{FIRST}/-{GROUP}/"))
                    .body(Empty::new())
                    .unwrap(),
            )
            .await;
            answer.into_body().collect().await.unwrap().to_bytes()
        })
        .await
        .expect("an answer must not wait on a caller that stopped reading");
        assert_eq!(body.len(), BODY);
        drop(unread);
    }
}
