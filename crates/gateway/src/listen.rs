//! The public door: one TLS session per caller, terminated here, and the proxy
//! that carries what comes out of it.
//!
//! ## Why the accept loop is this role's own
//!
//! The proxy library listens on TCP and unix sockets. This guest has neither —
//! a measured kernel with no network modules leaves vsock as the only way in,
//! and that is the property the whole design rests on. So the loop is ours, and
//! what the library is handed is an established connection.
//!
//! ## The handshake decides the name, once
//!
//! A group serves each name at a different address, so which name a connection
//! asked for decides which address its requests go to. It is settled here,
//! before a byte of HTTP is read, and travels no further than the door it
//! selects. What a name MEANS to whatever serves it is not known here and is not
//! needed.
//!
//! ## And it decides the protocol, so nothing has to guess
//!
//! A connection this role decrypted carries no record of what it negotiated,
//! so a proxy handed one can only guess at HTTP/2 by looking for its opening
//! bytes — and a well-formed HTTP/1.1 request shorter than that opening would
//! then hang, waiting for bytes the caller has no reason to send. This role
//! does not have to guess: it performed the negotiation. So it picks the path
//! itself, and both protocols are offered to the caller rather than one being
//! dropped to make the guessing safe.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use pingora_core::apps::{HttpServerApp, HttpServerOptions, ServerApp};
use pingora_core::protocols::http::ServerSession;
use pingora_core::protocols::l4::virt::{VirtualSockOpt, VirtualSocket};
use pingora_core::server::configuration::ServerConf;
use pingora_proxy::HttpProxy;
use safe_logger::debug;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use crate::proxy::Hop;
use crate::upstream::Upstreams;
use crate::{attest, tls};

/// How long the TLS handshake may take. Without it a caller that connects and
/// says nothing holds a slot for as long as it likes.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// What the caller decrypted, on its way to the proxy.
///
/// The proxy's own stream types are a kernel socket or nothing, and a TLS
/// session is neither. This is the door it leaves open for exactly that, and it
/// is only good enough on THIS side: a connection reaching api goes through
/// `crate::leg` instead, because that one is pooled and a pooled connection
/// needs a descriptor.
#[derive(Debug)]
struct Decrypted<S>(S);

impl<S> AsyncRead for Decrypted<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for Decrypted<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S> VirtualSocket for Decrypted<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + std::fmt::Debug,
{
    /// Nothing to set: what these options tune is a kernel socket, and the one
    /// under this session belongs to the host's splice, not to this session.
    fn set_socket_option(&self, _opt: VirtualSockOpt) -> std::io::Result<()> {
        Ok(())
    }
}

/// What it takes to answer a public connection, as of one push.
///
/// Both halves come from the names the host declared, so both are rebuilt when
/// it declares different ones — a certificate over the new names, and a door
/// for each of them. Neither is rebuilt per connection.
///
/// There is none of this before the first push: a role with no names has no
/// certificate to present, and a connection reaching it is dropped rather than
/// answered with something misleading.
pub struct Public {
    acceptor: TlsAcceptor,
    doors: Doors,
}

/// Follow the table, and publish what serving it takes.
///
/// Await this on the role's own task: a role that stopped following would keep
/// presenting a certificate for names the host no longer declares, and keep
/// routing through doors built for a table that is gone.
pub async fn follow(
    mut table: watch::Receiver<Arc<Upstreams>>,
    identity: Arc<crate::key::Identity>,
    proof: attest::Proof,
    conf: Arc<ServerConf>,
    publish: watch::Sender<Option<Arc<Public>>>,
) -> ! {
    let mut names: Vec<String> = Vec::new();
    loop {
        // Changed rather than every loop: the certificate is the expensive part
        // and the names usually did not move.
        let declared = table.borrow().served().to_vec();
        if declared != names {
            match tls::server_config(&identity, &declared) {
                Ok(config) => {
                    names = declared;
                    let public = Public {
                        acceptor: TlsAcceptor::from(Arc::new(config)),
                        doors: Doors::new(table.clone(), proof.clone(), conf.clone()),
                    };
                    publish.send_replace(Some(Arc::new(public)));
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

/// The proxies this role runs: one per name it answers to, plus one for
/// everything else.
///
/// They are shared by every caller, and so are the legs they pool — see
/// `crate::proxy` for why that is safe and why a proxy per caller is not
/// affordable.
struct Doors {
    served: HashMap<String, Arc<HttpProxy<Hop>>>,
    elsewhere: Arc<HttpProxy<Hop>>,
}

impl Doors {
    fn new(
        table: watch::Receiver<Arc<Upstreams>>,
        proof: attest::Proof,
        conf: Arc<ServerConf>,
    ) -> Doors {
        // One ledger for the whole role, because one pool of legs is what it
        // describes. See `crate::leg::Ledger`.
        let ledger = Arc::new(crate::leg::Ledger::default());
        let door = |name: Option<String>| {
            let mut proxy = HttpProxy::new(
                Hop::new(name, table.clone(), proof.clone(), ledger.clone()),
                conf.clone(),
            );
            // The proxy would otherwise look for HTTP/2's opening bytes on a
            // connection it cannot ask about — see the module docs. This says
            // that a connection reaching it in plain HTTP/2 is expected, and
            // `connection` is what decides that it is one.
            let mut options = HttpServerOptions::default();
            options.h2c = true;
            proxy.server_options = Some(options);
            proxy.handle_init_modules();
            Arc::new(proxy)
        };
        let served = table
            .borrow()
            .served()
            .iter()
            .map(|name| (name.to_lowercase(), door(Some(name.clone()))))
            .collect();
        Doors {
            served,
            elsewhere: door(None),
        }
    }

    /// The door for the name the handshake settled, or the one that says this
    /// is not the server for it. Matched without regard to case, because a host
    /// name has none.
    fn of(&self, name: Option<&str>) -> &Arc<HttpProxy<Hop>> {
        name.and_then(|name| self.served.get(&name.to_lowercase()))
            .unwrap_or(&self.elsewhere)
    }
}

/// Serve one public connection, from the handshake to the last answer.
pub async fn connection(public: Arc<Public>, stream: fleet_transport::Stream, peer: String) {
    let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, public.acceptor.accept(stream)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            debug!("handshake with {peer} failed: {e}");
            return;
        }
        Err(_) => {
            debug!("handshake with {peer} did not finish within the timeout");
            return;
        }
    };

    // Both answers of the handshake, taken before the session is moved: which
    // name this caller asked for, and which protocol it agreed to speak.
    let (name, over_h2) = {
        let (_, session) = tls.get_ref();
        (
            session.server_name().map(str::to_owned),
            session.alpn_protocol() == Some(tls::H2),
        )
    };

    let proxy = public.doors.of(name.as_deref());

    let stream: pingora_core::protocols::Stream =
        Box::new(pingora_core::protocols::l4::stream::Stream::from(
            pingora_core::protocols::l4::virt::VirtualSocketStream::new(Box::new(Decrypted(tls))),
        ));

    let (_shutdown, watcher) = watch::channel(false);
    if over_h2 {
        // Its own accept loop for the streams of this connection.
        proxy.process_new(stream, &watcher).await;
    } else {
        // Straight to the one-request-at-a-time path, with nothing peeked.
        proxy
            .process_new_http(ServerSession::new_http1(stream), &watcher)
            .await;
    }
}

/// End to end over loopback: real TLS, a real public connection, an api
/// stand-in behind. TCP arm only, because the listeners here are TCP.
#[cfg(all(test, not(feature = "vsock")))]
mod tests {
    use super::*;

    use std::convert::Infallible;

    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty, Full};
    use hyper::client::conn::http2::SendRequest;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::crypto::CryptoProvider;
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::{self, DigitallySignedStruct, SignatureScheme};

    use crate::affinity;
    use crate::proxy::MEASUREMENT;
    use crate::upstream::tests::{A, FIRST, SECOND, pushed};

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

    /// This role on a loopback listener, with `api` as the one group declared
    /// under both names. Returns its address and the SPKI its quote binds.
    async fn gateway(api: &str) -> (String, Vec<u8>) {
        let listener = fleet_transport::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let identity = Arc::new(crate::key::Identity::generated().unwrap());
        let spki = identity.spki().to_vec();
        let proof = attest::proof(spki.clone(), &crate::identity::attestor()).unwrap();

        let table = Upstreams::empty().replaced(&pushed(&format!(
            r#"{{
              "groups": {{ "{GROUP}": {{ "measurement": "{A}" }} }},
              "names": {{
                "{FIRST}": {{ "{GROUP}": ["{api}"] }},
                "{SECOND}":  {{ "{GROUP}": ["{api}"] }} }},
              "affinity": {{ "key": "{}", "ttl_seconds": 600 }} }}"#,
            "0".repeat(64)
        )));
        let (pushes, current) = watch::channel(Arc::new(table));
        let (serving, public) = watch::channel(None);
        tokio::spawn(async move {
            // Held so the table outlives the follower, as it does in the role.
            let _pushes = pushes;
            follow(
                current,
                identity,
                proof,
                Arc::new(ServerConf::default()),
                serving,
            )
            .await
        });

        // Nothing is served until the names have a certificate.
        tokio::time::timeout(Duration::from_secs(5), async {
            while public.borrow().is_none() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the first table is acted on");

        tokio::spawn(async move {
            fleet_transport::accept_forever(listener, move |stream, peer| {
                let public = public.borrow().clone();
                async move {
                    if let Some(public) = public {
                        tokio::spawn(connection(public, stream, peer));
                    }
                }
            })
            .await
        });
        (addr, spki)
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
    async fn caller(gateway: &str, name: &str, window: u32) -> SendRequest<Empty<Bytes>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];

        let tcp = tokio::net::TcpStream::connect(gateway).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(name.to_owned()).unwrap(), tcp)
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
        let (gateway, _) = gateway(&api().await).await;
        let mut caller = caller(&gateway, FIRST, 4 << 20).await;

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
        let (gateway, _) = gateway(&api().await).await;
        let mut caller = caller(&gateway, FIRST, 4 << 20).await;

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
        let (gateway, _) = gateway(&api().await).await;
        let mut second = caller(&gateway, SECOND, 4 << 20).await;

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

    /// A build nobody runs is the same answer as an upstream that would not
    /// talk, and two measurements are refused rather than resolved to whichever
    /// came first.
    #[tokio::test]
    async fn a_build_nobody_runs_and_a_build_named_twice() {
        let (gateway, _) = gateway(&api().await).await;
        let mut second = caller(&gateway, SECOND, 4 << 20).await;

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

    /// A name this role does not answer to is told so, rather than dropped or
    /// served something misleading.
    #[tokio::test]
    async fn a_name_this_role_does_not_serve_is_misdirected() {
        let (gateway, _) = gateway(&api().await).await;
        let mut stranger = caller(&gateway, "elsewhere.example.com", 4 << 20).await;
        let answer = ask(
            &mut stranger,
            Request::get("https://elsewhere.example.com/")
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
        let (gateway, spki) = gateway(&api().await).await;
        let mut caller = caller(&gateway, FIRST, 4 << 20).await;

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
        let (gateway, _) = gateway(&api().await).await;

        let mut attacker = caller(&gateway, FIRST, 65_535).await;
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

        let mut victim = caller(&gateway, FIRST, 4 << 20).await;
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
