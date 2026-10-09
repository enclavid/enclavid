//! The COMPILE boundary: fuse + compile a policy + its pinned plugins into a
//! cwasm and its metadata. api NEVER compiles in-process — it always drives a
//! compile-worker over rpc, so the api binary links NO Cranelift.
//!
//! [`Compiler`] wraps the `engine_rpc::CompilerService` client. The worker is a
//! separate CVM, brought up at boot rather than by api.
//! api [`connect`](connect_compile_worker)s to it at a configured address, under
//! mutual RA-TLS; the transport is TCP by default and vsock under that feature.
//! The components stream to the worker beside the call, and the cwasm streams
//! back beside the reply: api passes it on — to the execution-worker and to L2,
//! see [`crate::tee`] — as it arrives, never holds it whole, and never
//! deserializes it. The live `Component` is materialized only on the
//! execution-worker.

use bytes::Bytes;
use futures::stream::BoxStream;

use enclavid_boundary::{Asserted, AuthN, AuthZ, Covert, Exposed, Untrusted, reason};
use engine_rpc::{
    COMPILE_STREAM_DEADLINE, COMPILE_STREAM_IDLE, CompileError, CompileReply, CompileSource,
    CompilerLeg, MAX_BUNDLE_META_BYTES,
};
use fleet_stream::{Incoming, StreamError};
use fleet_transport::LegFailure;
use safe_logger::debug;

/// The COMPILE boundary: a client for a compile-worker's `engine_rpc::CompilerService`.
/// Given already-pulled artifact bytes (the orchestrator owns the OCI pull +
/// registry auth), the worker fuses + Cranelift-compiles + parses sections into
/// a [`Compiled`]. The client is a cheap remoc handle (`Send + Sync`);
/// concurrent `/connect` compiles multiplex over the one connection.
/// How api judges the compile hop's answers — see [`Compiler::compile`].
pub type CompileScope = (Asserted,);

/// What is still open on a value api is about to release to the compile-worker.
///
/// Its own alias rather than hatch-client's: that facade is the TEE↔host wire
/// perimeter, and a scope is a property of the CHANNEL, so this leg names its own.
type ToCompiler<T> = Exposed<T, (AuthN, AuthZ, Covert)>;

/// Mint one compile's inputs as a fully-vouched request — the only way artifacts
/// reach a compile-worker.
///
/// Specific to this value rather than a generic "anything crossing" mint, on the
/// `outbound_session_id` precedent: the audited answers live in one place (grep
/// `outbound_compile_request(`) instead of being restated at each call, where they
/// would be the same three sentences forever.
fn outbound_compile_request(source: CompileSource) -> Exposed<CompileSource, ()> {
    let open: ToCompiler<CompileSource> = Exposed::new(source);
    open.vouch_unchecked::<AuthN, _>(reason!(
        "identified: this leg dials ONE compile-time-pinned measurement, and the \
         handshake fails before a byte moves if the peer is not it"
    ))
    .vouch_unchecked::<AuthZ, _>(reason!(
        "no-secret: the consumer's own artifacts, going to the code that exists to \
         compile them; the recipient is handed nothing it is not being asked to read"
    ))
    .vouch_unchecked::<Covert, _>(reason!(
        "already-held: the HOST performed the OCI pull that produced these bytes, so \
         their length is a quantity it measured itself"
    ))
}

pub struct Compiler {
    leg: std::sync::Arc<crate::fleet::Leg<std::sync::Arc<CompilerLeg<CompileScope>>>>,
}

/// What a compile gives back: the metadata, encoded as the execute hop streams
/// it, and the cwasm — its length and digest, and its pieces as they arrive,
/// held to both. A cwasm that is not what it was named ends its pieces in an
/// error where it would have ended, so a reader passing them on abandons rather
/// than finishes.
pub struct Compiled {
    pub meta: Vec<u8>,
    pub cwasm_len: u64,
    pub cwasm_sha256: [u8; 32],
    pub cwasm: BoxStream<'static, Result<Bytes, StreamError>>,
}

impl Compiler {
    pub fn new(
        leg: std::sync::Arc<crate::fleet::Leg<std::sync::Arc<CompilerLeg<CompileScope>>>>,
    ) -> Self {
        Self { leg }
    }

    /// Compile the components `source` streams on the worker. A transport
    /// failure, or a leg that is down, surfaces as `CompileError::Failed`; the
    /// worker's own answer, `Refused` included, comes back as it was sent.
    pub async fn compile(&self, source: CompileSource) -> Result<Compiled, CompileError> {
        let client = self.leg.get().ok_or_else(|| {
            debug!("compile: the compile-worker leg is down");
            CompileError::Failed
        })?;
        let reply: Untrusted<CompileReply, CompileScope> =
            client.compile(outbound_compile_request(source)).await?;
        // CONTAINED, and the honest form of it: there is NO check available here.
        //
        // Read the axis carefully, because the obvious reading is the wrong one.
        // This is not about the peer having been substituted — that is `AuthN`, and
        // it IS closed: mutual RA-TLS against one compile-time-pinned measurement.
        // An unsubstituted, correctly-measured compiler still PICKS this value. Its
        // content is whatever Cranelift produced running over the CONSUMER's wasm,
        // so the adversary-supplied input on this leg is that wasm, not the peer,
        // and a toolchain escape it provokes survives a perfect pin with the
        // handshake succeeding throughout.
        //
        // What bounds a wrong bundle is all downstream: the executor files it in
        // api's own caller partition and deserializes it in a disposable per-round
        // child. NOT the L2 seal's AAD — api performs that seal, so it binds the
        // bytes to the slot they were filed under, never to the question that was
        // asked. It is a tamper-evident bag: proof nobody opened it afterwards, and
        // no evidence at all about what went in.
        let CompileReply { meta, cwasm, body } = reply
            .trust_unchecked::<Asserted, _>(reason!(
                "NO KIND FITS — an accepted risk, not a discharge. Not re-derived \
                 (this side carries no Cranelift), not bound (a digest the compiler \
                 also chose is its word twice), not bounded (the range is arbitrary \
                 native code), not contained (the audience is the executor, which \
                 did not author it). Carried because no check exists and the fleet \
                 needs a compiler; what limits the damage is downstream containment"
            ))
            .into_inner();
        // What the execute hop takes, held here where api would otherwise pass on
        // what no worker accepts.
        if meta.len() as u64 > MAX_BUNDLE_META_BYTES {
            debug!("compile: the metadata is past its bound");
            return Err(CompileError::Failed);
        }
        // The digest is the compiler's word too; it is held to it all the same,
        // so that what this side passes on is at least what the compiler named.
        let pieces = Incoming::open(body, cwasm.length(), COMPILE_STREAM_IDLE)
            .await
            .map_err(|e| {
                debug!("compile: the cwasm's stream: {e}");
                CompileError::Failed
            })?
            .into_pieces(COMPILE_STREAM_DEADLINE, Some(cwasm.sha256()));
        Ok(Compiled {
            meta,
            cwasm_len: cwasm.length(),
            cwasm_sha256: cwasm.sha256(),
            cwasm: pieces,
        })
    }
}

/// Connect to a compile-worker already listening at `addr` and hand back the leg.
/// The worker is brought up at boot, not by api. The dial is mutual RA-TLS — TCP by
/// default, vsock under that feature — and `engine_rpc::connect_compiler` takes the
/// attested stream from there, keeping the generated client this side cannot name.
/// `leg` is this end of the connection.
pub async fn connect_compile_worker(
    addr: &str,
    attestor: std::sync::Arc<dyn enclavid_attestation::Attestor>,
    leg: engine_rpc::LegSettings,
) -> Result<
    (
        std::sync::Arc<CompilerLeg<CompileScope>>,
        tokio::task::JoinHandle<()>,
    ),
    LegFailure,
> {
    let stream = fleet_transport::dial(addr).await.map_err(|e| {
        debug!("connect {addr}: {e}");
        LegFailure::Connect(e.kind())
    })?;
    // Mutual RA-TLS over the dial (same as the execution-worker): attest the peer's
    // pinned measurement + present our own attested cert.
    let config =
        crate::endorsement::fleet_client_config(attestor, crate::health::Peer::CompileWorker)
            .map_err(|e| {
                debug!("ra-tls: {e}");
                LegFailure::Mint
            })?;
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let tls = connector
        .connect(enclavid_ra_tls::server_name(), stream)
        .await
        .map_err(|e| {
            debug!("ra-tls: {e}");
            // A peer that attested to the wrong image is the failure this fleet
            // is most likely to see, and the one `Attest` said least about.
            match enclavid_ra_tls::pin_mismatch(&e)
                .and_then(|p| fleet_transport::Measurement::parse(&p.presented))
            {
                Some(m) => LegFailure::Pin(m),
                None => LegFailure::Attest,
            }
        })?;
    let (read, write) = tokio::io::split(tls);

    // Everything above this line is WHO — the dial, the pins, what a refusal means.
    // Everything below is WHAT MAY CROSS, and that belongs to engine-rpc: it brings
    // the hop up and keeps the generated client, which api has no name for.
    let (leg, driver) = engine_rpc::connect_compiler(read, write, &leg)
        .await
        .map_err(|e| {
            debug!("compile leg: {e}");
            match e {
                engine_rpc::LegError::Rpc => LegFailure::Rpc,
                engine_rpc::LegError::Clients | engine_rpc::LegError::Serve => LegFailure::Clients,
                engine_rpc::LegError::Closed => LegFailure::Closed,
            }
        })?;

    Ok((std::sync::Arc::new(leg), driver))
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclavid_boundary::AuthN;
    use engine_rpc::CompileRequest;
    use fleet_stream::{BlobHeader, bin};
    use futures::StreamExt;

    // A minimal in-process server, so the Compiler client's rpc plumbing is
    // exercised without a real worker (the transport factory
    // `connect_compile_worker` is the thin, hand-reviewed piece).
    //
    // It implements the UNTRUSTED view because that is the only implementable
    // shape: engine-rpc exports no raw server, so a test cannot serve this
    // contract by a route production code could not take either.
    //
    // Its cwasm is the policy's length and the plugin count; for the policy
    // `lie` it names one cwasm and sends another.
    struct MockService;

    impl engine_rpc::CompilerServiceUntrusted for MockService {
        type Scope = (AuthN,);

        async fn compile(
            &self,
            req: Untrusted<CompileRequest, Self::Scope>,
        ) -> Result<CompileReply, CompileError> {
            let (policy, plugins) = req
                .trust_unchecked::<AuthN, _>(reason!("test fixture"))
                .into_inner()
                .receive()
                .await
                .map_err(|_| CompileError::Failed)?;
            if policy == b"boom" {
                return Err(CompileError::Refused);
            }
            let cwasm = vec![policy.len() as u8, plugins.len() as u8];
            let header = BlobHeader::of(&cwasm).unwrap();
            let sent = if policy == b"lie" { vec![9, 9] } else { cwasm };
            let (tx, body) = bin::channel();
            tokio::spawn(fleet_stream::send(tx, sent));
            Ok(CompileReply {
                meta: b"meta".to_vec(),
                cwasm: header,
                body,
            })
        }
    }

    async fn read(compiled: Compiled) -> Vec<Result<Bytes, StreamError>> {
        compiled.cwasm.collect().await
    }

    fn whole(
        policy: &[u8],
        plugins: Vec<engine_types::composition::PluginInstance>,
    ) -> CompileSource {
        CompileSource::whole(policy.to_vec(), plugins).unwrap()
    }

    /// The Compiler client drives a CompilerService over an in-memory remoc
    /// duplex: args cross, the cwasm streams back, and the error path
    /// propagates.
    #[tokio::test]
    async fn compiler_round_trips() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (a_r, a_w) = tokio::io::split(a);
        let (b_r, b_w) = tokio::io::split(b);

        // Worker end: serve the mock through the contract's own serve half.
        let settings = engine_rpc::LegSettings::default();
        let server = tokio::spawn(async move {
            let _ = engine_rpc::serve_compiler(
                a_r,
                a_w,
                MockService,
                engine_rpc::DEFAULT_REQUEST_BUFFER,
                &settings,
            )
            .await;
        });

        // Orchestrator end: take the leg, wrap in Compiler.
        let (leg_client, _driver) =
            engine_rpc::connect_compiler::<CompileScope, _, _>(b_r, b_w, &settings)
                .await
                .expect("connect");
        let client = std::sync::Arc::new(leg_client);
        let leg = crate::fleet::Leg::new();
        leg.set(Some(client.clone()));
        let compiler = Compiler::new(leg.clone());

        let plugins = vec![engine_types::composition::PluginInstance {
            package: "p".into(),
            wasm: vec![0],
        }];
        let compiled = compiler.compile(whole(b"hello", plugins)).await.unwrap();
        assert_eq!(compiled.meta, b"meta");
        assert_eq!(compiled.cwasm_len, 2);
        assert_eq!(read(compiled).await, vec![Ok(Bytes::from_static(&[5, 1]))]);

        // A cwasm that is not the one it was named ends in an error, never in a
        // quiet end a reader passing it on would finish on.
        let compiled = compiler.compile(whole(b"lie", vec![])).await.unwrap();
        assert_eq!(read(compiled).await.last(), Some(&Err(StreamError::Digest)));

        // A down leg fails the call rather than waiting: how long to wait for a
        // peer is the host's decision, and the health port is already telling it.
        leg.set(None);
        // `Compiled` is deliberately not `Debug` (it holds a stream), so match the
        // outcome rather than unwrapping it.
        match compiler.compile(whole(b"hello", vec![])).await {
            Err(e) => assert_eq!(e, CompileError::Failed),
            Ok(_) => panic!("a call on a down leg must fail"),
        }
        leg.set(Some(client));

        let err = match compiler.compile(whole(b"boom", vec![])).await {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(
            err,
            CompileError::Refused,
            "the worker's answer crosses as itself"
        );

        server.abort();
    }
}
