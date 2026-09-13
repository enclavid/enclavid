//! The COMPILE boundary: fuse + compile a policy + its pinned plugins into a
//! [`CompiledBundle`]. api NEVER compiles in-process — it always drives a
//! compile-worker over rpc, so the api binary links NO Cranelift.
//!
//! [`Compiler`] wraps the `engine_rpc::CompilerService` client. The worker is a
//! separate CVM, brought up at boot rather than by api.
//! api [`connect`](connect_compile_worker)s to it at a configured address, under
//! mutual RA-TLS; the transport is TCP by default and vsock under that feature. The orchestrator holds the returned cwasm as BYTES via
//! [`bundle_to_entry`] and never deserializes it — the live `Component` is
//! materialized only on the execution-worker (the compile→execute seam is
//! bytes-in, bytes-out both ends).
//!
//! The [`CompiledBundle`] wire type lives in the `engine-rpc` crate (it is the compile
//! RPC return value, the L2 cache bundle — see [`crate::cwasm_cache`] — AND what
//! api hands the worker on `run_with_bundle`) so a cold compile and an L2 hit
//! resolve the same bundle the worker deserializes.

use enclavid_boundary::{Asserted, AuthN, AuthZ, Covert, Exposed, Untrusted, reason};
use engine_rpc::{CompileError, CompileRequest, CompiledBundle, CompilerLeg};
use engine_types::composition::PluginInstance;
use fleet_transport::LegFailure;
use safe_logger::debug;

/// The COMPILE boundary: a client for a compile-worker's `engine_rpc::CompilerService`.
/// Given already-pulled artifact bytes (the orchestrator owns the OCI pull +
/// registry auth), the worker fuses + Cranelift-compiles + parses sections into
/// a [`CompiledBundle`]. The client is a cheap remoc handle (`Send + Sync`);
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
fn outbound_compile_request(
    policy: Vec<u8>,
    plugins: Vec<PluginInstance>,
) -> Exposed<CompileRequest, ()> {
    let open: ToCompiler<CompileRequest> = Exposed::new(CompileRequest { policy, plugins });
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

impl Compiler {
    pub fn new(
        leg: std::sync::Arc<crate::fleet::Leg<std::sync::Arc<CompilerLeg<CompileScope>>>>,
    ) -> Self {
        Self { leg }
    }

    /// Compile `(policy, plugins)` on the worker. A transport failure surfaces
    /// as `CompileError` via its `From<remoc::rtc::CallError>`.
    pub async fn compile(
        &self,
        policy_wasm: Vec<u8>,
        plugins: Vec<PluginInstance>,
    ) -> Result<CompiledBundle, CompileError> {
        let client = self.leg.get().ok_or_else(|| {
            CompileError("the compile-worker leg is down; api is reporting it".into())
        })?;
        let bundle: Untrusted<CompiledBundle, CompileScope> = client
            .compile(outbound_compile_request(policy_wasm, plugins))
            .await?;
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
        Ok(bundle
            .trust_unchecked::<Asserted, _>(reason!(
                "NO KIND FITS — an accepted risk, not a discharge. Not re-derived \
                 (this side carries no Cranelift), not bound (a digest the compiler \
                 also chose is its word twice), not bounded (the range is arbitrary \
                 native code), not contained (the audience is the executor, which \
                 did not author it). Carried because no check exists and the fleet \
                 needs a compiler; what limits the damage is downstream containment"
            ))
            .into_inner())
    }
}

/// Connect to a compile-worker already listening at `addr` and hand back the leg.
/// The worker is brought up at boot, not by api. The dial is mutual RA-TLS — TCP by
/// default, vsock under that feature — and `engine_rpc::connect_compiler` takes the
/// attested stream from there, keeping the generated client this side cannot name.
pub async fn connect_compile_worker(
    addr: &str,
    attestor: std::sync::Arc<dyn enclavid_attestation::Attestor>,
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
    let (leg, driver) = engine_rpc::connect_compiler(read, write)
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

    // A minimal in-process server, so the Compiler client's rpc plumbing is
    // exercised without a real worker (the transport factory
    // `connect_compile_worker` is the thin, hand-reviewed piece).
    //
    // It implements the UNTRUSTED view because that is the only implementable
    // shape: engine-rpc exports no raw server, so a test cannot serve this
    // contract by a route production code could not take either.
    struct MockService;

    impl engine_rpc::CompilerServiceUntrusted for MockService {
        type Scope = (AuthN,);

        async fn compile(
            &self,
            req: Untrusted<CompileRequest, Self::Scope>,
        ) -> Result<CompiledBundle, CompileError> {
            let CompileRequest { policy, plugins } = req
                .trust_unchecked::<AuthN, _>(reason!("test fixture"))
                .into_inner();
            if policy == b"boom" {
                return Err(CompileError("intentional".into()));
            }
            Ok(CompiledBundle {
                cwasm: vec![policy.len() as u8, plugins.len() as u8],
                embedded_imports: vec![],
                catalogs: vec![],
            })
        }
    }

    /// The Compiler client drives a CompilerService over an in-memory remoc
    /// duplex: args cross, the typed bundle returns, and the error path
    /// propagates.
    #[tokio::test]
    async fn compiler_round_trips() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (a_r, a_w) = tokio::io::split(a);
        let (b_r, b_w) = tokio::io::split(b);

        // Worker end: serve the mock through the contract's own serve half.
        let server = tokio::spawn(async move {
            let _ = engine_rpc::serve_compiler(a_r, a_w, MockService, 4).await;
        });

        // Orchestrator end: take the leg, wrap in Compiler.
        let (leg_client, _driver) = engine_rpc::connect_compiler::<CompileScope, _, _>(b_r, b_w)
            .await
            .expect("connect");
        let client = std::sync::Arc::new(leg_client);
        let leg = crate::fleet::Leg::new();
        leg.set(Some(client.clone()));
        let compiler = Compiler::new(leg.clone());

        let plugins = vec![PluginInstance {
            package: "p".into(),
            wasm: vec![0],
        }];
        let bundle = compiler.compile(b"hello".to_vec(), plugins).await.unwrap();
        assert_eq!(bundle.cwasm, vec![5u8, 1u8]);

        // A down leg fails the call rather than waiting: how long to wait for a
        // peer is the host's decision, and the health port is already telling it.
        leg.set(None);
        // `CompiledBundle` is deliberately not `Debug` (it holds megabytes of
        // cwasm), so match the outcome rather than unwrapping it.
        match compiler.compile(b"hello".to_vec(), vec![]).await {
            Err(CompileError(m)) => assert!(m.contains("leg is down"), "{m}"),
            Ok(_) => panic!("a call on a down leg must fail"),
        }
        leg.set(Some(client));

        let err = match compiler.compile(b"boom".to_vec(), vec![]).await {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert!(format!("{err}").contains("intentional"), "got {err}");

        server.abort();
    }
}
