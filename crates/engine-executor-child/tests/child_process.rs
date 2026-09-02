//! Integration: the execution-worker's disposable per-round CHILD process.
//!
//! Drives the REAL `engine-executor-child` binary the way the supervisor does — the one
//! path the executor's in-process `happy_path` and the `engine-rpc` remoc test
//! don't cover: spawn a disposable per-round PROCESS over a socketpair, `prime`
//! it with a real (10-15 MiB) bundle, `run` one round, assert the child relayed
//! its callbacks and then EXITED; plus the fail-safe paths (garbage cwasm, dead
//! child).
//!
//! The binary under test comes from [`xtask::child_binary`], NOT from this
//! package's own `CARGO_BIN_EXE_engine-executor-child`. That one is built in the
//! same cargo invocation as this test, so it carries whatever features the
//! test's dev-dependencies added — the parent half of `engine-supervisor`, and
//! with it `tokio/process`. `child_binary` runs the invocation the image runs,
//! so what gets spawned below is what ships. See that function for the whole
//! reasoning.

use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use engine_compiler::Compiler;
use engine_executor::{Event, SessionState};
use remoc::codec::Ciborium;
use remoc::rtc::ServerShared;

use engine_rpc::{
    BundleRef, CallbackError, CatalogEntry, ChildCallbacks, ChildCallbacksServerShared,
    ChildService, ChildServiceClient, CompiledBundle, ConsentDisclosure, ExecError, RunStatus,
};

/// The plugins the policy imports, from the shared fixture catalog — the same
/// set the executor's `happy_path` composes, so this child primes the bundle
/// production actually produces.
fn all_plugins() -> Vec<engine_executor::PluginInstance> {
    xtask::fixtures::all_plugins()
        .into_iter()
        .map(|(package, wasm)| engine_executor::PluginInstance {
            package: package.to_string(),
            wasm: wasm.to_vec(),
        })
        .collect()
}

/// Unique suffix so concurrent tests don't collide on the cwasm temp file.
static TEST_CWASM_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Write a bundle's cwasm to a temp file and build the mmap-delivery
/// [`BundleRef`] the child now expects (Stage A) — the supervisor does this per
/// composition; the test does it inline. The file leaks (ephemeral test tmp).
fn to_bundle_ref(bundle: &CompiledBundle) -> BundleRef {
    let n = TEST_CWASM_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "enclavid-test-cwasm-{}-{n}.bin",
        std::process::id()
    ));
    std::fs::write(&path, &bundle.cwasm).expect("write test cwasm file");
    BundleRef {
        cwasm_path: path.to_string_lossy().into_owned(),
        embedded_imports: bundle.embedded_imports.clone(),
        catalogs: bundle.catalogs.clone(),
    }
}

/// The upstream the child's callbacks relay to — plays the supervisor's relay
/// (→ api). Records what the child called BACK during the run.
struct MockCallbacks {
    session_changes: Mutex<u32>,
    media_loads: Mutex<Vec<[u8; 32]>>,
}

impl ChildCallbacks for MockCallbacks {
    async fn media_load(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, CallbackError> {
        self.media_loads.lock().unwrap().push(hash);
        Ok(None)
    }
    async fn session_change(
        &self,
        _state: SessionState,
        _disclosures: Vec<ConsentDisclosure>,
        _media: Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<(), CallbackError> {
        *self.session_changes.lock().unwrap() += 1;
        Ok(())
    }
}

/// Compile the test policy + all plugins into a real wire `CompiledBundle`
/// (the same shape the compile-worker returns), so `prime` deserializes a
/// genuine multi-MiB cwasm rather than a synthetic stub.
fn real_bundle() -> CompiledBundle {
    let compiler = Compiler::new().expect("compiler");
    let parts = compiler
        .compile_to_parts(xtask::fixtures::test_policy(), &all_plugins())
        .expect("compile_to_parts");
    CompiledBundle {
        cwasm: parts.cwasm,
        embedded_imports: parts.embedded_imports,
        catalogs: parts
            .catalogs
            .into_iter()
            .map(|(hash, decls)| CatalogEntry { hash, decls })
            .collect(),
    }
}

/// Spawn the real `engine-executor-child` over a socketpair (its fd 0), the way the
/// supervisor does, and return the child handle + its `ChildService` client.
async fn spawn_child() -> (tokio::process::Child, ChildServiceClient<Ciborium>) {
    let (sup_end, child_end) = std::os::unix::net::UnixStream::pair().unwrap();
    sup_end.set_nonblocking(true).unwrap();
    let mut cmd = tokio::process::Command::new(xtask::child_binary("engine-executor-child"));
    cmd.stdin(std::process::Stdio::from(OwnedFd::from(child_end)));
    cmd.kill_on_drop(true);
    let child = cmd.spawn().expect("spawn engine-executor-child");

    let sup_end = tokio::net::UnixStream::from_std(sup_end).unwrap();
    let (read, write) = sup_end.into_split();
    type Cli = ChildServiceClient<Ciborium>;
    let (conn, _tx, mut rx) =
        remoc::Connect::io::<_, _, Cli, Cli, Ciborium>(engine_rpc::connection_cfg(), read, write)
            .await
            .unwrap();
    tokio::spawn(conn);
    let client = rx
        .recv()
        .await
        .unwrap()
        .expect("child sent its service client");
    (child, client)
}

/// Full happy path THROUGH the spawned process: prime a real bundle, run the
/// genesis round, assert a relayed `session_change`, then the child exits when
/// its client is dropped (disposable per-round process).
#[tokio::test]
async fn spawned_child_primes_runs_relays_then_exits() {
    let bundle = real_bundle();
    let (mut child, client) = spawn_child().await;

    // Prime via the mmap path: the child `deserialize_file`s a real
    // (multi-MiB) cwasm written to a temp file — only the path crosses the hop.
    client
        .prime(to_bundle_ref(&bundle))
        .await
        .expect("prime real bundle");

    let cbs = Arc::new(MockCallbacks {
        session_changes: Mutex::new(0),
        media_loads: Mutex::new(Vec::new()),
    });
    let (server, cb_client) = ChildCallbacksServerShared::<_, Ciborium>::new(cbs.clone(), 4);
    tokio::spawn(async move {
        let _ = server.serve(true).await;
    });

    // Genesis: the policy renders the passport media prompt and fires the
    // listener once — relayed to the mock as ONE session_change.
    let reply = client
        .run(SessionState::default(), Event::Start, vec![], cb_client)
        .await
        .expect("run genesis round");
    assert!(
        matches!(reply.status, RunStatus::AwaitingInput(_)),
        "genesis must render a prompt, got {:?}",
        reply.status,
    );
    assert_eq!(
        *cbs.session_changes.lock().unwrap(),
        1,
        "the child must relay exactly one session_change for the round",
    );

    // Dropping the client ends the child's serve loop → the PROCESS exits.
    drop(client);
    let status = tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .expect("child must exit promptly after its client is dropped")
        .expect("wait for child");
    assert!(status.success(), "child exits cleanly, got {status:?}");
}

/// The same round, but through `spawn_and_connect` with the hardening the
/// execution-worker actually uses — so the child runs under the egress
/// seccomp filter.
///
/// `spawn_child` above builds the pair and the `Command` by hand, which is
/// convenient and means it applies NO hardening; every other test in this
/// module therefore exercises a child the production filter has never
/// touched. This one closes that: it primes a real cwasm and runs a genesis
/// round, so wasmtime — `mmap`, `deserialize_file`, the whole engine — comes
/// up under the filter rather than beside it. A rule too broad shows up here
/// as a child that never finishes its handshake.
///
/// Linux-only: the filter is a no-op elsewhere, so off Linux this would
/// assert nothing.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn spawned_child_runs_a_round_under_the_production_filter() {
    let bundle = real_bundle();
    let hardening = engine_supervisor::Hardening {
        seccomp_egress: true,
        // What execution-worker passes: wasmtime reserves large VIRTUAL
        // memory, so a hard RLIMIT_AS would break it.
        address_space: None,
    };
    let (mut child, client) = engine_supervisor::spawn_and_connect::<ChildServiceClient<Ciborium>>(
        &xtask::child_binary("engine-executor-child"),
        &[],
        Some(hardening),
    )
    .await
    .expect("spawn a hardened engine-executor-child");

    client
        .prime(to_bundle_ref(&bundle))
        .await
        .expect("a hardened child must still deserialize a real cwasm");

    let cbs = Arc::new(MockCallbacks {
        session_changes: Mutex::new(0),
        media_loads: Mutex::new(Vec::new()),
    });
    let (server, cb_client) = ChildCallbacksServerShared::<_, Ciborium>::new(cbs.clone(), 4);
    tokio::spawn(async move {
        let _ = server.serve(true).await;
    });

    let reply = client
        .run(SessionState::default(), Event::Start, vec![], cb_client)
        .await
        .expect("a hardened child must still run a round");
    assert!(
        matches!(reply.status, RunStatus::AwaitingInput(_)),
        "genesis must render a prompt, got {:?}",
        reply.status,
    );

    drop(client);
    let status = tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .expect("hardened child must exit promptly after its client is dropped")
        .expect("wait for child");
    assert!(status.success(), "child exits cleanly, got {status:?}");
}

/// Fail-safe: a tampered / toolchain-skewed cwasm fails `deserialize` in the
/// child and surfaces as `ExecError::Run` — not a panic, not a hang.
#[tokio::test]
async fn prime_with_garbage_cwasm_fails_safe() {
    let (mut child, client) = spawn_child().await;
    let bundle = CompiledBundle {
        cwasm: b"definitely not a cwasm".to_vec(),
        embedded_imports: vec![],
        catalogs: vec![],
    };
    let err = tokio::time::timeout(
        Duration::from_secs(10),
        client.prime(to_bundle_ref(&bundle)),
    )
    .await
    .expect("prime must not hang")
    .expect_err("garbage cwasm must fail prime");
    assert!(
        matches!(err, ExecError::Run(_)),
        "expected ExecError::Run, got {err:?}"
    );
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
}

/// Fail-safe: a child that dies mid-flight makes the RPC ERROR (disconnect),
/// so the supervisor maps it to `ExecError` → api 5xx → applicant retries
/// against intact api-side state — it never hangs on a corpse.
#[tokio::test]
async fn dead_child_surfaces_error_not_hang() {
    let (mut child, client) = spawn_child().await;
    child.kill().await.expect("kill child");
    let bundle = CompiledBundle {
        cwasm: vec![],
        embedded_imports: vec![],
        catalogs: vec![],
    };
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        client.prime(to_bundle_ref(&bundle)),
    )
    .await
    .expect("call to a dead child must resolve (error), not hang");
    assert!(
        res.is_err(),
        "prime to a dead child must error, got {res:?}"
    );
}

/// PERF GATE (not an assertion) — measures the per-round cost the zygote
/// would remove (`deserialize` + `prime`, CoW-inherited) vs a full fresh-exec
/// round, on a REAL bundle. Run:
///   cargo test -p engine-executor-child --test child_process -- \
///     --ignored --nocapture measure
#[tokio::test]
#[ignore = "perf measurement; run with --ignored --nocapture"]
async fn measure_per_round_cost() {
    use std::time::{Duration, Instant};

    use engine_executor::{EmbeddedRegistry, Executor};

    let bundle = real_bundle();
    eprintln!(
        "\n=== cwasm size: {} bytes ({:.2} MiB) ===",
        bundle.cwasm.len(),
        bundle.cwasm.len() as f64 / (1024.0 * 1024.0),
    );

    let avg = |v: &[Duration]| v.iter().sum::<Duration>() / v.len() as u32;

    // Isolate Engine::new() (OS-agnostic wasmtime engine creation) — one of
    // the three things baked into the `spawn` phase (the others, exec/dyld,
    // are macOS-heavy on this dev box vs the Linux CVM target).
    {
        let _ = Executor::new().unwrap(); // warm
        let mut en = Vec::new();
        for _ in 0..10 {
            let t = Instant::now();
            let _e = Executor::new().unwrap();
            en.push(t.elapsed());
        }
        eprintln!("Executor::new() [Engine::new]: avg {:?}", avg(&en));
    }

    let executor = Executor::new().unwrap();
    let build_embedded = || {
        let mut b = EmbeddedRegistry::builder();
        for c in &bundle.catalogs {
            b.add_component(c.hash, c.decls.clone());
        }
        std::sync::Arc::new(b.build())
    };

    // Warm up (page-cache, allocator).
    {
        let comp = executor.deserialize_component(&bundle.cwasm).unwrap();
        let _ = executor
            .prime(&comp, &bundle.embedded_imports, build_embedded())
            .unwrap();
    }

    // (a)+(b): the two layers CoW-inheritance would remove, in-process.
    let n = 20;
    let (mut de, mut pr) = (Vec::new(), Vec::new());
    for _ in 0..n {
        let t = Instant::now();
        let comp = executor.deserialize_component(&bundle.cwasm).unwrap();
        de.push(t.elapsed());
        let t = Instant::now();
        let _primed = executor
            .prime(&comp, &bundle.embedded_imports, build_embedded())
            .unwrap();
        pr.push(t.elapsed());
    }
    eprintln!(
        "deserialize_component (bytes, warm):      avg {:?}",
        avg(&de)
    );
    eprintln!(
        "prime (Linker+InstancePre):               avg {:?}",
        avg(&pr)
    );

    // deserialize_FILE (mmap) — COLD (fresh executor, like a fresh child) vs
    // warm. Isolates whether the child's ~50 ms `prime` is deserialize COMPUTE
    // (a FULL zygote inheriting the warm Component eliminates it; LIGHT does
    // NOT) or transfer/remoc (neither zygote helps).
    {
        let n = TEST_CWASM_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("enclavid-measure-cwasm-{n}.bin"));
        std::fs::write(&path, &bundle.cwasm).unwrap();
        let cold = Executor::new().unwrap();
        let t = Instant::now();
        let _c = cold.deserialize_component_file(&path).unwrap();
        eprintln!(
            "deserialize_file (mmap) COLD (fresh executor): {:?}",
            t.elapsed()
        );
        let mut df = Vec::new();
        for _ in 0..10 {
            let t = Instant::now();
            let _c = executor.deserialize_component_file(&path).unwrap();
            df.push(t.elapsed());
        }
        eprintln!(
            "deserialize_file (mmap) warm:             avg {:?}",
            avg(&df)
        );
        let _ = std::fs::remove_file(&path);
    }

    // Scale of the catalogs (still shipped in BundleRef over remoc) — to tell
    // whether the ~48 ms residual `prime` is catalog VOLUME or remoc RPC base
    // latency.
    {
        let (mut ncat, mut nloc, mut ndf, mut nic) = (0usize, 0usize, 0usize, 0usize);
        for c in &bundle.catalogs {
            ncat += 1;
            ndf += c.decls.disclosure_fields.len();
            nic += c.decls.icons.len();
            for (_, tr) in &c.decls.localized {
                nloc += tr.len();
            }
        }
        eprintln!(
            "catalogs shipped in BundleRef: {ncat} components, {nloc} translations, {ndf} DF, {nic} icons"
        );
    }

    // Full fresh-exec round, BROKEN DOWN — the zygote (fork from a warm,
    // already-primed template) would replace `spawn`(exec+Engine::new) +
    // `prime`(deserialize+InstancePre) with a cheap fork; only `run`
    // (instantiate + the policy round) is inherent to every model.
    // Write the cwasm file ONCE (as the supervisor caches per composition); the
    // per-round `prime` then MMAPs it (Stage A) — this is what drops prime cost.
    let bundle_ref = to_bundle_ref(&real_bundle_cached());
    // Warm the engine-executor-child binary back into the page cache (the fixture
    // compilation above evicted it) so `sp` reflects STEADY-STATE spawn, not a
    // cold first-load.
    for _ in 0..3 {
        let (mut c, cl) = spawn_child().await;
        drop(cl);
        let _ = tokio::time::timeout(Duration::from_secs(5), c.wait()).await;
    }
    let (mut sp, mut prm, mut rn) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..5 {
        let t = Instant::now();
        let (mut child, client) = spawn_child().await;
        sp.push(t.elapsed());

        let t = Instant::now();
        client.prime(bundle_ref.clone()).await.expect("prime");
        prm.push(t.elapsed());

        let cbs = std::sync::Arc::new(MockCallbacks {
            session_changes: std::sync::Mutex::new(0),
            media_loads: std::sync::Mutex::new(Vec::new()),
        });
        let (server, cb_client) = ChildCallbacksServerShared::<_, Ciborium>::new(cbs, 4);
        tokio::spawn(async move {
            let _ = server.serve(true).await;
        });
        let t = Instant::now();
        client
            .run(SessionState::default(), Event::Start, vec![], cb_client)
            .await
            .expect("run");
        rn.push(t.elapsed());

        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(15), child.wait()).await;
    }
    eprintln!("--- full fresh-exec round, by phase ---");
    eprintln!(
        "  spawn (exec + child Engine::new + handshake): avg {:?}",
        avg(&sp)
    );
    eprintln!(
        "  prime (ship cwasm + child deserialize+pre):   avg {:?}",
        avg(&prm)
    );
    eprintln!(
        "  run   (instantiate + genesis policy round):   avg {:?}",
        avg(&rn)
    );
    eprintln!(
        "  → zygote removes spawn+prime, keeps run: saves ~{:?}/round",
        avg(&sp) + avg(&prm)
    );
    eprintln!("=== end perf gate ===\n");
}

/// `real_bundle` recompiles each call (~seconds); cache one for the round loop.
fn real_bundle_cached() -> CompiledBundle {
    use std::sync::OnceLock;
    static B: OnceLock<CompiledBundle> = OnceLock::new();
    B.get_or_init(real_bundle).clone()
}
