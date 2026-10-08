//! Integration: the compile-worker's disposable per-compile CHILD process.
//!
//! Proves the compiler's use of the shared `engine-supervisor` — spawn a REAL
//! `engine-compiler-child`, serve one `CompileChildService::compile`, fail safe, exit. The
//! happy-path compile itself is covered by engine-compiler's own tests of the
//! pieces `compile_to_parts` calls, and a real multi-MiB cwasm reaching a spawned
//! child is covered by the executor child's
//! `spawned_child_primes_runs_relays_then_exits` (same engine-supervisor, same
//! transport).
//!
//! The binary under test comes from [`xtask::child_binary`], NOT from this
//! package's own `CARGO_BIN_EXE_engine-compiler-child`. That one is built in the
//! same cargo invocation as this test, so it carries whatever features the
//! test's dev-dependencies added — the parent half of `engine-supervisor`, and
//! with it `tokio/process`. `child_binary` runs the invocation the image runs,
//! so what gets spawned below is what ships. See that function for the whole
//! reasoning.

use std::borrow::Cow;
use std::time::Duration;

use remoc::codec::Ciborium;

use engine_compiler::{CompileChildService, CompileChildServiceClient};
use engine_rpc::{CompileError, CompileRequest};
use engine_types::composition::PluginInstance;

/// Spawn the real `engine-compiler-child` over a socketpair (via engine-supervisor) the way the
/// compile-worker supervisor does, and return the child + its service client.
async fn spawn() -> (tokio::process::Child, CompileChildServiceClient<Ciborium>) {
    spawn_with(false).await
}

async fn spawn_with(
    filtered: bool,
) -> (tokio::process::Child, CompileChildServiceClient<Ciborium>) {
    let exe = xtask::child_binary("engine-compiler-child");
    engine_supervisor::spawn_and_connect::<CompileChildServiceClient<Ciborium>>(
        &exe, None, filtered,
    )
    .await
    .expect("spawn engine-compiler-child")
}

/// Fail-safe: a garbage / non-component policy makes the child's Cranelift compile
/// fail CLEANLY into a `CompileError` over the wire — not a panic, not a hang —
/// and the child process exits when its client is dropped (disposable per-compile).
#[tokio::test]
async fn garbage_policy_fails_safe_then_child_exits() {
    let (mut child, client) = spawn().await;

    // Not `expect_err` — `CompiledBundle` is deliberately not `Debug` (it holds
    // megabytes of cwasm), so match the outcome explicitly.
    let outcome = tokio::time::timeout(
        Duration::from_secs(30),
        client.compile(CompileRequest {
            policy: b"not a wasm component".to_vec(),
            plugins: vec![],
        }),
    )
    .await
    .expect("compile must not hang");
    match outcome {
        Ok(_) => panic!("garbage policy must fail to compile, got a bundle"),
        Err(e) => assert_eq!(
            e,
            CompileError::Failed,
            "garbage fails to compile; it is not a refusal"
        ),
    }

    drop(client);
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("child must exit after its client is dropped")
        .expect("wait for child");
    assert!(status.success(), "child exits cleanly, got {status:?}");
}

/// A component holding one custom section of `len` bytes.
fn with_section(name: &str, len: usize) -> Vec<u8> {
    let mut c = wasm_encoder::Component::new();
    c.section(&wasm_encoder::CustomSection {
        name: Cow::Borrowed(name),
        data: Cow::Owned(vec![b'x'; len]),
    });
    c.finish()
}

/// Catalogs past the cap are REFUSED, and the refusal crosses the seam as itself.
#[tokio::test]
async fn catalogs_past_the_cap_are_refused_through_the_child() {
    let (mut child, client) = spawn().await;
    let cap = engine_types::limits::MAX_EMBEDDED_SECTION_BYTES as usize;
    let outcome = tokio::time::timeout(
        Duration::from_secs(30),
        client.compile(CompileRequest {
            policy: with_section(enclavid_embedded::SECTION_I18N, cap + 1),
            plugins: vec![],
        }),
    )
    .await
    .expect("a refusal must not hang");
    match outcome {
        Ok(_) => panic!("catalogs past the cap must not compile"),
        Err(e) => assert_eq!(e, CompileError::Refused),
    }

    drop(client);
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("child must exit after its client is dropped")
        .expect("wait for child");
    assert!(status.success(), "child exits cleanly, got {status:?}");
}

/// Fail-safe: a child that dies mid-flight makes the RPC ERROR
/// (disconnect), not hang — so the supervisor maps it to a `CompileError` and api
/// surfaces a config-resolution failure rather than wedging.
#[tokio::test]
async fn dead_child_surfaces_error_not_hang() {
    let (mut child, client) = spawn().await;
    child.kill().await.expect("kill engine-compiler-child");

    let res = tokio::time::timeout(
        Duration::from_secs(10),
        client.compile(CompileRequest {
            policy: b"x".to_vec(),
            plugins: vec![],
        }),
    )
    .await
    .expect("call to a dead child must resolve (error), not hang");
    assert!(
        res.is_err(),
        "compile to a dead child must error, not return a bundle"
    );
}

/// A REAL compile, all the way through the spawned child: the fixture policy
/// fused with its plugins, Cranelift codegen, and a multi-MiB `cwasm` returned
/// over the socketpair.
///
/// Every other test here feeds the child garbage, which fails in the validator
/// long before codegen. So until this existed, no test had ever run Cranelift's
/// success path inside a spawned, hardened child — the single most syscall-hungry
/// thing the fleet does, and the path a sandbox has to survive for the product to
/// work at all. It is also what the child's syscall allowlist was measured
/// against; without it the allowlist would have been built from the error path.
///
/// Slow (a full compile of the real fixture), so the deadline is generous.
#[tokio::test]
async fn a_real_policy_compiles_through_the_spawned_child() {
    let plugins: Vec<PluginInstance> = xtask::fixtures::all_plugins()
        .into_iter()
        .map(|(package, wasm)| PluginInstance {
            package: package.to_string(),
            wasm: wasm.to_vec(),
        })
        .collect();

    let (mut child, client) = spawn_with(true).await;

    let bundle = tokio::time::timeout(
        Duration::from_secs(300),
        client.compile(CompileRequest {
            policy: xtask::fixtures::test_policy().to_vec(),
            plugins,
        }),
    )
    .await
    .expect("a real compile must not hang")
    .unwrap_or_else(|e| panic!("the fixture policy must compile: {e}"));

    assert!(
        bundle.cwasm.len() > 1_000_000,
        "a real composition's cwasm should be multi-MiB, got {} bytes",
        bundle.cwasm.len(),
    );
    assert!(
        !bundle.catalogs.is_empty(),
        "the composition's embedded catalogs must come back with it",
    );

    drop(client);
    let status = tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .expect("child must exit after its client is dropped")
        .expect("wait for child");
    assert!(status.success(), "child exits cleanly, got {status:?}");
}

/// The production filter must not stop a child from working.
///
/// It is installed between fork and exec, so it governs the whole of the
/// child's startup: the tokio runtime coming up, the remoc handshake, and
/// Cranelift. A syscall the runtime needs and the filter lacks shows up here as
/// a child that dies before it answers — rather than in production, on the
/// first compile.
///
/// Linux-only: the filter is a no-op elsewhere, so the assertion would be vacuous
/// on a dev host.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_child_starts_and_serves_under_the_production_filter() {
    let (mut child, client) = spawn_with(true).await;

    // Reaching a `CompileError` at all proves the child got through exec, stood a
    // runtime up, completed the handshake and ran Cranelift far enough to reject
    // the input.
    let outcome = tokio::time::timeout(
        Duration::from_secs(30),
        client.compile(CompileRequest {
            policy: b"not a wasm component".to_vec(),
            plugins: vec![],
        }),
    )
    .await
    .expect("a hardened child must not hang");
    match outcome {
        Ok(_) => panic!("garbage policy must fail to compile, got a bundle"),
        Err(e) => assert_eq!(e, CompileError::Failed),
    }

    drop(client);
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("hardened child must exit after its client is dropped")
        .expect("wait for child");
    assert!(status.success(), "child exits cleanly, got {status:?}");
}

/// The runner's whole path with a real child, as the compile-worker drives it:
/// admitted, spawned under the filters, answered — and then killed as the call
/// ends, its slot and what was kept for it given back once it is gone. A runner
/// of one slot answering twice is the slot coming back.
#[tokio::test]
async fn a_runner_answers_and_gives_back_what_its_child_held() {
    use std::sync::Arc;

    use engine_supervisor::{ChildRunner, ChildTimes, ExitCause, RunnerConfig};

    let runner = ChildRunner::new(
        RunnerConfig {
            exe: xtask::child_binary("engine-compiler-child"),
            max_children: 1,
            deadline: Duration::from_secs(30),
            admission_wait: Some(Duration::from_secs(30)),
            times: ChildTimes::default(),
        },
        None,
    );
    let kept = Arc::new(());
    for _ in 0..2 {
        let (answer, exit) = runner
            .run(
                None,
                kept.clone(),
                |client: CompileChildServiceClient<Ciborium>| async move {
                    client
                        .compile(CompileRequest {
                            policy: b"not a wasm component".to_vec(),
                            plugins: vec![],
                        })
                        .await
                },
            )
            .await
            .expect("the runner admits, spawns and answers");
        assert!(matches!(answer, Err(CompileError::Failed)));
        // Without cgroups nothing is attributed, but the cause settles only once
        // the child is gone.
        assert_eq!(exit.cause().await, ExitCause::Unattributed);
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        while Arc::strong_count(&kept) > 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("what was kept for each child is let go of once it is gone");
}
