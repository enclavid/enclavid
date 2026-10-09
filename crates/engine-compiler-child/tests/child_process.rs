//! Integration: the compile-worker's disposable per-compile CHILD process.
//!
//! Proves the compiler's use of the shared `engine-supervisor` — spawn a REAL
//! `engine-compiler-child` with an output file at its inherited descriptor, stream
//! one compile's components to it, take its answer and the cwasm it wrote, fail
//! safe, exit. The happy-path compile itself is covered by engine-compiler's own
//! tests of the pieces `compile_to_parts` calls, and a real multi-MiB cwasm reaching
//! a spawned child is covered by the executor child's
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
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsFd;
use std::time::Duration;

use remoc::codec::Ciborium;

use engine_compiler::{ChildCompiled, CompileChildService, CompileChildServiceClient};
use engine_rpc::{
    BundleMeta, CompileError, CompileRequest, CompileSource, MAX_CWASM_BYTES, PluginLength,
};
use engine_types::composition::PluginInstance;
use fleet_stream::{BlobHeader, StreamLen, bin};

/// A spawned child, its service client, and the file it writes its cwasm to.
struct Spawned {
    process: tokio::process::Child,
    client: CompileChildServiceClient<Ciborium>,
    output: File,
}

/// Spawn the real `engine-compiler-child` over a socketpair (via engine-supervisor)
/// the way the compile-worker supervisor does, with an output file at its
/// inherited descriptor.
async fn spawn() -> Spawned {
    spawn_with(false).await
}

async fn spawn_with(filtered: bool) -> Spawned {
    let exe = xtask::child_binary("engine-compiler-child");
    let output = tempfile::tempfile().expect("an output file");
    let (process, client) = engine_supervisor::spawn_and_connect::<
        CompileChildServiceClient<Ciborium>,
    >(&exe, Some(output.as_fd()), filtered)
    .await
    .expect("spawn engine-compiler-child");
    Spawned {
        process,
        client,
        output,
    }
}

/// One compile through `client`, its components streamed beside the call as the
/// supervisor relays them.
async fn compile(
    client: &CompileChildServiceClient<Ciborium>,
    policy: Vec<u8>,
    plugins: Vec<PluginInstance>,
) -> Result<ChildCompiled, CompileError> {
    let (request, writer) = CompileSource::whole(policy, plugins)
        .expect("components within the bound")
        .split();
    let mut call = std::pin::pin!(client.compile(request));
    tokio::select! {
        reply = &mut call => reply,
        () = writer => call.await,
    }
}

/// The child exits, cleanly, once its client is dropped.
async fn exits_cleanly(spawned: Spawned) {
    let Spawned {
        mut process,
        client,
        ..
    } = spawned;
    drop(client);
    let status = tokio::time::timeout(Duration::from_secs(15), process.wait())
        .await
        .expect("child must exit after its client is dropped")
        .expect("wait for child");
    assert!(status.success(), "child exits cleanly, got {status:?}");
}

/// Fail-safe: a garbage / non-component policy makes the child's Cranelift compile
/// fail CLEANLY into a `CompileError` over the wire — not a panic, not a hang —
/// and the child process exits when its client is dropped (disposable per-compile).
#[tokio::test]
async fn garbage_policy_fails_safe_then_child_exits() {
    let spawned = spawn().await;
    // Not `expect_err` — `ChildCompiled` is deliberately not `Debug`, so match
    // the outcome explicitly.
    let outcome = tokio::time::timeout(
        Duration::from_secs(30),
        compile(&spawned.client, b"not a wasm component".to_vec(), vec![]),
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
    exits_cleanly(spawned).await;
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
    let spawned = spawn().await;
    let cap = engine_types::limits::MAX_EMBEDDED_SECTION_BYTES as usize;
    let outcome = tokio::time::timeout(
        Duration::from_secs(30),
        compile(
            &spawned.client,
            with_section(enclavid_embedded::SECTION_I18N, cap + 1),
            vec![],
        ),
    )
    .await
    .expect("a refusal must not hang");
    match outcome {
        Ok(_) => panic!("catalogs past the cap must not compile"),
        Err(e) => assert_eq!(e, CompileError::Refused),
    }
    exits_cleanly(spawned).await;
}

/// Components that stop part-way are never compiled as what arrived: the child
/// answers `Failed` rather than compiling a prefix, and rather than hanging.
#[tokio::test]
async fn components_that_stop_part_way_are_not_compiled() {
    let spawned = spawn().await;
    let (tx, components) = bin::channel();
    let request = CompileRequest {
        policy: StreamLen::new(1000).unwrap(),
        plugins: vec![PluginLength {
            package: "p".into(),
            length: StreamLen::new(1000).unwrap(),
        }],
        components,
    };
    let abandon = async move {
        let mut raw = tx.into_inner().await.expect("the child takes the stream");
        let part = raw
            .send_chunks()
            .send(vec![0u8; 1500].into())
            .await
            .expect("the first part goes");
        drop(part);
        // Kept open until the child has answered, so what it sees is the
        // abandoned message and not a closed connection.
        std::future::pending::<()>().await
    };
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::select! {
            reply = spawned.client.compile(request) => reply,
            () = abandon => unreachable!("the abandoning side never ends"),
        }
    })
    .await
    .expect("an abandoned compile must not hang");
    match outcome {
        Ok(_) => panic!("an abandoned compile must not succeed"),
        Err(e) => assert_eq!(e, CompileError::Failed),
    }
    exits_cleanly(spawned).await;
}

/// Fail-safe: a child that dies mid-flight makes the RPC ERROR
/// (disconnect), not hang — so the supervisor maps it to a `CompileError` and api
/// surfaces a config-resolution failure rather than wedging.
#[tokio::test]
async fn dead_child_surfaces_error_not_hang() {
    let mut spawned = spawn().await;
    spawned
        .process
        .kill()
        .await
        .expect("kill engine-compiler-child");

    let res = tokio::time::timeout(
        Duration::from_secs(10),
        compile(&spawned.client, b"x".to_vec(), vec![]),
    )
    .await
    .expect("call to a dead child must resolve (error), not hang");
    assert!(
        res.is_err(),
        "compile to a dead child must error, not return a bundle"
    );
}

/// A REAL compile, all the way through the spawned child: the fixture policy
/// fused with its plugins, Cranelift codegen, and a multi-MiB `cwasm` written to
/// the output file the child was handed — exactly the length and digest it says.
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

    let mut spawned = spawn_with(true).await;

    let compiled = tokio::time::timeout(
        Duration::from_secs(300),
        compile(
            &spawned.client,
            xtask::fixtures::test_policy().to_vec(),
            plugins,
        ),
    )
    .await
    .expect("a real compile must not hang")
    .unwrap_or_else(|e| panic!("the fixture policy must compile: {e}"));

    // From the start: the child's descriptor is a copy of this one, sharing its
    // offset, which its writes left at the end.
    let mut cwasm = Vec::new();
    spawned
        .output
        .seek(SeekFrom::Start(0))
        .expect("rewind the output file");
    spawned
        .output
        .read_to_end(&mut cwasm)
        .expect("read the cwasm the child wrote");
    assert!(
        cwasm.len() > 1_000_000,
        "a real composition's cwasm should be multi-MiB, got {} bytes",
        cwasm.len(),
    );
    assert!(
        BlobHeader::<MAX_CWASM_BYTES>::of(&cwasm).unwrap() == compiled.cwasm,
        "the cwasm the child wrote is the one it named"
    );
    let meta: BundleMeta = ciborium::from_reader(&compiled.meta[..]).expect("the metadata decodes");
    assert!(
        !meta.catalogs.is_empty(),
        "the composition's embedded catalogs must come back with it",
    );
    exits_cleanly(spawned).await;
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
    let spawned = spawn_with(true).await;

    // Reaching a `CompileError` at all proves the child got through exec, stood a
    // runtime up, completed the handshake, took its components and ran Cranelift
    // far enough to reject the input.
    let outcome = tokio::time::timeout(
        Duration::from_secs(30),
        compile(&spawned.client, b"not a wasm component".to_vec(), vec![]),
    )
    .await
    .expect("a hardened child must not hang");
    match outcome {
        Ok(_) => panic!("garbage policy must fail to compile, got a bundle"),
        Err(e) => assert_eq!(e, CompileError::Failed),
    }
    exits_cleanly(spawned).await;
}

/// The runner's whole path with a real child, as the compile-worker drives it:
/// admitted, spawned under the filters with its output file, answered — and then
/// killed as the call ends, its slot and what was kept for it given back once it
/// is gone. A runner of one slot answering twice is the slot coming back.
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
        let output = tempfile::tempfile().expect("an output file");
        let (answer, exit) = runner
            .run(
                Some(output.as_fd()),
                kept.clone(),
                |client: CompileChildServiceClient<Ciborium>| async move {
                    compile(&client, b"not a wasm component".to_vec(), vec![]).await
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
