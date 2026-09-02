//! Integration: the compile-worker's disposable per-compile CHILD process.
//!
//! Proves the compiler's use of the shared `engine-supervisor` — spawn a REAL
//! `engine-compiler-child`, serve one `CompilerService::compile`, fail safe, exit. The
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

use std::time::Duration;

use remoc::codec::Ciborium;

use engine_rpc::{CompileError, CompilerService, CompilerServiceClient};

/// Spawn the real `engine-compiler-child` over a socketpair (via engine-supervisor) the way the
/// compile-worker supervisor does, and return the child + its service client.
async fn spawn() -> (tokio::process::Child, CompilerServiceClient<Ciborium>) {
    spawn_with(None).await
}

async fn spawn_with(
    hardening: Option<engine_supervisor::Hardening>,
) -> (tokio::process::Child, CompilerServiceClient<Ciborium>) {
    let exe = xtask::child_binary("engine-compiler-child");
    engine_supervisor::spawn_and_connect::<CompilerServiceClient<Ciborium>>(&exe, &[], hardening)
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
        client.compile(b"not a wasm component".to_vec(), vec![]),
    )
    .await
    .expect("compile must not hang");
    let CompileError(msg) = match outcome {
        Ok(_) => panic!("garbage policy must fail to compile, got a bundle"),
        Err(e) => e,
    };
    assert!(!msg.is_empty(), "CompileError should carry a message");

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
        client.compile(b"x".to_vec(), vec![]),
    )
    .await
    .expect("call to a dead child must resolve (error), not hang");
    assert!(
        res.is_err(),
        "compile to a dead child must error, not return a bundle"
    );
}

/// The production hardening must not stop a child from working.
///
/// The egress filter denies sockets, every open for writing, and `ioctl` — and it
/// is installed between fork and exec, so it governs the whole of the child's
/// startup: the loader (none: static musl), the tokio runtime coming up, the
/// remoc handshake, and Cranelift. Nothing had ever spawned a real child WITH a
/// `Hardening` in a test, so "the filter is not too broad" was an argument rather
/// than a measurement — and denying a syscall the runtime needs would fail at
/// exec, in production, on the first round.
///
/// Linux-only: the filter is a no-op elsewhere, so the assertion would be vacuous
/// on a dev host.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_child_starts_and_serves_under_the_production_filter() {
    let hardening = engine_supervisor::Hardening {
        seccomp_egress: true,
        address_space: None,
    };
    let (mut child, client) = spawn_with(Some(hardening)).await;

    // Reaching a `CompileError` at all proves the child got through exec, stood a
    // runtime up, completed the handshake and ran Cranelift far enough to reject
    // the input.
    let outcome = tokio::time::timeout(
        Duration::from_secs(30),
        client.compile(b"not a wasm component".to_vec(), vec![]),
    )
    .await
    .expect("a hardened child must not hang");
    match outcome {
        Ok(_) => panic!("garbage policy must fail to compile, got a bundle"),
        Err(CompileError(msg)) => assert!(!msg.is_empty(), "CompileError should carry a message"),
    }

    drop(client);
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("hardened child must exit after its client is dropped")
        .expect("wait for child");
    assert!(status.success(), "child exits cleanly, got {status:?}");
}
