//! Integration: the compile-worker's disposable per-compile CHILD process.
//!
//! Proves the compiler's use of the shared `engine-supervisor` — spawn a REAL
//! `compile-child`, serve one `CompilerService::compile`, fail safe, exit. The
//! happy-path compile itself is covered by the lib's `compile_to_parts` tests,
//! and a real (multi-MiB) `CompiledBundle` crossing the engine-supervisor socketpair is
//! covered by the executor's `spawned_child_primes_runs_relays_then_exits`
//! integration test (same engine-supervisor, same transport).
//!
//! Gated on `worker` so `CARGO_BIN_EXE_compile-child` exists and `engine-rpc` /
//! `engine-supervisor` / `remoc` are linked. Run with `--features worker`.
#![cfg(feature = "worker")]

use std::path::Path;
use std::time::Duration;

use remoc::codec::Ciborium;

use engine_rpc::{CompileError, CompilerService, CompilerServiceClient};

/// Spawn the real `compile-child` over a socketpair (via engine-supervisor) the way the
/// compile-worker supervisor does, and return the child + its service client.
async fn spawn() -> (tokio::process::Child, CompilerServiceClient<Ciborium>) {
    let exe = env!("CARGO_BIN_EXE_compile-child");
    engine_supervisor::spawn_and_connect::<CompilerServiceClient<Ciborium>>(Path::new(exe))
        .await
        .expect("spawn compile-child")
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

/// Fail-safe: a compile-child that dies mid-flight makes the RPC ERROR
/// (disconnect), not hang — so the supervisor maps it to a `CompileError` and api
/// surfaces a config-resolution failure rather than wedging.
#[tokio::test]
async fn dead_compile_child_surfaces_error_not_hang() {
    let (mut child, client) = spawn().await;
    child.kill().await.expect("kill compile-child");

    let res = tokio::time::timeout(Duration::from_secs(10), client.compile(b"x".to_vec(), vec![]))
        .await
        .expect("call to a dead child must resolve (error), not hang");
    assert!(res.is_err(), "compile to a dead child must error, not return a bundle");
}
