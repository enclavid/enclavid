//! Micro-bench: how long does spawning + handshaking a fresh `session-child`
//! take? This isolates the `spawn` phase (exec + dyld of the ~12 MiB
//! wasmtime-linked binary + the child's `Engine::new` + the remoc hello) — the
//! ONLY thing the fork-zygote (Stage B) would remove. It needs NO fixtures and
//! NO Cranelift (a bin pulls no dev-deps), so it builds fast in a Linux container
//! to answer the Stage-B gate: is exec cheap on Linux (the fork not worth its
//! unsafe) or expensive (worth it)?
//!
//! Usage: `spawn-bench [session-child-path] [iterations]`
//! (defaults: sibling `session-child`, 30 iterations).

use std::time::{Duration, Instant};

use engine_rpc::ChildServiceClient;
use engine_supervisor::spawn_and_connect;
use remoc::codec::Ciborium;

#[tokio::main]
async fn main() {
    let exe = std::env::args().nth(1).map(std::path::PathBuf::from).unwrap_or_else(|| {
        let mut p = std::env::current_exe().expect("current_exe");
        p.set_file_name("session-child");
        p
    });
    let iters: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(30);

    if !exe.exists() {
        panic!("session-child not found at {} (pass its path as arg1)", exe.display());
    }
    eprintln!("spawn-bench: exe={}, iters={iters}", exe.display());

    // Warm the page cache / first-run outliers.
    for _ in 0..3 {
        let (mut child, client) =
            spawn_and_connect::<ChildServiceClient<Ciborium>>(&exe, &[]).await.expect("spawn");
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    }

    let mut times = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        let (mut child, client) =
            spawn_and_connect::<ChildServiceClient<Ciborium>>(&exe, &[]).await.expect("spawn");
        // spawn_and_connect returns after exec + the child's Engine::new + the
        // remoc handshake (it recv'd the child's service client) — exactly the
        // `spawn` phase the zygote's fork replaces.
        times.push(t.elapsed());
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
    }

    times.sort();
    let sum: Duration = times.iter().sum();
    let avg = sum / times.len() as u32;
    let min = times.first().unwrap();
    let p50 = times[times.len() / 2];
    let max = times.last().unwrap();
    println!(
        "\nspawn+handshake over {iters}: avg {avg:?}  min {min:?}  p50 {p50:?}  max {max:?}"
    );
}
