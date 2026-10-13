//! What api does with a worker's cache miss: the composition from L2, or
//! compiled.

use axum::http::StatusCode;

use enclavid_boundary::{Exposed, Untrusted};
use engine_rpc::{
    BundleSource, CallbackServiceUntrusted, CompatToken, CompositionKey, ExecError, RunRequest,
    RunStatus,
};
use hatch_client::SessionMetadata;

use crate::compositions::Composition;
use crate::cwasm_cache;
use crate::init::Unavailable;
use crate::state::AppState;

/// Resolve the compiled bundle for `(composition_key, compat_token)` and run the
/// round with it — what api does with a worker's cache miss. This is the ONE
/// place a compile is triggered: the orchestrator holds no in-memory component
/// cache, so it opens L2 (or compiles) each time the worker's L1 misses.
///
///   * L2 hit: the bundle goes to the worker straight from the cache, a piece at
///     a time, so api never holds the cwasm. An entry found bad on the way — it
///     did not open, or did not hold what its header said — fails this round as
///     any infra fault does, and is dropped, so the next miss compiles afresh.
///     The round is not retried here: the worker answers a bundle it refused as
///     it answers a round that failed after running, so this side cannot know
///     that nothing ran.
///   * L2 miss, and the session's consumer has a compile of the composition under
///     way — a warmup's, or another round's: wait for it to end, then look in L2
///     again. Once: a round that still misses after it compiles too.
///   * L2 miss otherwise: this round compiles it
///     ([`Compositions::compile`](crate::compositions::Compositions::compile)),
///     and the worker and the cache take the cwasm at once as it streams back
///     ([`crate::tee`]), so api never holds it whole here either. Whoever of the
///     same consumer comes for the composition meanwhile waits until the cache
///     has kept it or failed to. A cache that cannot keep it costs the next miss
///     a compile; the round goes on. A cwasm that is not what the compiler named
///     reaches both as an abandoned stream, and neither keeps it.
///
/// The outer error is resolution's, the inner the round's. Compiles are one at a
/// time per composition and consumer in THIS process (see
/// [`crate::compositions`]); another consumer's, or another api's, race just
/// re-reads L2 or double-compiles (idempotent write).
pub(super) async fn run_resolved<C>(
    state: &AppState,
    composition_key: &CompositionKey,
    compat_token: &CompatToken,
    session_id: &str,
    metadata: &SessionMetadata,
    req: Exposed<RunRequest, ()>,
    callbacks: C,
) -> Result<Result<Untrusted<RunStatus, C::Scope>, ExecError>, Unavailable>
where
    C: CallbackServiceUntrusted + Send + Sync + 'static,
    C::Scope: Send,
{
    let compositions = &state.compositions;
    let composition = Composition::of(metadata).ok_or_else(|| {
        safe_logger::debug!("run_resolved: metadata.client missing for {session_id}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let open = || cwasm_cache::open(&compositions.cache_store, composition_key, compat_token);
    let mut hit = open().await;
    let mut compiling = None;
    if hit.is_none() {
        let lock = compositions.compile_lock(composition_key, &composition.consumer);
        match lock.clone().try_acquire_owned() {
            // Nobody of this consumer is compiling it: this round does, and holds
            // the lock while it does, so the next to come waits for this compile.
            Ok(held) => compiling = Some(held),
            // Someone is: wait for that compile to end — once — and look again. A
            // round that still misses compiles too, alongside rather than after
            // whoever took the lock next, so rounds on a composition that does
            // not compile are answered together, not one after another.
            Err(_) => {
                drop(lock.acquire().await);
                hit = open().await;
            }
        }
    }
    if let Some(hit) = hit {
        let cwasm_cache::Hit { source, found_bad } = hit;
        let reply = state.executor.run_with_bundle(req, source, callbacks).await;
        if found_bad.get() {
            cwasm_cache::remove(&compositions.cache_store, composition_key, compat_token).await;
        }
        return Ok(reply);
    }
    let crate::compiler::Compiled {
        meta,
        cwasm_len,
        cwasm_sha256,
        cwasm,
    } = compositions.compile(&composition, session_id).await?;
    let (feed, to_worker, to_cache) = crate::tee::tee(cwasm);
    let source = BundleSource::streamed(cwasm_len, cwasm_sha256, meta.clone(), to_worker)
        .ok_or_else(|| {
            safe_logger::debug!(
                "run_resolved: a bundle past the execute hop's bounds for {session_id}"
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    // The same compile, with the cache's branch of its cwasm.
    let entry = crate::compiler::Compiled {
        meta,
        cwasm_len,
        cwasm_sha256,
        cwasm: to_cache,
    };
    // The compile is over for whoever waits on it once the cache has kept it, or
    // failed to — not once this round has run, which they need not wait for.
    let keep = async {
        cwasm_cache::store(
            &compositions.cache_store,
            composition_key,
            compat_token,
            entry,
        )
        .await;
        drop(compiling);
    };
    let (reply, (), ()) = tokio::join!(
        state.executor.run_with_bundle(req, source, callbacks),
        keep,
        feed,
    );
    Ok(reply)
}
