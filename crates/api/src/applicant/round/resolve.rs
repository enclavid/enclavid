//! What api does with a worker's cache miss on a round: the composition from L2,
//! or compiled — see [`Compositions::with_bundle`](crate::compositions::Compositions::with_bundle).

use axum::http::StatusCode;

use enclavid_boundary::{Exposed, Untrusted};
use engine_rpc::{
    CallbackServiceUntrusted, CompatToken, CompositionKey, ExecError, RunRequest, RunStatus,
};
use session_types::SessionMetadata;

use crate::compositions::Composition;
use crate::init::Unavailable;
use crate::state::AppState;

/// Resolve the compiled bundle for `(composition_key, compat_token)` and run the
/// round with it. The outer error is resolution's, the inner the round's.
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
    let composition = Composition::of(metadata).ok_or_else(|| {
        safe_logger::debug!("run_resolved: metadata.client missing for {session_id}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    state
        .compositions
        .with_bundle(
            &composition,
            composition_key,
            compat_token,
            session_id,
            |source| state.executor.run_with_bundle(req, source, callbacks),
        )
        .await
}
