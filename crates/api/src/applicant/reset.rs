use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{MethodRouter, delete};

use crate::state::AppState;

/// Route factory. Public (no auth layer) — see `applicant::router`.
pub(super) fn delete_state() -> MethodRouter<Arc<AppState>> {
    delete(reset)
}

/// DELETE /session/:id/state — drops the encrypted state blob and the
/// in-memory key claim. After this the session is back to "unclaimed",
/// and the next /connect can take it with any key.
///
/// No auth: the legitimate applicant who lost their key cannot prove
/// ownership cryptographically (state is encrypted with the lost key).
/// Knowledge of `session_id` (≥128 bits entropy, distributed only to the
/// applicant + bank) is the trust gate. An attacker with `session_id`
/// can already grief the session via /connect front-running, so DELETE
/// adds no new attack surface — it just gives the legitimate user a
/// recovery path.
async fn reset(
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, StatusCode> {
    // The `u64` we discard is the host's claim of how many keys were
    // removed (0 = was already absent, 1 = wiped). Available for
    // observability if/when we want to distinguish "real reset" from
    // "no-op reset" — not used today. Trust-wise: a lying host can
    // fake either direction; the value is informational, not a
    // security signal. Confidentiality holds via encryption with the
    // applicant key the user is now discarding.
    state
        .state_store
        .delete(&session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .trust_unchecked();
    state.applicant_keys.invalidate(&session_id).await;
    Ok(StatusCode::NO_CONTENT)
}
