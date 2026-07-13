use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{MethodRouter, delete};

use broker_client::public_session_id;

use crate::state::AppState;

/// Route factory. Public (no auth layer) — see `applicant::router`.
pub(super) fn delete_state() -> MethodRouter<Arc<AppState>> {
    delete(reset)
}

/// DELETE /session/:id/state — drops the encrypted state blob. The state
/// IS the claim (it's sealed under the applicant key), so deleting it puts
/// the session back to "unclaimed" and the next /connect can take it with
/// any key — there is no separate in-memory claim to clear.
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
    // The `u64` we discard is the host's claim of how many state
    // entries were removed (0 = was already absent, 1 = wiped).
    // Available for observability if/when we want to distinguish "real
    // reset" from "no-op reset" — not used today. Trust-wise: a lying
    // host can fake either direction; the value is informational, not
    // a security signal. Confidentiality holds via encryption with the
    // applicant key the user is now discarding. Metadata + status
    // remain — only the state field is cleared, so the next /connect
    // can claim the session with a fresh key.
    // Returned deletion count is host-supplied; we drop it without
    // explicit peeling — purely informational, no security gate.
    state
        .session_store
        .delete(public_session_id(&session_id))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Drop the TEE-side pull-through cache for this session (the broker's
    // `delete` above already purged the sealed backing `session:{id}:media`).
    state.media_cache.purge(&session_id).await;
    Ok(StatusCode::NO_CONTENT)
}
