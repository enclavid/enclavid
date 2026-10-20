//! State for the client-facing API listener (POST /sessions etc.).
//!
//! Distinct from `AppState` (applicant-facing API): clients are authorized
//! through the hatch (`AuthClient`), sessions are created here with attestation
//! quotes; the applicant flow uses BearerKey and continues from a session that
//! this listener already created.
//!
//! `compositions` is shared with `AppState`: a warmup asked for here
//! compiles through the same compile locks and into the same L2 a round
//! looks in. `session_store` is also shared so writes from this side
//! (metadata, status) and reads from the applicant side (state) hit the
//! same backing service.

use std::sync::Arc;

use enclavid_attestation::Attestor;
use hatch_client::{AuthClient, Link};
use storage_client::SessionStore;

use crate::boundary::Hatch;
use crate::compositions::Compositions;

pub struct ClientState {
    pub auth: AuthClient<Hatch>,
    pub session_store: Arc<SessionStore>,
    pub attestor: Arc<dyn Attestor>,
    /// The applicant surface's, shared: a warmup has a session's composition
    /// compiled and kept before any round asks for it.
    pub compositions: Arc<Compositions>,
    /// The longest a pull may take, which a session's own pull deadline is
    /// held under.
    pub pull_deadline: std::time::Duration,
}

impl ClientState {
    /// `authorize_deadline` is how long the hatch has to answer each
    /// authorization, over `hatch`.
    pub fn new(
        hatch: Arc<dyn Link<Hatch>>,
        session_store: Arc<SessionStore>,
        attestor: Arc<dyn Attestor>,
        compositions: Arc<Compositions>,
        authorize_deadline: std::time::Duration,
        pull_deadline: std::time::Duration,
    ) -> Self {
        Self {
            auth: AuthClient::new(hatch, authorize_deadline),
            session_store,
            attestor,
            compositions,
            pull_deadline,
        }
    }
}
