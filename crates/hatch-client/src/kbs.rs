//! Client for the hatch's KBS relay.
//!
//! api reaches an artifact-key broker (KBS) through the hatch. This is the thin
//! transport primitive: it forwards ONE handshake/key-release leg and returns
//! the broker's answer. The attestation state machine (RCAR: auth → challenge →
//! attestation → resource), the ephemeral `TeeKeyPair` and the JWE unwrap live
//! one layer up in the api keyprovider — this client just couriers bytes.
//!
//! Trust model: the broker's answer can be dropped or stalled on the way. The
//! released key is JWE-wrapped to api's per-pull ephemeral key, bound into the
//! handshake's report data, so only the enclave can unwrap it and an answer from
//! another pull opens under none; that it is the layer's key is settled where the
//! layer ends, by its HMAC against the options its pinned manifest carries. The
//! caller MUST verify via `.trust_with(AuthN::Verified, …)` at the keyprovider
//! layer.

use std::marker::PhantomData;
use std::sync::Arc;

use enclavid_boundary::{Exposed, Receives, Untrusted};
use hatch_rpc::{KbsRequest, KbsResponse, RemoteHatchCalls};

use crate::error::BridgeError;
use crate::link::{Link, hatch, within};

/// How long the hatch has to answer ONE relayed leg, unless the host says
/// otherwise (api's `kbs-deadline-secs` setting).
///
/// Per leg, not per handshake: a full RCAR exchange is three of these, so the
/// worst case a caller can wait is three times this. Bounded because a relay is
/// reached from api's compile path, which can run inside an applicant round — an
/// unbounded wait here parks a round that is holding that round's captures.
pub const DEFAULT_RELAY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

/// Client for the hatch's KBS relay, held at end `B` of the hatch leg, whose
/// declaration says what is open on each value that crosses it.
pub struct KbsClient<B> {
    link: Arc<dyn Link<B>>,
    deadline: std::time::Duration,
    _end: PhantomData<fn() -> B>,
}

impl<B> Clone for KbsClient<B> {
    fn clone(&self) -> Self {
        Self {
            link: self.link.clone(),
            deadline: self.deadline,
            _end: PhantomData,
        }
    }
}

impl<B> KbsClient<B> {
    /// A client whose every relayed leg the hatch has `deadline` to answer.
    pub fn new(link: Arc<dyn Link<B>>, deadline: std::time::Duration) -> Self {
        Self {
            link,
            deadline,
            _end: PhantomData,
        }
    }
}

impl<B: RemoteHatchCalls + 'static> KbsClient<B> {
    /// Forward one KBS leg through the hatch. `req` arrives answered, as an
    /// authorization's does; the response comes back open on what `B` left open
    /// on it — the keyprovider verifies it by unwrapping the JWE with the
    /// ephemeral key. A failure comes back as `BridgeError`, from an error `B`'s
    /// declaration answered in full.
    pub async fn relay(
        &self,
        req: Exposed<KbsRequest, (), B>,
    ) -> Result<Untrusted<KbsResponse, <B as Receives<KbsResponse>>::Open, B>, BridgeError> {
        let hatch = hatch(self.link.as_ref())?;
        within(self.deadline, "kbs relay", async {
            hatch
                .kbs(req)
                .await
                .map_err(|e| BridgeError::Transport(e.to_string()))
        })
        .await
    }
}
