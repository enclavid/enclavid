//! What this role uses to check api, and what it does not check.
//!
//! **There is no pin here, and its absence is the design.** This role does not
//! decide which api build a caller may be served by; the caller does, per
//! request, having first verified this role's own attestation. See
//! `crate::upstream` for the delegation that rests on.
//!
//! What that leaves this module is one thing: an attestor, which is what
//! VERIFIES api's quote during the handshake. It is needed even though this end
//! presents nothing, because on a leg where only one end is asked for a
//! certificate, verifying is the direction that carries the weight.
//!
//! Minting is `mint_only_across_parts`: this guest has no egress, so it cannot
//! fetch the certificate that would endorse its own report — and it does not
//! need one to verify. api holds an endorsement, so the quote it presents
//! CARRIES its chain, and a verifier with none of its own reads that chain and
//! checks it to the compiled-in AMD root.
//!
//! **Across parts**, because this role fronts api instances on other machines.
//! The leaves refuse a peer on another part; this role cannot, and the
//! constructor spells out what that gives up — see
//! `SnpAttestor::mint_only_across_parts`. Everything else a peer is held to
//! stays: the chain, the VCEK issued to the chip the report names, the platform
//! posture, the TCB floor, and the exact measurement the caller asked for.

use std::sync::Arc;

use enclavid_attestation::Attestor;

/// This process's attestation backend.
#[cfg(feature = "sev-snp")]
pub fn attestor() -> Arc<dyn Attestor> {
    Arc::new(
        enclavid_attestation::SnpAttestor::mint_only_across_parts().unwrap_or_else(|e| {
            safe_logger::debug!("{e}");
            safe_logger::error_and_panic!(
                "gateway: cannot present an attested identity — /dev/sev-guest is absent, or this \
                 guest was launched in a posture this build refuses (VMPL, debug, migration \
                 agent, TCB floor). Stopping.",
                safe_logger::reason!("a constant reporting a platform state the host provisioned")
            )
        }),
    )
}

/// The dev fleet's one shared software identity. It proves a peer links this
/// source tree and nothing about where it runs — which is all a fleet without
/// hardware can say.
#[cfg(feature = "dev-attestation")]
pub fn attestor() -> Arc<dyn Attestor> {
    Arc::new(enclavid_attestation::MockAttestor::dev_fleet())
}
