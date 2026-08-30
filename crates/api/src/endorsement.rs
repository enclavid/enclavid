//! Builds the process's attestation backend.
//!
//! Under `sev-snp` this is the guest's whole bring-up sequence for proving
//! anything about itself, and it runs in an order that matters:
//!
//! ```text
//! 1. read the firmware's report about this launch   no certificate needed
//! 2. refuse to continue if the platform is unfit    no network needed
//! 3. name and fetch the endorsing certificate       through the hatch
//! 4. construct the attestor, which self-checks      mints, then verifies
//! ```
//!
//! Step 2 comes before step 3 deliberately. The channel carrying the report to
//! the guest is authenticated under a key the hypervisor does not hold, so a
//! guest can learn the conditions of its own launch without any certificate at
//! all — and a guest launched somewhere it refuses to run should discover that
//! even when it cannot reach anything.

use std::sync::Arc;

use enclavid_attestation::Attestor;
use enclavid_ra_tls::{MeasurementPolicy, RaTlsError};
use tokio_rustls::rustls::ClientConfig;

#[cfg(not(any(feature = "dev-attestation", feature = "sev-snp")))]
compile_error!(
    "no attestation backend selected: build with `dev-attestation` (the default, a \
     software test key) or `sev-snp` (real hardware attestation)"
);

// Cargo features are additive, so `--features sev-snp` on top of the defaults
// asks for both and silently gets one. Refusing the pair is what keeps a build
// that meant to be attested from carrying a software signer beside the real
// one: the attested build turns the defaults off
// (`--no-default-features --features sev-snp,vsock`).
#[cfg(all(feature = "dev-attestation", feature = "sev-snp"))]
compile_error!(
    "both attestation backends selected: `sev-snp` needs `--no-default-features`, \
     otherwise the default `dev-attestation` comes along with it"
);

#[cfg(all(feature = "sev-snp", not(target_os = "linux")))]
compile_error!(
    "feature `sev-snp` needs /dev/sev-guest, which exists only inside a Linux guest. \
     Build without it for non-Linux dev environments."
);

/// Software test key, no hardware. A quote it mints carries `format: "snp-dev"`,
/// which a production verifier refuses.
///
/// NOT the identity used for fleet legs: `SnpDevAttestor` verifies against its own key,
/// and each process generates a fresh one, so two processes built this way could never
/// attest each other. [`fleet_attestor`] supplies the shared dev identity instead.
#[cfg(feature = "dev-attestation")]
pub async fn build_attestor(_address_out: &str) -> Arc<dyn Attestor> {
    Arc::new(enclavid_attestation::SnpDevAttestor::new_random())
}

/// The identity api presents on a fleet leg, and the one it verifies peers against.
///
/// Separate from [`build_attestor`] under `dev-attestation` because a software backend
/// verifies against its own key: the whole dev fleet has to share one instance or nothing
/// handshakes. Under `sev-snp` there is no such split — the hardware attestor is the
/// process's one identity — but keeping the seam means the fleet leg names what it uses
/// rather than inheriting it.
#[cfg(feature = "dev-attestation")]
fn fleet_attestor(_process: Arc<dyn Attestor>) -> Arc<dyn Attestor> {
    Arc::new(enclavid_attestation::MockAttestor::dev_fleet())
}

#[cfg(feature = "dev-attestation")]
fn fleet_policy() -> MeasurementPolicy {
    MeasurementPolicy::Pinned(vec![
        enclavid_attestation::DEV_FLEET_MEASUREMENT.to_string(),
    ])
}

/// The process's own hardware identity — there is nothing to substitute.
#[cfg(feature = "sev-snp")]
fn fleet_attestor(process: Arc<dyn Attestor>) -> Arc<dyn Attestor> {
    process
}

/// Accepts any measurement, so a completed handshake proves the peer is a genuine
/// SEV-SNP guest at VMPL 0, non-debug, without a migration agent, on platform firmware
/// at or above this build's floor — that is, not an ordinary host process. It does not
/// prove WHICH software the peer runs, because a measurement is a function of an image's
/// contents and no image here carries another's.
#[cfg(feature = "sev-snp")]
fn fleet_policy() -> MeasurementPolicy {
    MeasurementPolicy::AcceptAny
}

/// The RA-TLS client config for a dial to a fleet peer. One place so the identity api
/// presents and the policy it applies are decided together rather than per call site.
pub fn fleet_client_config(attestor: Arc<dyn Attestor>) -> Result<ClientConfig, RaTlsError> {
    enclavid_ra_tls::client_config(fleet_attestor(attestor), fleet_policy())
}

/// Waits between fetch attempts. The certificate is the one thing this guest
/// cannot serve without, so a briefly unreachable key service should not cost a
/// restart — but the wait is bounded, because past that point the platform is
/// the problem and hanging is worse than stopping.
#[cfg(feature = "sev-snp")]
const RETRY_DELAYS: [std::time::Duration; 5] = [
    std::time::Duration::from_secs(1),
    std::time::Duration::from_secs(2),
    std::time::Duration::from_secs(5),
    std::time::Duration::from_secs(15),
    std::time::Duration::from_secs(30),
];

#[cfg(feature = "sev-snp")]
pub async fn build_attestor(address_out: &str) -> Arc<dyn Attestor> {
    use enclavid_attestation::{MILAN_ASK, SnpAttestor, vcek_identity};
    use hatch_client::{
        AuthN, AuthZ, Covert, HatchClient, KdsClient, Replay, VcekRequest, boundary, reason,
    };

    // Steps 1 and 2: what the hardware says about this launch, and whether this
    // build is willing to run here at all.
    let identity = vcek_identity().expect(
        "refusing to run on this platform: the guest's own attestation report was \
         unreadable, or it describes a launch this build does not accept (debug \
         enabled, a migration agent, a VMPL other than 0, or platform firmware \
         below the floor compiled into enclavid-attestation)",
    );

    let request = VcekRequest {
        product_line: identity.product_line.to_string(),
        chip_id: identity.chip_id,
        bootloader_spl: identity.bootloader_spl,
        tee_spl: identity.tee_spl,
        snp_spl: identity.snp_spl,
        microcode_spl: identity.microcode_spl,
    };

    let hatch = HatchClient::new(address_out)
        .await
        .expect("failed to connect to hatch");
    let kds = KdsClient::new(hatch);

    // Step 3. Retrying here rather than host-side: the TEE is the only party
    // that can decide to abort, and it can only decide that if it sees the
    // failures.
    let mut attempt = 0usize;
    let response = loop {
        let exposed = boundary::outbound::to_untrusted(request.clone())
            .vouch_unchecked::<AuthN, _>(reason!(
                "the request names a public certificate — the chip identity and platform \
                 version numbers the host already knows, since it launched this guest"
            ))
            .vouch_unchecked::<AuthZ, _>(reason!(
                "fetching our own endorsement from AMD IS the courier op"
            ))
            .vouch_unchecked::<Covert, _>(reason!(
                "every field is read verbatim from the firmware's report at startup, before \
                 any policy or applicant input exists in this process"
            ));

        match kds.vcek(exposed).await {
            Ok(response) => break response,
            Err(e) if attempt < RETRY_DELAYS.len() => {
                public_logger::warn!(
                    reason!(
                        "a transport error reaching our own endorsement, at startup, before \
                         any policy or applicant input exists in this process"
                    ),
                    "api: endorsement fetch failed ({e}); retrying"
                );
                tokio::time::sleep(RETRY_DELAYS[attempt]).await;
                attempt += 1;
            }
            Err(e) => panic!(
                "could not obtain this chip's endorsement certificate: {e}. Without it \
                 nothing can verify a quote this guest mints, so it will not serve."
            ),
        }
    };

    // Step 4. `AuthN` is closed by the construction itself, not asserted: the
    // constructor verifies the AMD chain against the compiled-in root and then
    // requires the certificate to verify a report this chip has just produced.
    // A certificate for another machine, or for a superseded platform TCB,
    // fails that and never becomes an attestor.
    let attestor = response
        .trust::<AuthN, _, _, _, _>(|response| SnpAttestor::new(MILAN_ASK, &response.certificate))
        .expect(
            "the certificate the hatch returned does not endorse this chip at this \
             platform TCB",
        )
        .trust_unchecked::<AuthZ, _>(reason!(
            "a VCEK is published by AMD to anyone who asks for it; there is no party for \
             whom receiving one is unauthorised"
        ))
        .trust_unchecked::<Replay, _>(reason!(
            "the same construction rejects a stale answer — a certificate for an earlier \
             platform TCB cannot verify the report this chip just signed"
        ))
        .into_inner();

    Arc::new(attestor)
}
