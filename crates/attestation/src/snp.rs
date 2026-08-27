//! Production SEV-SNP backend.
//!
//! Mints by asking the AMD Secure Processor through `/dev/sev-guest`; verifies
//! against a trust root that is a constant in this crate. Nothing about the
//! trust decision is read from the host, so which AMD root — and which platform
//! firmware floor — a build accepts is itself part of what that build's
//! measurement attests.
//!
//! A quote carries the firmware's report bytes verbatim plus the leaf (VCEK)
//! and intermediate (ASK) certificates the attestor was built with. Only the
//! ARK is pinned: an ASK is legitimate exactly when the pinned ARK signs it, so
//! carrying it in the quote costs nothing and survives an AMD intermediate
//! rotation without a rebuild. The same reasoning is why the endorsement chain
//! may travel any path at all — these are public certificates, and a forged one
//! fails against the root the verifier already holds.
//!
//! `verify_quote` is a free function: verification needs no local hardware, so
//! a verifier outside a guest uses it without opening a device. Minting lives
//! in the `mint` module below, which exists only where the guest device does.

use serde::{Deserialize, Serialize};
use sev::certs::snp::{Certificate, Chain, Verifiable, builtin, ca};
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::TcbVersion;
use sev::parser::ByteParser;

use crate::{AttestationError, Quote, ReportData};

/// Wire discriminator for this backend.
const SNP_FORMAT: &str = "sev-snp";

/// The VMPL a report must be requested at, and the level this guest runs at. A
/// report minted at a higher VMPL describes a *less* privileged context than
/// the one holding the key being bound, so honouring one would let that
/// context speak for the enclave.
const REQUIRED_VMPL: u32 = 0;

/// Report layouts below version 2 predate the field offsets this parser reads.
/// Later versions (3, 5) only append, so the floor is a minimum, not a match.
const MIN_REPORT_VERSION: u32 = 2;

/// Platform-firmware floor. AMD derives a VCEK per TCB and keeps endorsing
/// superseded ones, so without a floor a host running firmware with known
/// defects still presents a chain that verifies all the way to the root.
/// Raising it means a rebuild, which is the point: the floor a release
/// enforces travels inside that release's measurement.
const MIN_TCB: TcbFloor = TcbFloor {
    bootloader: 4,
    tee: 0,
    snp: 29,
    microcode: 222,
};

/// `KeyInfo::signing_key` value for a VCEK. A VLEK is loaded by the platform
/// owner rather than derived from the chip, which is a weaker statement about
/// *which machine* signed — so it is not accepted here.
const SIGNING_KEY_VCEK: u32 = 0;

/// The AMD product line whose root is pinned below. The two move together: a
/// chain from another generation would not verify against this ARK anyway, and
/// AMD's key service names its certificates by the same string.
pub const PRODUCT_LINE: &str = "Milan";

/// AMD's Milan intermediate, as shipped with the `sev` crate. Re-exported so a
/// caller assembling an attestor needs no `sev` dependency of its own — only
/// the VCEK varies per machine, and only it has to be obtained.
pub const MILAN_ASK: &[u8] = builtin::milan::ASK;

/// The four security version numbers that make up a platform TCB.
struct TcbFloor {
    bootloader: u8,
    tee: u8,
    snp: u8,
    microcode: u8,
}

impl TcbFloor {
    /// Every component must independently meet the floor — a platform cannot
    /// offset an old component against a new one.
    fn accepts(&self, tcb: &TcbVersion) -> bool {
        tcb.bootloader >= self.bootloader
            && tcb.tee >= self.tee
            && tcb.snp >= self.snp
            && tcb.microcode >= self.microcode
    }
}

/// Quote payload for `format: "sev-snp"`. `report` is what the firmware
/// returned, byte for byte — re-encoding it would change the bytes the VCEK
/// signature covers.
#[derive(Serialize, Deserialize)]
struct SnpEnvelope {
    #[serde(with = "serde_bytes")]
    report: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ask_der: Vec<u8>,
    #[serde(with = "serde_bytes")]
    vcek_der: Vec<u8>,
}

/// The trust root: AMD's Milan root key, compiled in from the `sev` crate's
/// built-in copy. A chain rooted anywhere else — including a self-signed
/// forgery the host presents as an ARK — has nothing to verify against.
fn pinned_ark() -> Result<Certificate, AttestationError> {
    builtin::milan::ark().map_err(|e| AttestationError::Backend(format!("pinned Milan ARK: {e}")))
}

/// Checks that read the report's own claims about the platform it ran on.
/// Runs only after the signature has been verified — until then these fields
/// are the host's to write.
fn check_report_policy(report: &AttestationReport) -> Result<(), AttestationError> {
    let reject = |m: String| Err(AttestationError::PolicyRejected(m));

    if report.version < MIN_REPORT_VERSION {
        return reject(format!("report version {}", report.version));
    }
    if report.vmpl != REQUIRED_VMPL {
        return reject(format!("report minted at VMPL {}", report.vmpl));
    }
    // A debug-enabled guest lets the hypervisor read its memory, which makes
    // every other guarantee here decorative.
    if report.policy.debug_allowed() {
        return reject("guest policy allows debug".into());
    }
    // A migration agent can move guest state to another machine, which moves
    // it out from under the measurement this quote binds.
    if report.policy.migrate_ma_allowed() {
        return reject("guest policy allows a migration agent".into());
    }
    if report.key_info.signing_key() != SIGNING_KEY_VCEK {
        return reject(format!(
            "report signed by key type {} rather than a VCEK",
            report.key_info.signing_key()
        ));
    }
    // Both TCBs, for different reasons. `reported_tcb` is the one the signing
    // key is derived at — what the report says the platform is now. `launch_tcb`
    // is what was in force when this guest was created, and therefore what
    // established its memory encryption and its measurement. The host can raise
    // the platform TCB under a guest that is already running, so checking only
    // the former accepts an enclave that superseded firmware brought up.
    for (which, tcb) in [
        ("reported", &report.reported_tcb),
        ("launch", &report.launch_tcb),
    ] {
        if !MIN_TCB.accepts(tcb) {
            return reject(format!(
                "{which} platform TCB below floor: bl={} tee={} snp={} ucode={}",
                tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode
            ));
        }
    }
    Ok(())
}

/// Verify a `sev-snp` quote: the AMD chain signs the report, the report was
/// minted under an acceptable platform posture, and it binds `expected`.
///
/// Needs no hardware — a verifier outside a guest calls this directly.
pub fn verify_quote(quote: &Quote, expected: &ReportData) -> Result<(), AttestationError> {
    if quote.format != SNP_FORMAT {
        return Err(AttestationError::UnsupportedFormat(quote.format.clone()));
    }
    let envelope: SnpEnvelope = ciborium::from_reader(quote.quote_blob.as_slice())
        .map_err(|e| AttestationError::InvalidQuote(format!("cbor envelope: {e}")))?;
    let report = AttestationReport::from_bytes(&envelope.report)
        .map_err(|e| AttestationError::InvalidQuote(format!("report bytes: {e}")))?;

    // Authenticate before reading anything the report says. The ARK is ours;
    // only the two certificates below it come from the peer.
    let chain = Chain {
        ca: ca::Chain {
            ark: pinned_ark()?,
            ask: Certificate::from_der(&envelope.ask_der)
                .map_err(|e| AttestationError::InvalidQuote(format!("ASK: {e}")))?,
        },
        vek: Certificate::from_der(&envelope.vcek_der)
            .map_err(|e| AttestationError::InvalidQuote(format!("VCEK: {e}")))?,
    };
    let vcek = (&chain)
        .verify()
        .map_err(|e| AttestationError::InvalidQuote(format!("certificate chain: {e}")))?;
    (vcek, &report)
        .verify()
        .map_err(|_| AttestationError::BadSignature)?;

    check_report_policy(&report)?;

    if report.report_data[..32] != expected.hash() {
        return Err(AttestationError::BindingMismatch);
    }
    // Minting fills the low half and leaves the rest zero. Anything in the
    // upper half is a channel that rides inside a signed, trusted structure.
    if report.report_data[32..] != [0u8; 32] {
        return Err(AttestationError::PolicyRejected(
            "report_data carries data outside the binding".into(),
        ));
    }
    // Callers pin `quote.measurement`; the signature covers `report.measurement`.
    // Without this, a peer presents a genuine report and advertises someone
    // else's measurement alongside it.
    if quote.measurement != hex::encode(report.measurement) {
        return Err(AttestationError::MeasurementMismatch);
    }
    Ok(())
}

/// Minting talks to the AMD Secure Processor through `/dev/sev-guest`, which
/// exists only inside a Linux guest. Verification does not, so it stays outside
/// this module and a verifier on any platform links the crate without it.
#[cfg(target_os = "linux")]
mod mint {
    use std::sync::Mutex;

    use sev::certs::snp::Certificate;
    use sev::firmware::guest::{AttestationReport, Firmware};
    use sev::parser::ByteParser;

    use super::{
        PRODUCT_LINE, REQUIRED_VMPL, SNP_FORMAT, SnpEnvelope, check_report_policy, verify_quote,
    };
    use crate::{AttestationError, Attestor, Quote, ReportData};

    /// What AMD's key service needs in order to name the certificate that
    /// endorses this chip: the product line, the chip identity, and the four
    /// security version numbers of the TCB the signing key is derived at.
    pub struct VcekIdentity {
        pub product_line: &'static str,
        pub chip_id: String,
        pub bootloader_spl: u8,
        pub tee_spl: u8,
        pub snp_spl: u8,
        pub microcode_spl: u8,
    }

    /// Read the endorsement parameters straight out of the firmware.
    ///
    /// This needs no certificate. The guest-request channel is authenticated
    /// under a key the hypervisor does not hold, so a guest can read the report
    /// *about itself* long before it has anything to prove to anyone else —
    /// and the report is the only channel by which the hardware tells it the
    /// conditions of its own launch.
    ///
    /// That is why the platform posture is checked here rather than later: a
    /// guest launched in a configuration this build refuses stops now, instead
    /// of after a round trip to a key service that would have succeeded.
    pub fn vcek_identity() -> Result<VcekIdentity, AttestationError> {
        let mut firmware = Firmware::open()
            .map_err(|e| AttestationError::Backend(format!("open /dev/sev-guest: {e}")))?;
        let report_bytes = firmware
            .get_report(None, Some([0u8; 64]), Some(REQUIRED_VMPL))
            .map_err(|e| AttestationError::Backend(format!("guest report request: {e}")))?;
        let report = AttestationReport::from_bytes(&report_bytes).map_err(|e| {
            AttestationError::Backend(format!("firmware returned an unparsable report: {e}"))
        })?;

        check_report_policy(&report)?;

        // A platform running with MASK_CHIP_ID publishes no chip identity, so
        // the certificate endorsing it cannot be named. Saying so here beats
        // querying for 128 zero characters and reporting the not-found.
        if report.chip_id == [0u8; 64] {
            return Err(AttestationError::PolicyRejected(
                "platform masks its chip identity, so its endorsement cannot be named".into(),
            ));
        }

        Ok(VcekIdentity {
            product_line: PRODUCT_LINE,
            chip_id: hex::encode(report.chip_id),
            // `reported_tcb`, not `current_tcb`: this is the TCB the signing
            // key is derived at, and the one `check_report_policy` gates.
            bootloader_spl: report.reported_tcb.bootloader,
            tee_spl: report.reported_tcb.tee,
            snp_spl: report.reported_tcb.snp,
            microcode_spl: report.reported_tcb.microcode,
        })
    }

    /// Ask the chip for a 32-byte secret bound to this launch.
    ///
    /// The secret is derived inside the AMD Secure Processor from a seed fused
    /// into the part; nothing supplies it and nothing can be asked for it from
    /// outside. Which is the point — a key handed in by the host is a key the
    /// host has.
    ///
    /// What the derivation mixes in decides who else can reproduce it:
    ///
    ///   * MEASUREMENT ties the key to this exact image, so a different release
    ///     derives a different key and cannot read what this one sealed. That
    ///     costs continuity across releases and buys the property the whole
    ///     design rests on — a compromised later version inherits no history.
    ///   * GUEST_POLICY ties it to the launch posture, so the same image
    ///     relaunched with debugging enabled derives a different key. The
    ///     platform check already refuses to run that way; this makes the data
    ///     unreadable even if it did.
    ///
    /// TCB_VERSION is deliberately NOT mixed. Platform firmware updates are
    /// routine security hygiene, and binding to them would make every update
    /// discard sealed state — a mechanism that punishes patching. The floor in
    /// `check_report_policy` is what keeps old firmware out instead.
    pub fn derive_seal_key() -> Result<[u8; 32], AttestationError> {
        use sev::firmware::guest::{DerivedKey, GuestFieldSelect};

        let mut firmware = Firmware::open()
            .map_err(|e| AttestationError::Backend(format!("open /dev/sev-guest: {e}")))?;

        // The mitigation vector in force at launch, which the firmware requires
        // for this request and which the derivation then also binds.
        let report_bytes = firmware
            .get_report(None, Some([0u8; 64]), Some(REQUIRED_VMPL))
            .map_err(|e| AttestationError::Backend(format!("guest report request: {e}")))?;
        let report = AttestationReport::from_bytes(&report_bytes).map_err(|e| {
            AttestationError::Backend(format!("firmware returned an unparsable report: {e}"))
        })?;

        let mut fields = GuestFieldSelect(0);
        fields.set_measurement(true);
        fields.set_guest_policy(true);

        // Root key: the chip-derived VCEK, not the migration key — a migration
        // key would let a migration agent reproduce this secret elsewhere.
        let request = DerivedKey::new(
            false,
            fields,
            REQUIRED_VMPL,
            0,
            0,
            Some(report.launch_mit_vector.unwrap_or(0)),
        );
        firmware
            .get_derived_key(None, request)
            .map_err(|e| AttestationError::Backend(format!("derive sealing key: {e}")))
    }

    /// Prod SEV-SNP attestor. Holds the guest device open for minting and the
    /// endorsement chain to attach to each quote; verifying uses none of its
    /// state.
    pub struct SnpAttestor {
        firmware: Mutex<Firmware>,
        ask_der: Vec<u8>,
        vcek_der: Vec<u8>,
        /// The TCB the held endorsement covers, as `(bootloader, tee, snp,
        /// microcode)`.
        endorsed_tcb: (u8, u8, u8, u8),
    }

    impl SnpAttestor {
        /// `vcek_der` endorses this exact chip at its current TCB; `ask_der` is
        /// AMD's intermediate. Both are public certificates whose authenticity
        /// is settled at verify time against the compiled-in root, so how the
        /// caller obtained them does not change what a quote proves. Either
        /// encoding is accepted.
        ///
        /// Opens the device and mints-then-verifies one throwaway quote before
        /// returning, so a guest holding the wrong chip's endorsement — or none
        /// at all — fails at startup instead of at its first handshake.
        pub fn new(ask_der: &[u8], vcek_der: &[u8]) -> Result<Self, AttestationError> {
            let identity = vcek_identity()?;
            let firmware = Firmware::open()
                .map_err(|e| AttestationError::Backend(format!("open /dev/sev-guest: {e}")))?;
            let attestor = Self {
                firmware: Mutex::new(firmware),
                ask_der: normalise_cert(ask_der, "ASK")?,
                vcek_der: normalise_cert(vcek_der, "VCEK")?,
                endorsed_tcb: (
                    identity.bootloader_spl,
                    identity.tee_spl,
                    identity.snp_spl,
                    identity.microcode_spl,
                ),
            };

            let probe = ReportData::session(String::new(), String::new());
            let quote = attestor.mint(&probe)?;
            verify_quote(&quote, &probe)?;
            Ok(attestor)
        }
    }

    /// AMD's key service serves DER while other sources carry PEM. Normalising
    /// once at construction leaves the wire format with one encoding to parse,
    /// and rejects a malformed certificate before it can reach a peer.
    fn normalise_cert(bytes: &[u8], what: &str) -> Result<Vec<u8>, AttestationError> {
        let cert = Certificate::from_der(bytes)
            .or_else(|_| Certificate::from_pem(bytes))
            .map_err(|e| AttestationError::Backend(format!("parse supplied {what}: {e}")))?;
        cert.to_der()
            .map_err(|e| AttestationError::Backend(format!("re-encode {what}: {e}")))
    }

    impl Attestor for SnpAttestor {
        fn mint(&self, data: &ReportData) -> Result<Quote, AttestationError> {
            let mut report_data = [0u8; 64];
            report_data[..32].copy_from_slice(&data.hash());

            let report_bytes = {
                let mut fw = self
                    .firmware
                    .lock()
                    .map_err(|_| AttestationError::Backend("guest device lock poisoned".into()))?;
                fw.get_report(None, Some(report_data), Some(REQUIRED_VMPL))
                    .map_err(|e| AttestationError::Backend(format!("guest report request: {e}")))?
            };

            let report = AttestationReport::from_bytes(&report_bytes).map_err(|e| {
                AttestationError::Backend(format!("firmware returned an unparsable report: {e}"))
            })?;

            // A platform firmware update changes the TCB the signing key is
            // derived at, which retires the endorsement this process holds.
            // Without this the guest keeps minting quotes carrying a superseded
            // certificate and the only signal is a chain failure at the far end.
            let tcb = &report.reported_tcb;
            if (tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode) != self.endorsed_tcb {
                let (bl, tee, snp, ucode) = self.endorsed_tcb;
                return Err(AttestationError::PolicyRejected(format!(
                    "platform TCB moved under this process; the held endorsement covers \
                     bl={bl} tee={tee} snp={snp} ucode={ucode}"
                )));
            }

            let envelope = SnpEnvelope {
                report: report_bytes,
                ask_der: self.ask_der.clone(),
                vcek_der: self.vcek_der.clone(),
            };
            let mut quote_blob = Vec::new();
            ciborium::into_writer(&envelope, &mut quote_blob)
                .map_err(|e| AttestationError::Backend(format!("encode quote: {e}")))?;

            Ok(Quote {
                format: SNP_FORMAT.to_string(),
                quote_blob,
                measurement: hex::encode(report.measurement),
            })
        }

        fn verify(&self, quote: &Quote, expected: &ReportData) -> Result<(), AttestationError> {
            verify_quote(quote, expected)
        }
    }
}

#[cfg(target_os = "linux")]
pub use mint::{SnpAttestor, VcekIdentity, derive_seal_key, vcek_identity};

#[cfg(test)]
mod tests {
    use super::*;

    fn tcb(bootloader: u8, tee: u8, snp: u8, microcode: u8) -> TcbVersion {
        TcbVersion {
            fmc: None,
            bootloader,
            tee,
            snp,
            microcode,
        }
    }

    /// A report shaped like the one this stack produces: version 5 on a Milan
    /// part, VMPL 0, debug off, no migration agent, VCEK-signed, and the
    /// platform TCB the hardware currently reports.
    fn acceptable_report() -> AttestationReport {
        let mut report = AttestationReport::default();
        report.version = 5;
        report.vmpl = REQUIRED_VMPL;
        report.policy.set_smt_allowed(true);
        report.reported_tcb = tcb(4, 0, 29, 222);
        report.launch_tcb = tcb(4, 0, 29, 222);
        report.cpuid_fam_id = Some(25);
        report.cpuid_mod_id = Some(1);
        report.cpuid_step = Some(1);
        report
    }

    #[test]
    fn accepts_this_stacks_report_shape() {
        check_report_policy(&acceptable_report()).unwrap();
    }

    #[test]
    fn rejects_debug_enabled_guest() {
        let mut report = acceptable_report();
        report.policy.set_debug_allowed(true);
        assert!(matches!(
            check_report_policy(&report),
            Err(AttestationError::PolicyRejected(_))
        ));
    }

    #[test]
    fn rejects_migration_agent() {
        let mut report = acceptable_report();
        report.policy.set_migrate_ma_allowed(true);
        assert!(matches!(
            check_report_policy(&report),
            Err(AttestationError::PolicyRejected(_))
        ));
    }

    #[test]
    fn rejects_non_zero_vmpl() {
        let mut report = acceptable_report();
        report.vmpl = 1;
        assert!(matches!(
            check_report_policy(&report),
            Err(AttestationError::PolicyRejected(_))
        ));
    }

    /// A guest created under superseded firmware keeps reporting the platform's
    /// current TCB after the host updates it, so the floor has to look at what
    /// was in force at launch too.
    #[test]
    fn rejects_a_guest_launched_below_the_floor() {
        let mut report = acceptable_report();
        report.launch_tcb = tcb(4, 0, 28, 222);
        assert!(matches!(
            check_report_policy(&report),
            Err(AttestationError::PolicyRejected(_))
        ));
    }

    /// Each component is checked on its own: a newer microcode must not buy
    /// back an older SNP firmware.
    #[test]
    fn tcb_floor_is_per_component() {
        assert!(MIN_TCB.accepts(&tcb(4, 0, 29, 222)));
        assert!(MIN_TCB.accepts(&tcb(5, 1, 30, 223)));
        assert!(!MIN_TCB.accepts(&tcb(4, 0, 28, 255)));
        assert!(!MIN_TCB.accepts(&tcb(3, 0, 29, 222)));
    }

    #[test]
    fn foreign_format_rejected() {
        let quote = Quote {
            format: "snp-dev".into(),
            quote_blob: Vec::new(),
            measurement: String::new(),
        };
        assert!(matches!(
            verify_quote(&quote, &ReportData::for_kbs(vec![0u8; 32])),
            Err(AttestationError::UnsupportedFormat(_))
        ));
    }

    /// A quote whose certificates do not chain to the compiled-in AMD root is
    /// rejected before any field of the report is read.
    #[test]
    fn unrooted_chain_rejected() {
        let envelope = SnpEnvelope {
            report: acceptable_report().to_bytes().unwrap().to_vec(),
            ask_der: vec![0u8; 4],
            vcek_der: vec![0u8; 4],
        };
        let mut quote_blob = Vec::new();
        ciborium::into_writer(&envelope, &mut quote_blob).unwrap();
        let quote = Quote {
            format: SNP_FORMAT.into(),
            quote_blob,
            measurement: hex::encode([0u8; 48]),
        };
        assert!(matches!(
            verify_quote(&quote, &ReportData::for_kbs(vec![0u8; 32])),
            Err(AttestationError::InvalidQuote(_))
        ));
    }

    /// The pinned root is a real AMD certificate and is self-consistent.
    #[test]
    fn pinned_root_is_the_amd_milan_chain() {
        let ark = pinned_ark().unwrap();
        let ask = builtin::milan::ask().unwrap();
        (&ca::Chain { ark, ask }).verify().unwrap();
    }
}
