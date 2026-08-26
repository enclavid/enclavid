//! Exercises the prod SEV-SNP backend against real hardware: mint a quote from
//! `/dev/sev-guest`, verify it through the compiled-in AMD root, and confirm a
//! quote bound to one value does not verify against another.
//!
//! Runs as PID 1's `/bin/app` in a guest built from `image/`, so it prints a
//! line per step and lets the machine power off — there is no shell to return
//! to.

#[cfg(target_os = "linux")]
fn main() {
    use enclavid_attestation::AttestationError;

    match run() {
        Ok(()) => println!("SELFTEST-OK"),
        Err(e) => println!("SELFTEST-FAIL {e}"),
    }
    println!("SELFTEST-DONE");

    fn run() -> Result<(), AttestationError> {
        use enclavid_attestation::{Attestor, ReportData, SnpAttestor, verify_quote};

        // The VCEK endorses one chip at one TCB, so it cannot be baked in; it
        // is placed in the image next to this binary. The ASK is AMD's
        // per-generation intermediate and travels with the `sev` crate.
        let vcek = std::fs::read("/vcek.der")
            .map_err(|e| AttestationError::Backend(format!("read /vcek.der: {e}")))?;
        let ask = sev::certs::snp::builtin::milan::ASK;

        let attestor = SnpAttestor::new(ask, &vcek)?;
        println!("SELFTEST-STARTUP-ATTEST-OK");

        let bound = ReportData::for_ratls(b"selftest-spki".to_vec());
        let quote = attestor.mint(&bound)?;

        println!("SELFTEST-FORMAT {}", quote.format);
        println!("SELFTEST-MEASUREMENT {}", quote.measurement);
        println!("SELFTEST-QUOTE-BYTES {}", quote.quote_blob.len());

        verify_quote(&quote, &bound)?;
        println!("SELFTEST-VERIFY-OK");

        // The same quote must not satisfy a different binding — otherwise the
        // report authenticates the platform but not the key it was minted for.
        let other = ReportData::for_ratls(b"someone-elses-spki".to_vec());
        match verify_quote(&quote, &other) {
            Err(AttestationError::BindingMismatch) => println!("SELFTEST-BINDING-ENFORCED"),
            Err(e) => return Err(AttestationError::Backend(format!("wrong rejection: {e}"))),
            Ok(()) => {
                return Err(AttestationError::Backend(
                    "quote verified against a binding it was not minted for".into(),
                ));
            }
        }
        Ok(())
    }
}

/// The guest device is Linux-only, so elsewhere this builds but does nothing.
#[cfg(not(target_os = "linux"))]
fn main() {
    println!("SELFTEST-SKIP no guest device outside Linux");
}
