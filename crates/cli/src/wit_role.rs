//! Detect an artifact's WIT role (policy vs plugin) from the component's
//! top-level interface exports, so the `policy` / `plugin` command groups
//! can assert the artifact handed to them matches the declared role.
//!
//! Discriminator: a policy component exports the `enclavid:policy/policy`
//! interface (`world policy { export enclavid:policy/policy@x; }`); a
//! plugin exports its own interfaces and never the policy world. The
//! exported interface id is the component's top-level export name, so a
//! version-tolerant `starts_with("enclavid:policy/policy")` is enough —
//! no full WIT decode needed.
//!
//! Since policy and plugin artifacts are otherwise identical on the wire
//! (both are plaintext wasm components → one `application/wasm` layer),
//! this check is what makes `policy` / `plugin` meaningful command groups
//! rather than cosmetic aliases: each validates the artifact's role.

use anyhow::{Context, Result, bail};
use wasmparser::{Encoding, Parser, Payload};

const POLICY_EXPORT_PREFIX: &str = "enclavid:policy/policy";

/// Does the component export the `enclavid:policy/policy` interface?
/// Errors if the input isn't a wasm component (e.g. a core module).
fn exports_policy(wasm: &[u8]) -> Result<bool> {
    let mut is_component = false;
    for payload in Parser::new(0).parse_all(wasm) {
        match payload.context("parsing the wasm artifact")? {
            Payload::Version { encoding, .. } => {
                is_component = matches!(encoding, Encoding::Component);
            }
            Payload::ComponentExportSection(reader) => {
                for export in reader {
                    let export = export.context("reading a component export")?;
                    if export.name.0.starts_with(POLICY_EXPORT_PREFIX) {
                        return Ok(true);
                    }
                }
            }
            _ => {}
        }
    }
    if !is_component {
        bail!(
            "input is a core wasm module, not a component — componentize it first \
             (`wasm-tools component new <module> -o <component>`)"
        );
    }
    Ok(false)
}

/// Assert the component is a **policy** (exports `enclavid:policy/policy`).
pub fn assert_policy(wasm: &[u8]) -> Result<()> {
    if exports_policy(wasm)? {
        Ok(())
    } else {
        bail!(
            "this component does not export `enclavid:policy/policy` — it looks like a \
             plugin. Use `enclavid plugin embed` instead."
        )
    }
}

/// Assert the component is a **plugin** (does NOT export the policy world).
pub fn assert_plugin(wasm: &[u8]) -> Result<()> {
    if exports_policy(wasm)? {
        bail!(
            "this component exports `enclavid:policy/policy` — it's a policy, not a \
             plugin. Use `enclavid policy embed` instead."
        )
    } else {
        Ok(())
    }
}
