use enclavid_host_bridge::{DisplayField as ProtoDisplayField, suspended};

use crate::enclavid::disclosure::disclosure::{DisplayField, Host};
use crate::host_state::HostState;
use crate::listener::ConsentDisclosure;
use crate::sanitize;

impl Host for HostState {
    async fn prompt_disclosure(
        &mut self,
        fields: Vec<DisplayField>,
        reason_ref: String,
    ) -> wasmtime::Result<bool> {
        sanitize::validate_fields(&fields, &self.registered_text_refs)?;
        // The reason itself is a `text-ref` — host resolves to a
        // human-readable string when assembling the consent screen.
        // It must be in the policy's pre-declared dictionary; that
        // closes the runtime-crafting channel (policy can't pick a
        // reason string at evaluate time based on user attributes).
        sanitize::ensure_registered(
            &reason_ref,
            &self.registered_text_refs,
            "prompt_disclosure reason",
        )?;
        let sanitized = sanitize::sanitize_fields(fields);

        let accepted = self
            .replay
            .current_suspended()
            .and_then(|s| s.request.as_ref())
            .and_then(|r| match r {
                suspended::Request::Consent(c) => c.accepted,
                _ => None,
            });

        let proto_fields: Vec<ProtoDisplayField> = sanitized.into_iter().map(Into::into).collect();

        match accepted {
            None => Err(suspended::Request::consent(proto_fields, reason_ref).into()),
            Some(false) => Ok(false),
            Some(true) => {
                self.pending_disclosures
                    .push(ConsentDisclosure { fields: proto_fields });
                Ok(true)
            }
        }
    }
}

// --- WIT → proto conversion ---
//
// Three flat strings either way; passthrough modulo ownership.

impl From<DisplayField> for ProtoDisplayField {
    fn from(f: DisplayField) -> Self {
        Self {
            key: f.key,
            label: f.label,
            value: f.value,
        }
    }
}
