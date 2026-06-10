use enclavid_host_bridge::{DisplayField as ProtoDisplayField, suspended};

use crate::enclavid::disclosure::disclosure::{DisplayField, Host};
use crate::listener::ConsentDisclosure;
use crate::sanitize;
use crate::state::HostState;

impl Host for HostState {
    async fn prompt_disclosure(
        &mut self,
        fields: Vec<DisplayField>,
        reason_ref: String,
        requester_ref: String,
    ) -> wasmtime::Result<bool> {
        sanitize::validate_fields(&fields, &self.embedded)?;
        // Both `reason` and `requester` are localized refs minted by
        // some component in the composition. Lookup in the localized
        // store closes two channels at once: the runtime-crafting
        // channel (policy can't mint a raw string at evaluate time
        // based on user attributes) and the cross-component channel
        // (a forged ref attributing a message to another slot fails
        // because the only way the store has a token is for a
        // component to have minted it through its own slot).
        sanitize::ensure_localized(
            &reason_ref,
            &self.embedded.localized,
            "prompt_disclosure reason",
        )?;
        sanitize::ensure_localized(
            &requester_ref,
            &self.embedded.localized,
            "prompt_disclosure requester",
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
            None => Err(suspended::Request::consent(
                proto_fields,
                reason_ref,
                requester_ref,
            )
            .into()),
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
