use enclavid_host_bridge::{suspended, ConsentRequest, DisplayField as ProtoDisplayField};
use prost::Message;

use crate::enclavid::disclosure::disclosure::{DisplayField, Host};
use crate::host_state::HostState;
use crate::sanitize;

impl Host for HostState {
    async fn prompt_disclosure(
        &mut self,
        fields: Vec<DisplayField>,
    ) -> wasmtime::Result<bool> {
        sanitize::validate_fields(&fields)?;
        let sanitized = sanitize::sanitize_fields(fields);
        let proto_fields: Vec<ProtoDisplayField> = sanitized
            .into_iter()
            .map(|f| ProtoDisplayField { label: f.label, value: f.value })
            .collect();

        let accepted = self
            .replay
            .current_suspended()
            .and_then(|s| s.request.as_ref())
            .and_then(|r| match r {
                suspended::Request::Consent(c) => c.accepted,
                _ => None,
            });

        match accepted {
            None => Err(suspended::Request::consent(proto_fields).into()),
            Some(false) => Ok(false),
            Some(true) => {
                // Reuse ConsentRequest as the disclosed-record schema:
                // same fields + an explicit `accepted` marker.
                let payload = ConsentRequest {
                    fields: proto_fields,
                    accepted: Some(true),
                }
                .encode_to_vec();
                // Host's "Ok" is a claim of append. A lying host that
                // drops disclosure entries means the client never receives
                // consented data — operationally observable (client polls
                // /shared-data and sees nothing), not a confidentiality
                // break. Confidentiality holds because chunks are
                // encrypted to client_pk before append.
                self.disclosure_store
                    .append(&self.session_id, payload, &self.client_pk)
                    .await
                    .map_err(|e| wasmtime::Error::msg(format!("disclosure append failed: {e}")))?
                    .trust_unchecked();
                Ok(true)
            }
        }
    }
}
