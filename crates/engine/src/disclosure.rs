use enclavid_host_bridge::{
    AppendDisclosure, ConsentRequest, DisplayField as ProtoDisplayField, suspended,
};
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
                // TODO encrypt: encrypt `payload` to `self.client_pk`
                // (age recipient, hybrid AES+X25519) BEFORE staging.
                // The host stores opaque bytes — encryption is the
                // engine's responsibility. Confidentiality of
                // disclosure data depends on this landing.
                let _ = &self.client_pk;
                let encrypted = payload;
                // Stage in the in-memory buffer. The API harvests
                // pending disclosures after `runner.run` returns and
                // merges them into the next `SessionStore::commit` —
                // so the consent answer in state and the disclosure
                // entry land in one atomic transaction. No
                // duplicate-on-retry race.
                self.pending_disclosures
                    .push(AppendDisclosure(encrypted));
                Ok(true)
            }
        }
    }
}
