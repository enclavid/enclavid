use enclavid_host_bridge::{
    DisplayField as ProtoDisplayField, DocumentField as ProtoDocumentField, DocumentFieldKind,
    DocumentRole as ProtoDocumentRole, FieldKey as ProtoFieldKey,
    LocalizedText as ProtoLocalizedText, WellKnownFieldKey, field_key, suspended,
};

use crate::enclavid::disclosure::disclosure::{
    DisplayField, DocumentRole as WitDocumentRole, FieldKey as WitFieldKey, Host,
    LocalizedText as WitLocalizedText,
};
use crate::host_state::HostState;
use crate::listener::ConsentDisclosure;
use crate::sanitize;

impl Host for HostState {
    async fn prompt_disclosure(
        &mut self,
        fields: Vec<DisplayField>,
        reason: WitLocalizedText,
    ) -> wasmtime::Result<bool> {
        sanitize::validate_fields(&fields)?;
        sanitize::validate_reason(&reason)?;
        let sanitized = sanitize::sanitize_fields(fields);
        let sanitized_reason = sanitize::sanitize_localized(reason);

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
            None => Err(suspended::Request::consent(proto_fields, sanitized_reason.into()).into()),
            Some(false) => Ok(false),
            Some(true) => {
                // Structured record handed to the listener as-is. The
                // api crate owns the public JSON wire format and seals
                // to the consumer recipient — engine stays out of both.
                self.pending_disclosures
                    .push(ConsentDisclosure { fields: proto_fields });
                Ok(true)
            }
        }
    }
}

// --- WIT → proto conversions ---
//
// Orphan-rule note: WIT types are generated inside this crate (via
// `wasmtime::component::bindgen!`), so `impl From<WitX> for ProtoY` is
// allowed even though both `From` and `ProtoY` are foreign — the
// trait parameter is local.

impl From<DisplayField> for ProtoDisplayField {
    fn from(f: DisplayField) -> Self {
        Self {
            key: Some(f.key.into()),
            value: f.value,
        }
    }
}

impl From<WitFieldKey> for ProtoFieldKey {
    fn from(key: WitFieldKey) -> Self {
        let kind = match key {
            WitFieldKey::FirstName => well_known(WellKnownFieldKey::FirstName),
            WitFieldKey::LastName => well_known(WellKnownFieldKey::LastName),
            WitFieldKey::MiddleName => well_known(WellKnownFieldKey::MiddleName),
            WitFieldKey::DateOfBirth => well_known(WellKnownFieldKey::DateOfBirth),
            WitFieldKey::PlaceOfBirth => well_known(WellKnownFieldKey::PlaceOfBirth),
            WitFieldKey::Nationality => well_known(WellKnownFieldKey::Nationality),
            WitFieldKey::Sex => well_known(WellKnownFieldKey::Sex),
            WitFieldKey::CountryOfResidence => well_known(WellKnownFieldKey::CountryOfResidence),
            WitFieldKey::DocumentNumber(role) => document(role, DocumentFieldKind::Number),
            WitFieldKey::DocumentIssuingCountry(role) => {
                document(role, DocumentFieldKind::IssuingCountry)
            }
            WitFieldKey::DocumentIssueDate(role) => document(role, DocumentFieldKind::IssueDate),
            WitFieldKey::DocumentExpiryDate(role) => document(role, DocumentFieldKind::ExpiryDate),
            WitFieldKey::Custom(loc) => field_key::Kind::Custom(loc.into()),
        };
        Self { kind: Some(kind) }
    }
}

impl From<WitDocumentRole> for ProtoDocumentRole {
    fn from(role: WitDocumentRole) -> Self {
        match role {
            WitDocumentRole::Passport => Self::Passport,
            WitDocumentRole::IdCard => Self::IdCard,
            WitDocumentRole::DriversLicense => Self::DriversLicense,
        }
    }
}

impl From<WitLocalizedText> for ProtoLocalizedText {
    fn from(loc: WitLocalizedText) -> Self {
        Self {
            language: loc.language,
            text: loc.text,
        }
    }
}

// Helpers — `well_known` is unary (would normally be a `From` impl on
// `WellKnownFieldKey`, but `WellKnownFieldKey` is foreign so we can't
// add an inherent `Into` impl for the foreign target type).
// `document` takes two args, doesn't fit `From`'s unary shape.
fn well_known(k: WellKnownFieldKey) -> field_key::Kind {
    field_key::Kind::WellKnown(k as i32)
}

fn document(role: WitDocumentRole, kind: DocumentFieldKind) -> field_key::Kind {
    field_key::Kind::DocumentField(ProtoDocumentField {
        role: ProtoDocumentRole::from(role) as i32,
        kind: kind as i32,
    })
}
