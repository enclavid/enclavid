//! `disclosure-fields`: the policy's fields, labelled with this plugin's texts.

use crate::WellKnown;
use crate::enclavid::host::refs::DisclosureFieldRef;
use crate::enclavid::host_disclosure::disclosure::DisplayField;
use crate::enclavid_ext::well_known::i18n::{Key, localized};
use crate::exports::enclavid::well_known::disclosure_fields::Guest;

/// A `DisplayField` of the policy's `field`, shown by the text `label`.
fn labelled(field: DisclosureFieldRef, label: Key, value: String) -> DisplayField {
    DisplayField {
        key: field,
        label: localized(label),
        value,
    }
}

impl Guest for WellKnown {
    // Document identifiers
    fn passport_number(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::PassportNumberLabel, value)
    }
    fn id_card_number(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::IdCardNumberLabel, value)
    }
    fn drivers_license_number(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::DriversLicenseNumberLabel, value)
    }
    fn document_issuing_country(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::DocumentIssuingCountryLabel, value)
    }
    fn document_expiry(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::DocumentExpiryLabel, value)
    }
    fn document_issued(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::DocumentIssuedLabel, value)
    }

    // Identity
    fn given_name(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::GivenNameLabel, value)
    }
    fn family_name(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::FamilyNameLabel, value)
    }
    fn full_name(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::FullNameLabel, value)
    }
    fn date_of_birth(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::DateOfBirthLabel, value)
    }
    fn sex(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::SexLabel, value)
    }
    fn nationality(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::NationalityLabel, value)
    }

    // Contact / location
    fn residence_country(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::ResidenceCountryLabel, value)
    }
    fn address(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::AddressLabel, value)
    }
    fn email(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::EmailLabel, value)
    }
    fn phone(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::PhoneLabel, value)
    }

    // Other
    fn tax_id(field: DisclosureFieldRef, value: String) -> DisplayField {
        labelled(field, Key::TaxIdLabel, value)
    }
}
