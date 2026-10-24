//! The text a component shows the applicant: what a `localized-ref` carries —
//! its text in every language the catalog has it in.
//!
//! The platform picks the language; the component never learns which one the
//! applicant reads.

use serde::{Deserialize, Serialize};

/// A text in one language.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Translation {
    pub language: String,
    pub text: String,
}

/// What a `localized-ref` resolves to: its text in every language the catalog
/// has it in.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Localized {
    pub translations: Vec<Translation>,
}
