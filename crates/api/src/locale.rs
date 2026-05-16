//! Applicant locale negotiation.
//!
//! The applicant API resolves every text-ref into a single string for
//! the user's preferred language server-side, so the wire payload is
//! a plain `String` instead of a per-locale translation map. This
//! halves-or-more the response size for polici with multi-language
//! coverage and keeps the frontend free of i18n logic.
//!
//! Locale comes from the standard `Accept-Language` HTTP header
//! (browsers set it automatically from system preferences). To change
//! language mid-session the frontend reloads with a different header
//! — slower than client-side switching, but our threshold is "fast
//! initial load" over "instant locale switch" (which is rare in
//! practice on a single verification flow).
//!
//! Parsing: take the first preference, drop q-values (negligible
//! delta in practice, simpler code). Default `"en"` when the header
//! is missing or malformed. The `TextRegistry::resolve_string` lookup
//! handles the fallback chain (exact → language base → en → first
//! available) so any locale string we pass in produces a usable
//! result.

use axum::extract::FromRequestParts;
use axum::http::header::ACCEPT_LANGUAGE;
use axum::http::request::Parts;
use axum::http::StatusCode;

const DEFAULT_LOCALE: &str = "en";

/// Applicant's preferred locale tag (`en`, `ru-RU`, `zh-Hant`, ...).
/// Always non-empty — defaulted to `"en"` on header miss.
pub struct Locale(pub String);

impl Locale {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for Locale {
    fn default() -> Self {
        Self(DEFAULT_LOCALE.to_string())
    }
}

impl<S> FromRequestParts<S> for Locale
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(DEFAULT_LOCALE);
        // Accept-Language: ru-RU,ru;q=0.9,en;q=0.8 → first preference
        // before comma → "ru-RU". Strip q-value (`;q=...`) if present
        // — we ignore q-values for simplicity (an applicant browser's
        // declared first preference is what we honour).
        let first = header.split(',').next().unwrap_or(DEFAULT_LOCALE).trim();
        let tag = first.split(';').next().unwrap_or(first).trim();
        let tag = if tag.is_empty() { DEFAULT_LOCALE } else { tag };
        Ok(Locale(tag.to_string()))
    }
}
