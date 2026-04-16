use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::StatusCode;
use base64ct::{Base64, Encoding};
use secrecy::SecretBox;

use crate::state::ClientKey;

/// Extractor wrapping the client key parsed from `Authorization: Bearer <base64>`.
pub struct BearerKey(pub ClientKey);

impl<S: Send + Sync> FromRequestParts<S> for BearerKey {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(StatusCode::UNAUTHORIZED)?
            .to_str()
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        let token = header
            .strip_prefix("Bearer ")
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let bytes = Base64::decode_vec(token).map_err(|_| StatusCode::UNAUTHORIZED)?;

        Ok(BearerKey(SecretBox::new(Box::new(bytes))))
    }
}
