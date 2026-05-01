use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("attestation backend rejected the request: {0}")]
    Backend(String),

    #[error("quote uses unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("quote payload could not be parsed: {0}")]
    InvalidQuote(String),

    #[error("signature verification failed")]
    BadSignature,

    #[error("report_data in quote does not match expected binding")]
    BindingMismatch,

    #[error("measurement in quote does not match expected pin")]
    MeasurementMismatch,
}
