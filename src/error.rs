use thiserror::Error;

/// Common application error type for domain-level failures.
#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum AegisError {
    #[error("request denied: {0}")]
    Denied(String),
}
