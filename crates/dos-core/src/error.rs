use thiserror::Error;

#[derive(Debug, Error)]
pub enum DosError {
    #[error("bad path: {0}")]
    BadPath(String),

    #[error("not found")]
    NotFound,

    #[error("already exists")]
    AlreadyExists,

    #[error("permission denied")]
    PermissionDenied,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid request: {0}")]
    Invalid(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("internal: {0}")]
    Internal(String),
}
