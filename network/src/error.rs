//! Error types for network I/O operations.

use crate::Id;

/// Error types for network I/O operations.
#[derive(Debug, thiserror::Error)]
pub enum NetIoError {
    #[error("error in IO: {0}")]
    IoError(#[from] std::io::Error),
    #[error("error acquiring the mutex: {0}")]
    MutexLockFailed(String),
    /// The requested connection was not found.
    #[error("connection not found with peer {0}")]
    ConnectionNotFound(Id),
    #[error("a time out error occurred: {0}")]
    Timeout(String),
}

/// Type alias for network I/O results.
pub type NetIoResult<T> = std::result::Result<T, NetIoError>;
