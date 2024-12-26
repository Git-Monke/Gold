#[derive(thiserror::Error, Debug)]
pub enum Error {
    // Generic
    #[error("Generic {0}")]
    Generic(String),

    // Blockchain Open Errors

    // Io
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
