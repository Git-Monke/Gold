#[derive(thiserror::Error, Debug)]
pub enum Error {
    // Generic
    #[error("Generic {0}")]
    Generic(String),

    // Io
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
