use thiserror::Error;

pub type Result<T> = std::result::Result<T, AssemblyError>;

#[derive(Debug, Error)]
pub enum AssemblyError {
    #[error("Error during assembly/dissasembly")]
    AssemblyError(#[from] super::inner::InnerError),

    #[error("Could not decode enough instructions while trying to relocate")]
    RelocationError,
}
