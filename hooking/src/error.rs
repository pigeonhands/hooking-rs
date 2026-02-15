use thiserror::Error;

pub type Result<T> = std::result::Result<T, HookingError>;

#[derive(Debug, Error)]
pub enum HookingError {
    #[error("Memory error")]
    MemoryError(#[from] crate::mem::MemoryError),

    #[error("Assembly error")]
    AssemblyError(#[from] crate::asm::AssemblyError),

    #[error("Provided destination for hook \"{0}\" was null")]
    NoDestination(String),
}
