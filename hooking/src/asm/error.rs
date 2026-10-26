use thiserror::Error;

pub type Result<T> = std::result::Result<T, AssemblyError>;

#[derive(Debug, Error)]
pub enum AssemblyError {
    #[error("Error during assembly/dissasembly")]
    AssemblyError(#[from] iced_x86::IcedError),

    #[error("Could not decode enough instructions while trying to relocate")]
    RelocationError,

    #[error("Relocating instruction {0:?} is not supported")]
    UnsupportedRelocation(iced_x86::Code),
}
