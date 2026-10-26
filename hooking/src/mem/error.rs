use thiserror::Error;

pub type Result<T> = std::result::Result<T, MemoryError>;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("A lock was poisoned by a panic while it was held")]
    PoisonedLock,

    #[error("Failed to retrieve page size")]
    NoPageSize,

    #[error("Failed to allocate page memory")]
    CantAllocate,

    #[error("Failed to map dual-view memory")]
    CantMapMemory,

    #[error("Failed to query memory protection. Address: {0:x}")]
    CantQueryProtection(usize),

    #[error("Failed to set memroy protection. Address: {0:x}")]
    CantSetMemoryProtection(usize),

    #[error("Not enough memory left in heap. Needs: {needs} | Has: {has}")]
    NoMemory { needs: usize, has: usize },

    #[error("Cant find module with name {0}")]
    CantFindModule(String),

    #[error("Cant find symbol with name {0}")]
    CantFindSymbol(String),

    #[error("Address is not usable for this situation")]
    BadAdress(*const std::ffi::c_void),
}
