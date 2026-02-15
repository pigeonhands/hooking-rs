use thiserror::Error;

pub type Result<T> = std::result::Result<T, MemoryError>;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("TableHeap state is poisoned")]
    BadTableHeapState,

    #[error("Tried to access table heap before allocation")]
    TableHeapNotAllocated,

    #[error("Failed to retrieve page size")]
    NoPageSize,

    #[error("Failed to allocate page memory")]
    CantAllocate,

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
