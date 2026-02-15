use std::{ffi::c_void, ptr::NonNull};

pub mod inner {
    pub mod x86_64;
    pub use x86_64::*;

    pub use x86_64::HookAssemblerx86_64 as HookAssemblerImpl;
}

pub mod error;
pub use error::{AssemblyError, Result};

pub type DefaultHookAssembler = inner::HookAssemblerImpl;

pub trait HookAssembler {
    fn assemble_trampoline(
        &self,
        eip: usize,
        destination_fn: NonNull<c_void>,
        restore_fn_address: Option<NonNull<c_void>>,
    ) -> Result<Vec<u8>>;

    fn relocate_instructions(
        &self,
        eip: usize,
        source_data: NonNull<c_void>,
        min_size_bytes: usize,
        add_jump: bool,
    ) -> Result<Vec<u8>>;
}
