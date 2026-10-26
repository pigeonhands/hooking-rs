use core::ffi;
use core::{ffi::CStr, ptr::NonNull};
use std::ffi::c_void;
use std::ops::Range;

use crate::arena::{CodeArena, DefaultArena};
use crate::asm;
use crate::error::{HookingError, Result};
use crate::patch::{DefaultPatcher, PatchWriter};
use crate::sys;

static DEFAULT_ARENA: DefaultArena = DefaultArena::new();
static DEFAULT_PATCHER: DefaultPatcher = DefaultPatcher::new();

/// The longest x86 instruction.
const MAX_INSTRUCTION_LEN: usize = 15;

#[derive(Debug)]
pub struct Hook<'a> {
    pub data: HookData<'a>,
    patcher: &'a dyn PatchWriter,
    is_applied: bool,
}

impl Hook<'static> {
    pub unsafe fn by_name(
        module: Option<&CStr>,
        symbol: &CStr,
        destination: *mut u8,
    ) -> Result<Self> {
        let hook_writer = HookWriter::from_static();
        unsafe { hook_writer.create_hook_by_name(module, symbol, destination) }
    }

    pub unsafe fn create(target: *mut u8, destination: *mut u8) -> Result<Self> {
        let hook_writer = HookWriter::from_static();
        unsafe {
            hook_writer.create_hook(
                NonNull::new(target as *mut _)
                    .ok_or(HookingError::InvalidTarget(target as *const _))?,
                NonNull::new(destination as *mut _)
                    .ok_or(HookingError::InvalidDestination(destination as *const _))?,
            )
        }
    }
}

impl<'a> Hook<'a> {
    /// The hooked function's original code, relocated so it can still be
    /// called while the hook is applied.
    pub fn original_function(&self) -> NonNull<c_void> {
        NonNull::from(self.data.original_fn_call_stub_data).cast()
    }

    pub unsafe fn apply_hook(&mut self) -> Result<()> {
        if self.is_applied {
            return Ok(());
        }
        let target = self.data.symbol_address.cast();
        unsafe { self.patcher.write(target, &self.data.patch_data)? };
        self.is_applied = true;

        Ok(())
    }

    pub unsafe fn remove_hook(&mut self) -> Result<()> {
        if !self.is_applied {
            return Ok(());
        }
        let target = self.data.symbol_address.cast();
        unsafe {
            self.patcher
                .write(target, &self.data.original_instructions)?
        };
        self.is_applied = false;

        Ok(())
    }
}

#[derive(Debug)]
pub struct HookData<'a> {
    pub symbol_address: NonNull<ffi::c_void>,
    pub trampoline_data: &'a [u8],
    pub original_fn_call_stub_data: &'a [u8],
    pub patch_data: Vec<u8>,
    pub original_instructions: Vec<u8>,
}

/// Where each part of a hook's code is, as offsets into the code placed in
/// the arena:
///
/// | Bytes | Contents |
/// | --- | --- |
/// | pointer size | Address of `original_fn`, read by the trampoline on x86_64 |
/// | `trampoline` | Passes that address to the hook, then jumps to the hook |
/// | `original_fn` | The instructions overwritten by the patch, then a jump back |
struct HookLayout {
    trampoline: Range<usize>,
    original_fn: Range<usize>,
    /// The jump to the trampoline, written over the target.
    patch: Vec<u8>,
}

impl HookLayout {
    /// Assemble a hook's code to run at `at`. `target_code` is the start of
    /// the target function, which runs at `target`.
    fn assemble(
        at: usize,
        target: usize,
        target_code: &[u8],
        destination: usize,
    ) -> Result<(Vec<u8>, Self)> {
        let slot_len = std::mem::size_of::<usize>();

        let trampoline_at = at + slot_len;
        let trampoline = asm::trampoline(trampoline_at, destination, at)?;

        let original_fn_at = trampoline_at + trampoline.len();
        let patch = asm::patch(target, trampoline_at)?;
        // The target is live code, so the calls it makes are readable.
        let original_fn =
            unsafe { asm::relocate(target_code, target, original_fn_at, patch.len())? };

        let mut bytes = original_fn_at.to_ne_bytes().to_vec();
        bytes.extend_from_slice(&trampoline);
        bytes.extend_from_slice(&original_fn);

        let trampoline = slot_len..slot_len + trampoline.len();
        let original_fn = trampoline.end..bytes.len();
        let layout = Self {
            trampoline,
            original_fn,
            patch,
        };
        Ok((bytes, layout))
    }
}

pub struct HookWriter<'a> {
    arena: &'a dyn CodeArena,
    patcher: &'a dyn PatchWriter,
}

impl HookWriter<'static> {
    pub const fn from_static() -> Self {
        Self::new(&DEFAULT_ARENA)
    }
}

impl<'a> HookWriter<'a> {
    pub const fn new(arena: &'a dyn CodeArena) -> Self {
        Self {
            arena,
            patcher: &DEFAULT_PATCHER,
        }
    }

    /// Use `patcher` to write hooks into their target functions.
    pub const fn with_patcher(self, patcher: &'a dyn PatchWriter) -> Self {
        Self {
            arena: self.arena,
            patcher,
        }
    }

    pub unsafe fn create_hook_by_name(
        &self,
        module: Option<&CStr>,
        symbol: &CStr,
        destination: *mut u8,
    ) -> Result<Hook<'a>> {
        let destination = NonNull::new(destination as *mut c_void).ok_or_else(|| {
            HookingError::NoDestination(symbol.to_str().unwrap_or("<invalid-symbol-name>").into())
        })?;

        unsafe {
            let symbol_address = sys::find_symbol(module, symbol)?;
            self.create_hook(symbol_address, destination)
        }
    }

    pub unsafe fn create_hook(
        &self,
        target: NonNull<c_void>,
        destination: NonNull<c_void>,
    ) -> Result<Hook<'a>> {
        let hook_data = unsafe { self.write_hook_table(target, destination)? };
        Ok(Hook {
            data: hook_data,
            patcher: self.patcher,
            is_applied: false,
        })
    }

    pub unsafe fn write_hook_table(
        &self,
        target: NonNull<ffi::c_void>,
        destination_fn: NonNull<ffi::c_void>,
    ) -> Result<HookData<'a>> {
        let target_address = target.as_ptr() as usize;
        let target_code = unsafe { decodable_code(target) };
        let destination = destination_fn.as_ptr() as usize;

        // `place` may assemble more than once; the last layout is the one placed.
        let mut layout = None;
        let placed_at = self.arena.place(Some(target_address), &mut |at| {
            let (bytes, assembled) =
                HookLayout::assemble(at, target_address, target_code, destination)?;
            layout = Some(assembled);
            Ok(bytes)
        })?;
        let layout = layout.expect("place assembles the code it places");

        let placed = |range: Range<usize>| unsafe {
            std::slice::from_raw_parts(placed_at.as_ptr().add(range.start), range.len())
        };

        Ok(HookData {
            symbol_address: target,
            trampoline_data: placed(layout.trampoline),
            original_fn_call_stub_data: placed(layout.original_fn),
            original_instructions: target_code[..layout.patch.len()].to_vec(),
            patch_data: layout.patch,
        })
    }
}

/// The code at the start of `target` that relocation may decode: the
/// longest patch, plus one more instruction that may start inside it.
///
/// Reading stops at the end of the page holding the last byte the longest
/// patch could overwrite, so it never touches a page the patch wouldn't.
unsafe fn decodable_code<'a>(target: NonNull<c_void>) -> &'a [u8] {
    let start = target.as_ptr() as usize;
    let page_end = sys::align_up(start + asm::MAX_PATCH_LEN, sys::page_size());
    let len = (asm::MAX_PATCH_LEN + MAX_INSTRUCTION_LEN).min(page_end - start);
    unsafe { std::slice::from_raw_parts(target.as_ptr().cast(), len) }
}
