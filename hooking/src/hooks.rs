use core::ffi;
use core::{ffi::CStr, ptr::NonNull};
use std::ffi::c_void;
use std::ops::Range;

use crate::arena::{CodeArena, DefaultArena};
use crate::asm;
use crate::error::{HookingError, Result};
use crate::patch::{DefaultPatcher, PatchWriter};
use crate::sys;

#[cfg(target_arch = "x86_64")]
pub use self::save_registers::*;

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

    /// Like [`Hook::create`], but the trampoline saves all argument registers
    /// (integer and SSE) before calling `dispatch` with pointers to the saved
    /// state. The caller doesn't need to know the target's signature — the
    /// dispatch function reads and writes arguments through [`SavedRegs`] and
    /// signals the outcome through [`DispatchResult`].
    ///
    /// The dispatch function is keyed by the original-function stub address
    /// (the first argument), so the caller can register per-hook callback data
    /// in its own global table.
    ///
    /// ```no_run
    /// # use hooking::hooks::{Hook, SavedRegs, DispatchResult};
    /// extern "C" fn my_dispatch(
    ///     original: usize,
    ///     int_regs: *mut u64,
    ///     sse_regs: *mut [u8; 16],
    ///     result: *mut DispatchResult,
    /// ) {
    ///     let regs = SavedRegs { int_regs, sse_regs };
    ///     // Inspect regs.read_int(0) for the first integer argument, etc.
    ///     // Write a Passthrough result to call the original:
    ///     unsafe { *result = DispatchResult::passthrough() };
    /// }
    ///
    /// # let target: *mut u8 = std::ptr::null_mut();
    /// let mut hook = unsafe { Hook::create_save_registers(target, my_dispatch) }.unwrap();
    /// unsafe { hook.apply_hook() }.unwrap();
    /// ```
    ///
    /// # Safety
    /// `target` must point to the start of a function.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn create_save_registers(
        target: *mut u8,
        dispatch: SavedRegsDispatch,
    ) -> Result<Self> {
        SAVE_REGISTERS_DISPATCH.store(dispatch as usize, std::sync::atomic::Ordering::Release);
        unsafe {
            Self::create(target, save_registers_trampoline as *mut u8)
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

#[cfg(target_arch = "x86_64")]
mod save_registers {
    use std::sync::atomic::AtomicUsize;

    use crate::ORIGINAL_FN_CHECKSUM_MAGIC;

    /// The dispatch function currently in use. Set by `create_save_registers`
    /// before the hook is applied, read by the trampoline's dispatch shim.
    pub(super) static SAVE_REGISTERS_DISPATCH: AtomicUsize = AtomicUsize::new(0);

    /// The function signature the naked trampoline calls. The consumer
    /// provides this — hooking-rs only provides the trampoline that saves
    /// registers and calls it.
    ///
    /// - `original`: the original-function stub address (use it as a key to
    ///   look up per-hook callback data)
    /// - `int_regs`: pointer to 6 saved integer registers `[rdi, rsi, rdx,
    ///   rcx, r8, r9]`, readable and writable
    /// - `sse_regs`: pointer to 8 saved SSE registers `[xmm0..xmm7]`, each
    ///   16 bytes, readable and writable
    /// - `result`: pointer to a [`DispatchResult`] the function must write
    ///   before returning
    pub type SavedRegsDispatch = extern "C" fn(
        original: usize,
        int_regs: *mut u64,
        sse_regs: *mut [u8; 16],
        result: *mut DispatchResult,
    );

    /// Pointers to the integer and SSE argument registers saved on the
    /// trampoline's stack. Valid only during a dispatch call.
    ///
    /// Integer registers are stored as `[rdi, rsi, rdx, rcx, r8, r9]`
    /// (index 0 = rdi). SSE registers as `[xmm0, xmm1, ..., xmm7]`, each
    /// 16 bytes.
    ///
    /// ```
    /// # use hooking::hooks::SavedRegs;
    /// # let mut ints = [0u64; 6];
    /// # let mut sses = [[0u8; 16]; 8];
    /// let regs = SavedRegs { int_regs: ints.as_mut_ptr(), sse_regs: sses.as_mut_ptr() };
    /// // Read the first integer argument (rdi):
    /// let first_arg = regs.read_int(0);
    /// // Write a modified value back:
    /// regs.write_int(0, 42);
    /// // Read a float from xmm0:
    /// let f = regs.read_f64(0);
    /// ```
    pub struct SavedRegs {
        pub int_regs: *mut u64,
        pub sse_regs: *mut [u8; 16],
    }

    impl SavedRegs {
        /// Read integer register at `index` (0=rdi, 1=rsi, 2=rdx, 3=rcx,
        /// 4=r8, 5=r9).
        pub fn read_int(&self, index: u8) -> u64 {
            assert!(index < 6, "integer register index out of range");
            unsafe { *self.int_regs.add(index as usize) }
        }

        /// Write integer register at `index`.
        pub fn write_int(&self, index: u8, val: u64) {
            assert!(index < 6, "integer register index out of range");
            unsafe { *self.int_regs.add(index as usize) = val }
        }

        /// Read a 32-bit float from SSE register at `index` (0=xmm0, ...,
        /// 7=xmm7).
        pub fn read_f32(&self, index: u8) -> f32 {
            assert!(index < 8, "SSE register index out of range");
            let bytes = unsafe { &*self.sse_regs.add(index as usize) };
            f32::from_le_bytes(bytes[..4].try_into().unwrap())
        }

        /// Read a 64-bit float from SSE register at `index`.
        pub fn read_f64(&self, index: u8) -> f64 {
            assert!(index < 8, "SSE register index out of range");
            let bytes = unsafe { &*self.sse_regs.add(index as usize) };
            f64::from_le_bytes(bytes[..8].try_into().unwrap())
        }

        /// Write a 32-bit float to SSE register at `index`.
        pub fn write_f32(&self, index: u8, val: f32) {
            assert!(index < 8, "SSE register index out of range");
            let bytes = unsafe { &mut *self.sse_regs.add(index as usize) };
            bytes[..4].copy_from_slice(&val.to_le_bytes());
        }

        /// Write a 64-bit float to SSE register at `index`.
        pub fn write_f64(&self, index: u8, val: f64) {
            assert!(index < 8, "SSE register index out of range");
            let bytes = unsafe { &mut *self.sse_regs.add(index as usize) };
            bytes[..8].copy_from_slice(&val.to_le_bytes());
        }
    }

    /// What the dispatch function tells the trampoline to do after it
    /// returns.
    #[derive(Debug, Clone, Copy)]
    pub enum HookAction {
        /// Restore all saved registers and tail-call the original function.
        Passthrough,
        /// Return immediately with this value in `rax`.
        OverrideInt(u64),
        /// Return immediately with this value in `xmm0`.
        OverrideFloat(f64),
    }

    /// The result the dispatch function writes to the trampoline's stack.
    /// The trampoline reads `action` to decide what to do next.
    ///
    /// Use [`DispatchResult::passthrough`], [`DispatchResult::override_int`],
    /// or [`DispatchResult::override_float`] to construct.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct DispatchResult {
        /// 0 = passthrough, 1 = override int (rax), 2 = override float (xmm0).
        action: u64,
        int_val: u64,
        float_val: f64,
    }

    impl DispatchResult {
        /// Restore registers and call the original.
        pub fn passthrough() -> Self {
            Self { action: 0, int_val: 0, float_val: 0.0 }
        }

        /// Return immediately with `val` in `rax`.
        pub fn override_int(val: u64) -> Self {
            Self { action: 1, int_val: val, float_val: 0.0 }
        }

        /// Return immediately with `val` in `xmm0`.
        pub fn override_float(val: f64) -> Self {
            Self { action: 2, int_val: 0, float_val: val }
        }
    }

    impl From<HookAction> for DispatchResult {
        fn from(action: HookAction) -> Self {
            match action {
                HookAction::Passthrough => Self::passthrough(),
                HookAction::OverrideInt(v) => Self::override_int(v),
                HookAction::OverrideFloat(v) => Self::override_float(v),
            }
        }
    }

    /// Shim called from the naked trampoline. Reads the real dispatch fn
    /// from the atomic and forwards the call.
    extern "C" fn save_registers_dispatch_shim(
        original: usize,
        int_regs: *mut u64,
        sse_regs: *mut [u8; 16],
        result: *mut DispatchResult,
    ) {
        let dispatch_addr = SAVE_REGISTERS_DISPATCH.load(std::sync::atomic::Ordering::Acquire);
        if dispatch_addr == 0 {
            unsafe { *result = DispatchResult::passthrough() };
            return;
        }
        let dispatch: SavedRegsDispatch = unsafe { std::mem::transmute(dispatch_addr) };
        dispatch(original, int_regs, sse_regs, result);
    }

    /// Naked trampoline for [`Hook::create_save_registers`]. Saves all
    /// System V AMD64 argument registers, calls the dispatch function, and
    /// either restores them for a tail-call to the original or returns an
    /// override value.
    #[unsafe(naked)]
    pub(super) unsafe extern "C" fn save_registers_trampoline() {
        core::arch::naked_asm!(
            // Save callee-saved registers for the original pointer and frame.
            "push rbx",
            "push rbp",
            "mov rbp, rsp",

            // Verify r10/r11 checksum from hooking's redirect stub.
            "mov rbx, r10",
            "movabs rax, {magic}",
            "xor rax, r10",
            "cmp rax, r11",
            "jne 9f",

            // Save integer argument registers: [rdi, rsi, rdx, rcx, r8, r9].
            // Pushed so that rsp points to rdi (index 0) after all pushes.
            "push r9",
            "push r8",
            "push rcx",
            "push rdx",
            "push rsi",
            "push rdi",

            // Save SSE argument registers (8 × 16 = 128 bytes).
            "sub rsp, 128",
            "movdqu [rsp+0x00], xmm0",
            "movdqu [rsp+0x10], xmm1",
            "movdqu [rsp+0x20], xmm2",
            "movdqu [rsp+0x30], xmm3",
            "movdqu [rsp+0x40], xmm4",
            "movdqu [rsp+0x50], xmm5",
            "movdqu [rsp+0x60], xmm6",
            "movdqu [rsp+0x70], xmm7",

            // Allocate DispatchResult (24 bytes, rounded to 32 for alignment).
            "sub rsp, 32",

            // Call dispatch(original, &int_regs, &sse_regs, &result).
            "mov rdi, rbx",              // original stub address
            "lea rsi, [rsp + 32 + 128]", // int_regs: past result + sse
            "lea rdx, [rsp + 32]",       // sse_regs: past result
            "mov rcx, rsp",              // result: bottom of stack

            // Stack: ret(8) + rbx(8) + rbp(8) + ints(48) + sse(128) + result(32) = 232
            // 232 % 16 = 8, so subtract 8 to align for the call.
            "sub rsp, 8",
            "call {dispatch}",
            "add rsp, 8",

            // Read result.action
            "mov rax, [rsp]",
            "test rax, rax",
            "jnz 2f",

            // action=0: Passthrough — restore all regs and tail-call original.
            "add rsp, 32",
            "movdqu xmm0, [rsp+0x00]",
            "movdqu xmm1, [rsp+0x10]",
            "movdqu xmm2, [rsp+0x20]",
            "movdqu xmm3, [rsp+0x30]",
            "movdqu xmm4, [rsp+0x40]",
            "movdqu xmm5, [rsp+0x50]",
            "movdqu xmm6, [rsp+0x60]",
            "movdqu xmm7, [rsp+0x70]",
            "add rsp, 128",
            "pop rdi",
            "pop rsi",
            "pop rdx",
            "pop rcx",
            "pop r8",
            "pop r9",
            "mov rax, rbx",
            "mov rsp, rbp",
            "pop rbp",
            "pop rbx",
            "jmp rax",

            "2:",
            // action=1 or 2: override return value.
            "cmp rax, 2",
            "je 3f",
            // action=1: int override — load int_val into rax.
            "mov rax, [rsp + 8]",
            "jmp 4f",
            "3:",
            // action=2: float override — load float_val into xmm0.
            "movsd xmm0, [rsp + 16]",
            "xor eax, eax",
            "4:",
            // Clean up frame and return with the override.
            "mov rsp, rbp",
            "pop rbp",
            "pop rbx",
            "ret",

            "9:",
            // r10/r11 checksum mismatch — not called from a hook, bail.
            "pop rbp",
            "pop rbx",
            "ret",

            magic = const ORIGINAL_FN_CHECKSUM_MAGIC,
            dispatch = sym save_registers_dispatch_shim,
        );
    }

    /// The return value of [`call_with_saved_regs`]: both possible return
    /// slots so the caller can pick the right one based on the method's
    /// return type.
    #[repr(C)]
    pub struct CallResult {
        pub int_val: u64,
        pub float_val: f64,
    }

    /// Calls `original` with the integer and SSE registers from the
    /// saved-register arrays, as if the original function had been called
    /// directly. Returns both `rax` and `xmm0` so the caller can pick
    /// the right one based on the return type.
    ///
    /// # Safety
    ///
    /// `original` must be a valid function pointer (the stub returned by
    /// hooking). `int_regs` must point to at least 6 `u64`s and
    /// `sse_regs` to at least 8 × 16-byte slots, as the
    /// [`SavedRegsDispatch`] callback receives them.
    pub unsafe fn call_with_saved_regs(
        original: usize,
        int_regs: *const u64,
        sse_regs: *const [u8; 16],
    ) -> CallResult {
        let mut result = CallResult { int_val: 0, float_val: 0.0 };
        unsafe {
            call_original_trampoline(
                original,
                int_regs,
                sse_regs,
                &mut result as *mut CallResult,
            );
        }
        result
    }

    /// Naked trampoline that loads all System V argument registers from
    /// the saved arrays, calls the original function, and writes rax +
    /// xmm0 to the output struct.
    ///
    /// Args (System V ABI):
    ///   rdi = original fn ptr
    ///   rsi = int_regs ptr
    ///   rdx = sse_regs ptr
    ///   rcx = result ptr (CallResult)
    #[unsafe(naked)]
    unsafe extern "C" fn call_original_trampoline(
        _original: usize,
        _int_regs: *const u64,
        _sse_regs: *const [u8; 16],
        _result: *mut CallResult,
    ) {
        core::arch::naked_asm!(
            "push rbx",
            "push rbp",
            "mov rbp, rsp",

            // Save original fn ptr and result ptr (they'll be clobbered
            // when we load the target's argument registers).
            "mov rbx, rdi",         // original
            "push rcx",             // result ptr at [rbp-16]

            // Load SSE registers from rdx.
            "movdqu xmm0, [rdx+0x00]",
            "movdqu xmm1, [rdx+0x10]",
            "movdqu xmm2, [rdx+0x20]",
            "movdqu xmm3, [rdx+0x30]",
            "movdqu xmm4, [rdx+0x40]",
            "movdqu xmm5, [rdx+0x50]",
            "movdqu xmm6, [rdx+0x60]",
            "movdqu xmm7, [rdx+0x70]",

            // Load integer registers from rsi (do this last — clobbers
            // rsi and rdi which we were using for our own args).
            "mov r9,  [rsi+40]",
            "mov r8,  [rsi+32]",
            "mov rcx, [rsi+24]",
            "mov rdx, [rsi+16]",
            "mov rax, rsi",         // save rsi ptr before clobbering
            "mov rsi, [rax+8]",
            "mov rdi, [rax+0]",

            // Align stack for the call: rbp is 16-aligned, we pushed
            // one extra (rcx), so rsp = rbp - 8 which is 16+8. Sub 8
            // to get 16-aligned before the call instruction.
            "sub rsp, 8",
            "call rbx",
            "add rsp, 8",

            // Write return values to CallResult.
            "mov rcx, [rbp-16]",    // result ptr
            "mov [rcx], rax",       // int_val = rax
            "movsd [rcx+8], xmm0", // float_val = xmm0

            "mov rsp, rbp",
            "pop rbp",
            "pop rbx",
            "ret",
        );
    }
}
