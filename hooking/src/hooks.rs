use core::ffi;
use core::{ffi::CStr, ptr::NonNull};
use iced_x86::{
    BlockEncoder, BlockEncoderResult, Code, Decoder, DecoderOptions, Encoder, Instruction,
    InstructionBlock, Register,
};

use crate::table::{HookHeap, HookHeapWriter};

static HOOK_HEAP: HookHeap = HookHeap::new();

#[derive(Debug)]
pub struct Hook<'a> {
    pub data: HookData<'a>,
}

impl<'a> Hook<'a> {
    pub fn apply_hook(&mut self) {}
}

#[derive(Debug)]
pub struct HookData<'a> {
    pub symbol_address: NonNull<ffi::c_void>,
    pub trampoline_data: &'a [u8],
    pub restore_data: &'a [u8],
}

pub struct HookWriter<'a> {
    hook_heap: &'a HookHeap,
}

impl<'a> HookWriter<'a> {
    pub const fn new(hook_heap: &'a HookHeap) -> Self {
        Self { hook_heap }
    }
    pub const fn from_static() -> Self {
        Self::new(&HOOK_HEAP)
    }

    fn bitness(&self) -> u32 {
        #[cfg(target_pointer_width = "64")]
        let bitness = 64;

        #[cfg(target_pointer_width = "32")]
        let bitness = 32;

        bitness
    }

    pub unsafe fn write_hook(
        &self,
        module: Option<&CStr>,
        symbol: &CStr,
        destination: *mut u8,
    ) -> Option<Hook<'a>> {
        let destination_fn = NonNull::new(destination as *mut ffi::c_void)?;

        let module_handle = if let Some(module_name) = module {
            ModuleHandle::from_name(module_name)?
        } else {
            ModuleHandle::none()
        };

        let sym_addr =
            NonNull::new(unsafe { libc::dlsym(module_handle.handle(), symbol.as_ptr()) })?;

        let data = unsafe { self.write_hook_table(sym_addr, destination_fn)? };

        Some(Hook { data })
    }

    fn write_instructions(
        &self,
        eip: usize,
        instructions: &[Instruction],
    ) -> Option<BlockEncoderResult> {
        let block = InstructionBlock::new(&instructions, eip as u64);
        let result = BlockEncoder::encode(self.bitness(), block, 0).ok()?;
        Some(result)
    }

    pub unsafe fn write_hook_table(
        &self,
        sym_addr: NonNull<ffi::c_void>,
        destination_fn: NonNull<ffi::c_void>,
    ) -> Option<HookData<'a>> {
        let mut write_lock = self.hook_heap.start_write();
        let mut rip = write_lock.current_address()? as usize;

        let (hook_frame, _hook_frame_size) = {
            let result = self.write_instructions(
                rip,
                &[
                    Instruction::with_branch(Code::Jmp_rel32_64, destination_fn.as_ptr() as u64)
                        .ok()?,
                    Instruction::with(Code::Nopd),
                ],
            )?;

            let code_addr = write_lock.write_bytes(&result.code_buffer)?;
            let code_size = result.code_buffer.len() as usize;

            rip += code_size;
            (code_addr, code_size)
        };

        let (trampoline_addr, trampoline_size) = {
            let result = self.write_instructions(
                rip,
                &[
                    Instruction::with_branch(Code::Jmp_rel32_64, hook_frame.as_ptr() as u64)
                        .ok()?,
                    Instruction::with(Code::Nopd),
                ],
            )?;

            let code_addr = write_lock.write_bytes(&result.code_buffer)?;
            let code_size = result.code_buffer.len() as usize;

            rip += code_size;
            (code_addr, code_size)
        };

        let (restore_hook_addr, restore_hook_size) = {
            let mut encoder = Encoder::new(self.bitness());

            let target_fn_data = unsafe {
                core::slice::from_raw_parts(sym_addr.as_ptr() as *const u8, trampoline_size + 15)
            };

            let mut decoder =
                Decoder::with_ip(64, target_fn_data, rip as u64, DecoderOptions::NONE);

            let mut instructions_read = 0;

            while instructions_read < trampoline_size {
                if !decoder.can_decode() {
                    return None;
                }
                let instr = decoder.decode();
                encoder.encode(&instr, rip as u64).ok()?;
                rip += instr.len();
                instructions_read += instr.len();
            }

            let additional_instructions = [
                Instruction::with_branch(Code::Jmp_rel32_64, unsafe {
                    sym_addr.add(instructions_read).as_ptr() as u64
                })
                .ok()?,
                Instruction::with(Code::Nopd),
            ];

            for instr in &additional_instructions {
                encoder.encode(&instr, rip as u64).ok()?;
                rip += instr.len();
            }

            let buffer = encoder.take_buffer();

            let code_addr = write_lock.write_bytes(&buffer)?;
            let code_size = buffer.len() as usize;

            (code_addr, code_size)
        };

        Some(HookData {
            symbol_address: sym_addr,
            trampoline_data: unsafe {
                core::slice::from_raw_parts(trampoline_addr.as_ptr() as *const _, trampoline_size)
            },
            restore_data: unsafe {
                core::slice::from_raw_parts(
                    restore_hook_addr.as_ptr() as *const _,
                    restore_hook_size,
                )
            },
        })
    }
}
#[derive(Debug, Clone)]
enum ModuleHandle {
    None,
    Libc(NonNull<ffi::c_void>),
}

impl ModuleHandle {
    pub fn none() -> Self {
        Self::None
    }
    pub fn from_name(module_name: &CStr) -> Option<Self> {
        let handle = unsafe { libc::dlopen(module_name.as_ptr(), libc::RTLD_LAZY) };

        if handle.is_null() {
            None
        } else {
            NonNull::new(handle).map(Self::Libc)
        }
    }
    pub fn handle(&self) -> *mut ffi::c_void {
        match self {
            Self::None => libc::RTLD_DEFAULT as *mut ffi::c_void,
            Self::Libc(handle) => handle.as_ptr(),
        }
    }
}
