use core::ffi;
use core::{ffi::CStr, ptr::NonNull};
use iced_x86::{
    BlockEncoder, BlockEncoderResult, Code, Decoder, DecoderOptions, Encoder, Instruction,
    InstructionBlock, MemoryOperand, Register,
};

use crate::mem::ExecWriteGuard;
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
    ) -> Result<Hook<'a>, ()> {
        let destination_fn = NonNull::new(destination as *mut ffi::c_void).ok_or(())?;

        let module_handle = if let Some(module_name) = module {
            ModuleHandle::from_name(module_name).ok_or(())?
        } else {
            ModuleHandle::none()
        };

        let sym_addr =
            NonNull::new(unsafe { libc::dlsym(module_handle.handle(), symbol.as_ptr()) })
                .ok_or(())?;

        unsafe { self.write_hook_fn_ptr(sym_addr, destination_fn) }
    }
    pub unsafe fn write_hook_fn_ptr(
        &self,
        target: NonNull<ffi::c_void>,
        destination: NonNull<ffi::c_void>,
    ) -> Result<Hook<'a>, ()> {
        let data = unsafe { self.write_hook_table(target, destination)? };
        Ok(Hook { data })
    }

    fn write_instructions(
        &self,
        eip: usize,
        instructions: &[Instruction],
    ) -> Result<BlockEncoderResult, ()> {
        let block = InstructionBlock::new(&instructions, eip as u64);
        let result = BlockEncoder::encode(self.bitness(), block, 0).unwrap();
        Ok(result)
    }

    pub unsafe fn write_hook_table(
        &self,
        sym_addr: NonNull<ffi::c_void>,
        destination_fn: NonNull<ffi::c_void>,
    ) -> Result<HookData<'a>, ()> {
        let mut write_lock = self.hook_heap.start_write();
        let _write_guard = write_lock.make_heap_writable()?;

        write_lock.allocate_heap();

        let restore_fn_ptr =
            write_lock.write_bytes(&(0xaaaaaaaaaaaaaaaa as usize).to_be_bytes())?;

        let mut rip = write_lock.current_address()? as usize;

        let (trampoline_addr, trampoline_size) = {
            let result = self.write_instructions(
                rip,
                &[
                    Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::R10,
                        MemoryOperand::with_base_displ(
                            Register::RIP,
                            restore_fn_ptr.as_ptr() as i64,
                        ),
                    )
                    .map_err(|_| ())?,
                    Instruction::with_branch(Code::Jmp_rel32_64, destination_fn.as_ptr() as u64)
                        .map_err(|_| ())?,
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
                    return Err(());
                }
                let instr = decoder.decode();
                let encoded = encoder.encode(&instr, rip as u64).map_err(|_| ())?;
                rip += encoded;
                instructions_read += encoded;
            }

            let sym_addr_after_replaced = sym_addr.as_ptr() as u64 + instructions_read as u64;
            let additional_instructions = [
                Instruction::with_branch(Code::Jmp_rel32_64, sym_addr_after_replaced)
                    .map_err(|_| ())?,
                Instruction::with(Code::Nopd),
            ];

            for instr in &additional_instructions {
                encoder.encode(&instr, rip as u64).map_err(|_| ())?;
                rip += instr.len();
            }

            let buffer = encoder.take_buffer();

            let code_addr = write_lock.write_bytes(&buffer)?;
            let code_size = buffer.len() as usize;

            (code_addr, code_size)
        };

        unsafe {
            let write_restore_addr: usize = restore_hook_addr.as_ptr() as usize;
            restore_fn_ptr.cast().write(write_restore_addr);
            //     core::ptr::copy_nonoverlapping(
            //         restore_hook_addr.as_ptr(),
            //         restore_fn_ptr.as_ptr(),
            //         core::mem::size_of::<usize>(),
            //     );
        }

        Ok(HookData {
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
