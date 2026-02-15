use iced_x86::{
    BlockEncoder, BlockEncoderResult, Code, ConditionCode, Decoder, DecoderOptions, Instruction,
    InstructionBlock, MemoryOperand, Register, code_asm::*,
};
use std::{ffi::c_void, ptr::NonNull};

use super::super::*;

pub type InnerError = iced_x86::IcedError;

pub struct HookAssemblerx86_64;

impl HookAssemblerx86_64 {
    pub const fn new() -> Self {
        Self
    }

    fn bitness(&self) -> u32 {
        #[cfg(target_pointer_width = "64")]
        let bitness = 64;

        #[cfg(target_pointer_width = "32")]
        let bitness = 32;

        bitness
    }
    fn assemble_instruction_block(
        &self,
        eip: usize,
        instructions: &[Instruction],
    ) -> Result<BlockEncoderResult> {
        let block = InstructionBlock::new(instructions, eip as u64);
        let result = BlockEncoder::encode(self.bitness(), block, 0)?;
        Ok(result)
    }
}

impl HookAssembler for HookAssemblerx86_64 {
    fn assemble_trampoline(
        &self,
        eip: usize,
        destination_fn: NonNull<c_void>,
        restore_fn_address: Option<NonNull<c_void>>,
    ) -> Result<Vec<u8>> {
        let set_restore_fn_instructon = if let Some(restore_fn_address) = restore_fn_address {
            Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R10,
                MemoryOperand::with_base_displ(Register::RIP, restore_fn_address.as_ptr() as i64),
            )?
        } else {
            Instruction::new()
            //Instruction::with(Code::Nopd)
        };

        let instructions = &[
            set_restore_fn_instructon,
            Instruction::with_branch(Code::Jmp_rel32_64, destination_fn.as_ptr() as u64)?,
            Instruction::with(Code::Nopd),
        ];

        let assembled = self.assemble_instruction_block(eip, instructions)?;
        Ok(assembled.code_buffer)
    }

    fn assemble_patch(&self, eip: usize, destination_fn: NonNull<c_void>) -> Result<Vec<u8>> {
        let instructions = &[Instruction::with_branch(
            Code::Jmp_rel32_64,
            destination_fn.as_ptr() as u64,
        )?];

        let assembled = self.assemble_instruction_block(eip, instructions)?;
        Ok(assembled.code_buffer)
    }

    fn relocate_instructions(
        &self,
        eip: usize,
        source_address: NonNull<c_void>,
        patch_size: usize,
        add_jump: bool,
    ) -> Result<Vec<u8>> {
        let target_fn_data = unsafe {
            core::slice::from_raw_parts(source_address.as_ptr() as *const u8, patch_size + 20)
        };

        let mut a = CodeAssembler::new(self.bitness())?;

        let mut decoder = Decoder::with_ip(
            self.bitness(),
            target_fn_data,
            source_address.as_ptr() as u64,
            DecoderOptions::NONE,
        );

        let mut instruction_size_read = 0;
        while instruction_size_read < patch_size {
            if !decoder.can_decode() {
                return Err(AssemblyError::RelocationError);
            }
            let mut instr = decoder.decode();
            instruction_size_read += instr.len();

            let mem_displacement = instr.memory_displacement64();
            if self.bitness() == 64 && mem_displacement != 0 {
                //  relative addressing is done with 32bit offsets
                //  even on 64bit. Move the absolute address into a reg
                //  then patch the instruction to use the register.

                if instr.memory_base() == Register::RIP {
                    a.push(r10)?;
                    a.mov(r10, mem_displacement)?;

                    instr.set_memory_base(Register::R10);
                    instr.set_memory_displacement64(0);
                    a.add_instruction(instr)?;

                    a.pop(r10)?;
                } else if instr.is_call_near() {
                    // a.push(r10)?;
                    // a.mov(r10, mem_displacement)?;
                    // a.call(r10)?;
                    // a.pop(r10)?;

                    let mut rip_0 = a.create_label();
                    a.call(rip_0)?;
                    a.set_label(&mut rip_0)?;
                    a.dq(&[mem_displacement])?;
                } else if instr.is_jmp_short_or_near() {
                    // a.mov(r10, mem_displacement)?;
                    // a.jmp(r10)?;
                    a.db(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00])?; //JMP [RAX+0]
                    a.dq(&[mem_displacement])?;
                } else if instr.is_jcc_short_or_near() {
                    // there is no such thing as a conditional 64bit jump
                    // so we create a non-conditional jump and cnditionally
                    // skip it if the reverse conditional is true.

                    let mut skip_to = a.create_label();

                    match instr.condition_code() {
                        ConditionCode::e => a.jne(skip_to)?,
                        ConditionCode::ne => a.je(skip_to)?,
                        ConditionCode::b => a.jae(skip_to)?,
                        ConditionCode::ae => a.jb(skip_to)?,
                        ConditionCode::be => a.ja(skip_to)?,
                        ConditionCode::a => a.jbe(skip_to)?,
                        ConditionCode::l => a.jge(skip_to)?,
                        ConditionCode::ge => a.jl(skip_to)?,
                        ConditionCode::le => a.jg(skip_to)?,
                        ConditionCode::g => a.jle(skip_to)?,
                        ConditionCode::p => a.jnp(skip_to)?,
                        ConditionCode::np => a.jp(skip_to)?,
                        ConditionCode::o => a.jno(skip_to)?,
                        ConditionCode::no => a.jo(skip_to)?,
                        ConditionCode::s => a.jns(skip_to)?,
                        ConditionCode::ns => a.js(skip_to)?,
                        ConditionCode::None => a.jmp(skip_to)?,
                    };

                    // a.push(r10)?;
                    // a.mov(r10, mem_displacement)?;
                    // a.jmp(r10)?;
                    // a.pop(r10)?;

                    // JMP [RIP+0]
                    a.db(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00])?;
                    a.dq(&[mem_displacement])?;

                    a.set_label(&mut skip_to)?;
                } else {
                    a.add_instruction(instr)?;
                }
            } else {
                a.add_instruction(instr)?;
            }
        }

        if add_jump {
            a.jmp((source_address.as_ptr() as usize + patch_size) as u64)?;
            a.nop()?;
        }

        let buffer = self.assemble_instruction_block(eip, a.instructions())?;

        Ok(buffer.code_buffer)
    }
}
