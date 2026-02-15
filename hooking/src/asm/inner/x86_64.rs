use iced_x86::{
    BlockEncoder, BlockEncoderResult, Code, Decoder, DecoderOptions, Encoder, Instruction,
    InstructionBlock, MemoryOperand, Register,
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
        let block = InstructionBlock::new(&instructions, eip as u64);
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
        min_size_bytes: usize,
        add_jump: bool,
    ) -> Result<Vec<u8>> {
        let target_fn_data = unsafe {
            core::slice::from_raw_parts(source_address.as_ptr() as *const u8, min_size_bytes + 20)
        };

        let mut encoder = Encoder::new(self.bitness());

        let mut decoder = Decoder::with_ip(64, target_fn_data, eip as u64, DecoderOptions::NONE);

        let mut relitive_eip = 0;

        while relitive_eip < min_size_bytes {
            if !decoder.can_decode() {
                return Err(AssemblyError::RelocationError);
            }
            let instr = decoder.decode();
            let encoded = encoder.encode(&instr, (eip + relitive_eip) as u64)?;
            relitive_eip += encoded;
        }

        let additional_instructions: &[Instruction] = if add_jump {
            let sym_addr_after_replaced = source_address.as_ptr() as u64 + relitive_eip as u64;
            &[
                Instruction::with_branch(Code::Jmp_rel32_64, sym_addr_after_replaced)?,
                Instruction::with(Code::Nopd),
            ]
        } else {
            &[]
        };

        for instr in additional_instructions {
            relitive_eip += encoder.encode(&instr, (eip + relitive_eip) as u64)?;
        }

        let buffer = encoder.take_buffer();

        Ok(buffer)
    }
}
