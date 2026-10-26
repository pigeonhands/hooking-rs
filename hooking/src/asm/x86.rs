use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderError, DecoderOptions, Instruction,
    InstructionBlock, InstructionInfoFactory, MemoryOperand, Register, code_asm::*,
};

use super::*;
use crate::sys;

pub use arch::MAX_PATCH_LEN;
use arch::*;

#[cfg(target_arch = "x86_64")]
mod arch {
    use iced_x86::code_asm::CodeAssembler;
    use iced_x86::{Code, Instruction, MemoryOperand, Register};

    use super::Result;
    use crate::ORIGINAL_FN_CHECKSUM_MAGIC;

    pub const BITNESS: u32 = 64;

    /// The longest patch: `jmp [rip+0]` followed by the 8 byte destination,
    /// used when the trampoline is out of rel32 range of the target.
    pub const MAX_PATCH_LEN: usize = 6 + 8;

    pub const JMP_REL32: Code = Code::Jmp_rel32_64;

    /// Pass the original function's address, read from `original_fn_slot`,
    /// in r10 with a checksum of it in r11, for `original_function_ptr`.
    pub fn pass_original_fn(original_fn_slot: usize) -> Result<Vec<Instruction>> {
        let slot = MemoryOperand::with_base_displ(Register::RIP, original_fn_slot as i64);
        let checksum = ORIGINAL_FN_CHECKSUM_MAGIC as u64;
        Ok(vec![
            Instruction::with2(Code::Mov_r64_rm64, Register::R10, slot)?,
            Instruction::with2(Code::Mov_r64_imm64, Register::R11, checksum)?,
            Instruction::with2(Code::Xor_r64_rm64, Register::R11, Register::R10)?,
        ])
    }

    /// x86_64 code finds its own address with RIP relative operands, which
    /// `relocate` already handles.
    pub unsafe fn relocate_pc_capture(
        _a: &mut CodeAssembler,
        _instr: &Instruction,
    ) -> Result<bool> {
        Ok(false)
    }
}

#[cfg(target_arch = "x86")]
mod arch {
    use iced_x86::code_asm::CodeAssembler;
    use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Register};

    use super::Result;

    pub const BITNESS: u32 = 32;

    /// rel32 offsets reach the whole 32bit address space, so the patch is
    /// always a `jmp rel32`.
    pub const MAX_PATCH_LEN: usize = 5;

    pub const JMP_REL32: Code = Code::Jmp_rel32_32;

    /// x86 passes arguments on the stack, and a hook's prologue is free to
    /// use any scratch register to copy them before its body runs, so there
    /// is no register that would reliably reach `original_function_ptr`.
    pub fn pass_original_fn(_original_fn_slot: usize) -> Result<Vec<Instruction>> {
        Ok(Vec::new())
    }

    /// Position independent x86 code finds its own address by calling the
    /// next instruction, or a `__x86.get_pc_thunk.*` helper, and reading the
    /// return address. Relocated as a real call it would see the relocated
    /// address, so these calls are emulated with the original one:
    ///     call next_ip           ->  push original_next_ip
    ///     call get_pc_thunk.reg  ->  mov reg, original_next_ip
    /// Returns whether `instr` was one of these.
    ///
    /// # Safety
    /// The target of `instr`, if it is a call, must be readable.
    pub unsafe fn relocate_pc_capture(a: &mut CodeAssembler, instr: &Instruction) -> Result<bool> {
        if instr.code() != Code::Call_rel32_32 {
            return Ok(false);
        }
        let target = instr.near_branch_target();
        let return_address = instr.next_ip() as u32;

        if target == instr.next_ip() {
            a.add_instruction(Instruction::with1(Code::Pushd_imm32, return_address)?)?;
            return Ok(true);
        }
        if let Some(reg) = unsafe { pc_thunk_register(target) } {
            a.add_instruction(Instruction::with2(
                Code::Mov_r32_imm32,
                reg,
                return_address,
            )?)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// The register loaded by the function at `address` if it is a
    /// `__x86.get_pc_thunk.*`:
    ///     mov reg, [esp]
    ///     ret
    ///
    /// # Safety
    /// `address` must be readable.
    unsafe fn pc_thunk_register(address: u64) -> Option<Register> {
        const THUNK_LEN: usize = 3 + 1;
        let code = unsafe { std::slice::from_raw_parts(address as *const u8, THUNK_LEN) };
        let mut decoder = Decoder::with_ip(BITNESS, code, address, DecoderOptions::NONE);
        let (mov, ret) = (decoder.decode(), decoder.decode());

        let loads_return_address = mov.code() == Code::Mov_r32_rm32
            && mov.memory_base() == Register::ESP
            && mov.memory_index() == Register::None
            && mov.memory_displacement32() == 0;
        (loads_return_address && ret.code() == Code::Retnd).then(|| mov.op0_register())
    }
}

/// Bytes the System V ABI lets functions use below `rsp` without moving it.
#[cfg(not(target_os = "windows"))]
const RED_ZONE: i64 = 128;
#[cfg(target_os = "windows")]
const RED_ZONE: i64 = 0;

/// Registers that can be borrowed to hold a far address. Only used on
/// x86_64, as nothing is out of range on x86.
const SCRATCH_REGISTERS: &[Register] = &[
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RBX,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];

/// Encode `instructions` to run at `ip`.
///
/// The block encoder re-targets relative branches and RIP relative operands
/// for the new address. Branches whose target is out of rel32 range are
/// rewritten to longer forms, e.g. `jcc` becomes the inverted condition
/// skipping over a `jmp [rip+x]`. Out of range RIP relative memory operands
/// are an error, so `relocate` rewrites those itself first.
fn encode(ip: usize, instructions: &[Instruction]) -> Result<Vec<u8>> {
    let block = InstructionBlock::new(instructions, ip as u64);
    let result = BlockEncoder::encode(BITNESS, block, BlockEncoderOptions::NONE)?;
    Ok(result.code_buffer)
}

/// The jump written over the start of the hooked function. It is kept as
/// short as possible, as every byte of it overwrites the target.
pub fn patch(ip: usize, trampoline: usize) -> Result<Vec<u8>> {
    let mut a = CodeAssembler::new(BITNESS)?;
    if sys::in_rel32_range(ip, trampoline) {
        a.jmp(trampoline as u64)?;
    } else {
        // x86_64 only: jmp [rip+0], with the destination straight after it.
        // The block encoder's own far form pads the destination to 8 byte
        // alignment.
        let mut destination = a.create_label();
        a.jmp(qword_ptr(destination))?;
        a.set_label(&mut destination)?;
        a.dq(&[trampoline as u64])?;
    }
    Ok(a.assemble(ip as u64)?)
}

/// Jumps to `destination_fn`, first passing it the original function where
/// the architecture allows (see `pass_original_fn`).
pub fn trampoline(ip: usize, destination_fn: usize, original_fn_slot: usize) -> Result<Vec<u8>> {
    let mut instructions = pass_original_fn(original_fn_slot)?;
    instructions.push(Instruction::with_branch(JMP_REL32, destination_fn as u64)?);
    encode(ip, &instructions)
}

/// Copy whole instructions from the start of `code` (which runs at `from`)
/// until at least `min_len` bytes are covered, adjusted to run at `to`, then
/// jump back to the first instruction that wasn't copied.
///
/// # Safety
/// The targets of calls in the copied instructions must be readable, as on
/// x86 they are checked for `__x86.get_pc_thunk.*` (see `relocate_pc_capture`).
pub unsafe fn relocate(code: &[u8], from: usize, to: usize, min_len: usize) -> Result<Vec<u8>> {
    let mut a = CodeAssembler::new(BITNESS)?;
    let mut decoder = Decoder::with_ip(BITNESS, code, from as u64, DecoderOptions::NONE);
    let mut info = InstructionInfoFactory::new();

    let mut copied = 0;
    while copied < min_len {
        if !decoder.can_decode() {
            return Err(AssemblyError::RelocationError);
        }
        let instr = decoder.decode();
        if decoder.last_error() != DecoderError::None {
            return Err(AssemblyError::RelocationError);
        }
        copied += instr.len();

        if unsafe { relocate_pc_capture(&mut a, &instr)? } {
            continue;
        }

        let is_far_memory_operand = instr.is_ip_rel_memory_operand()
            && !sys::in_rel32_range(to, instr.ip_rel_memory_address() as usize);
        if is_far_memory_operand {
            relocate_far_memory_operand(&mut a, &mut info, instr)?;
        } else {
            a.add_instruction(instr)?;
        }
    }

    a.jmp((from + copied) as u64)?;
    encode(to, a.instructions())
}

/// Rewrite an instruction whose RIP relative memory operand, at `address`,
/// is out of rel32 range of the relocated code. x86_64 only, as x86 has no
/// RIP relative operands. All rewrites preserve every register and flag
/// the original instruction didn't change.
fn relocate_far_memory_operand(
    a: &mut CodeAssembler,
    info: &mut InstructionInfoFactory,
    instr: Instruction,
) -> Result<()> {
    let address = instr.ip_rel_memory_address();

    match instr.code() {
        // `lea reg, [rip+x]` only computes the address, so load it directly:
        //     mov reg, address
        // Operand 0 is the destination register.
        Code::Lea_r64_m => {
            let reg = instr.op0_register();
            a.add_instruction(Instruction::with2(Code::Mov_r64_imm64, reg, address)?)?;
        }

        // `mov reg, [rip+x]` overwrites reg anyway, so use it to hold the address:
        //     mov reg, address
        //     mov reg, [reg]
        // Operand 0 is the destination register.
        Code::Mov_r64_rm64 => {
            let reg = instr.op0_register();
            a.add_instruction(Instruction::with2(Code::Mov_r64_imm64, reg, address)?)?;
            let load = MemoryOperand::with_base(reg);
            a.add_instruction(Instruction::with2(Code::Mov_r64_rm64, reg, load)?)?;
        }

        // `jmp [rip+x]`: jump to the pointer stored at address.
        Code::Jmp_rm64 => jmp_to_pointer_at(a, address)?,

        // `call [rip+x]`: call a thunk that jumps to the pointer at address.
        // The callee sees the normal stack layout and returns to the
        // `jmp after`, which continues after the thunk.
        //         call thunk
        //         jmp after
        // thunk:  (jmp_to_pointer_at address)
        // after:
        Code::Call_rm64 => {
            let mut thunk = a.create_label();
            let mut after = a.create_label();
            a.call(thunk)?;
            a.jmp(after)?;
            a.set_label(&mut thunk)?;
            jmp_to_pointer_at(a, address)?;
            a.set_label(&mut after)?;
        }

        // Anything else: borrow a register the instruction doesn't use to
        // hold the address.
        _ => with_scratch_register(a, info, instr, address)?,
    }

    Ok(())
}

/// Jump to the pointer stored at `address` with every register preserved
/// and the stack as it was:
///     push rax              ; save rax, making room for the destination
///     mov rax, address
///     mov rax, [rax]        ; the destination
///     xchg [rsp], rax       ; restore rax, leaving the destination on the stack
///     ret                   ; pop it and jump there
fn jmp_to_pointer_at(a: &mut CodeAssembler, address: u64) -> Result<()> {
    a.push(rax)?;
    a.mov(rax, address)?;
    a.mov(rax, qword_ptr(rax))?;
    a.xchg(qword_ptr(rsp), rax)?;
    a.ret()?;
    Ok(())
}

/// Run `instr` with its RIP relative operand replaced by a scratch register
/// holding `address`:
///     lea rsp, [rsp-128]    ; System V only: step over the red zone
///     push scratch
///     mov scratch, address
///     (instr, using [scratch])
///     pop scratch
///     lea rsp, [rsp+128]    ; System V only
/// `lea` is used to move `rsp` as it leaves the flags alone.
fn with_scratch_register(
    a: &mut CodeAssembler,
    info: &mut InstructionInfoFactory,
    mut instr: Instruction,
    address: u64,
) -> Result<()> {
    let used = info.info(&instr).used_registers();
    let uses = |reg: Register| {
        used.iter()
            .any(|used| used.register().full_register() == reg)
    };

    // Saving the scratch register moves rsp, which would change what an
    // instruction using the stack sees.
    let unsupported = AssemblyError::UnsupportedRelocation(instr.code());
    if uses(Register::RSP) {
        return Err(unsupported);
    }
    let scratch = *SCRATCH_REGISTERS
        .iter()
        .find(|&&reg| !uses(reg))
        .ok_or(unsupported)?;

    instr.set_memory_base(scratch);
    instr.set_memory_displacement64(0);
    instr.set_memory_displ_size(0);

    if RED_ZONE != 0 {
        a.lea(rsp, qword_ptr(rsp - RED_ZONE))?;
    }
    a.add_instruction(Instruction::with1(Code::Push_r64, scratch)?)?;
    a.add_instruction(Instruction::with2(Code::Mov_r64_imm64, scratch, address)?)?;
    a.add_instruction(instr)?;
    a.add_instruction(Instruction::with1(Code::Pop_r64, scratch)?)?;
    if RED_ZONE != 0 {
        a.lea(rsp, qword_ptr(rsp + RED_ZONE))?;
    }

    Ok(())
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use iced_x86::Formatter;

    const FROM: usize = 0x7000_0000_0000;
    const NEAR: usize = FROM + 0x1000;
    const FAR: usize = FROM + 0x1_0000_0000;
    const DATA: usize = FROM + 0x100;
    const DATA_HEX: &str = "700000000100h";

    fn rip_data() -> MemoryOperand {
        MemoryOperand::with_base_displ(Register::RIP, DATA as i64)
    }

    /// Encode `instructions` at `FROM`, padded so the decoder never runs out of bytes.
    fn assemble(instructions: &[Instruction]) -> Vec<u8> {
        let mut instructions = instructions.to_vec();
        instructions.push(Instruction::with(Code::Int3));
        encode(FROM, &instructions).unwrap()
    }

    fn decode(bytes: &[u8], ip: usize) -> Vec<Instruction> {
        Decoder::with_ip(64, bytes, ip as u64, DecoderOptions::NONE)
            .into_iter()
            .collect()
    }

    fn disassemble(bytes: &[u8], ip: usize) -> Vec<String> {
        let mut formatter = iced_x86::IntelFormatter::new();
        decode(bytes, ip)
            .iter()
            .map(|instr| {
                let mut out = String::new();
                formatter.format(instr, &mut out);
                out
            })
            .collect()
    }

    /// Relocate code from `FROM`. It has no calls to `__x86.get_pc_thunk.*`
    /// candidates to read, as those are only looked for on x86.
    fn relocate_from(code: &[u8], to: usize, min_len: usize) -> Result<Vec<u8>> {
        unsafe { relocate(code, FROM, to, min_len) }
    }

    fn relocate_one(instruction: Instruction, to: usize) -> Vec<String> {
        let relocated = relocate_from(&assemble(&[instruction]), to, 1).unwrap();
        disassemble(&relocated, to)
    }

    /// The 64bit value a `jmp/call qword ptr [rip+x]` in `bytes` reads.
    fn pointer_read_by(instr: &Instruction, bytes: &[u8], ip: usize) -> u64 {
        let offset = instr.ip_rel_memory_address() as usize - ip;
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    #[test]
    fn near_patch_is_a_rel32_jmp() {
        let near = patch(FROM, NEAR).unwrap();
        assert_eq!(near.len(), 5);
        assert_eq!(decode(&near, FROM)[0].near_branch_target(), NEAR as u64);
    }

    #[test]
    fn far_patch_is_an_unpadded_indirect_jmp() {
        let far = patch(FROM, FAR).unwrap();
        assert_eq!(far.len(), MAX_PATCH_LEN);
        let jmp = &decode(&far, FROM)[0];
        assert_eq!(jmp.code(), Code::Jmp_rm64);
        assert_eq!(pointer_read_by(jmp, &far, FROM), FAR as u64);
    }

    #[test]
    fn near_rip_relative_is_kept() {
        let instr = Instruction::with2(Code::Mov_r64_rm64, Register::RAX, rip_data()).unwrap();
        assert_eq!(
            relocate_one(instr, NEAR)[0],
            format!("mov rax,[{DATA_HEX}]")
        );
    }

    #[test]
    fn far_lea() {
        let instr = Instruction::with2(Code::Lea_r64_m, Register::RCX, rip_data()).unwrap();
        assert_eq!(relocate_one(instr, FAR)[0], format!("mov rcx,{DATA_HEX}"));
    }

    #[test]
    fn far_mov_r64() {
        let instr = Instruction::with2(Code::Mov_r64_rm64, Register::R10, rip_data()).unwrap();
        assert_eq!(
            relocate_one(instr, FAR)[..2],
            [format!("mov r10,{DATA_HEX}"), "mov r10,[r10]".into()]
        );
    }

    #[test]
    fn far_jmp_indirect() {
        let instr = Instruction::with1(Code::Jmp_rm64, rip_data()).unwrap();
        assert_eq!(
            relocate_one(instr, FAR)[..5],
            [
                "push rax".to_string(),
                format!("mov rax,{DATA_HEX}"),
                "mov rax,[rax]".into(),
                "xchg [rsp],rax".into(),
                "ret".into(),
            ]
        );
    }

    #[test]
    fn far_call_indirect() {
        let instr = Instruction::with1(Code::Call_rm64, rip_data()).unwrap();
        let out = relocate_one(instr, FAR);
        assert!(out[0].starts_with("call "), "{out:?}");
        assert!(out[1].starts_with("jmp "), "{out:?}");
        assert_eq!(
            out[2..7],
            relocate_one(Instruction::with1(Code::Jmp_rm64, rip_data()).unwrap(), FAR)[..5]
        );
    }

    #[test]
    fn far_other_instructions_use_an_unused_register() {
        // cmpxchg uses rax and rcx, so rdx is borrowed.
        let instr = Instruction::with2(Code::Cmpxchg_rm32_r32, rip_data(), Register::ECX).unwrap();
        let mut expected = vec![
            "push rdx".to_string(),
            format!("mov rdx,{DATA_HEX}"),
            "cmpxchg [rdx],ecx".into(),
            "pop rdx".into(),
        ];
        if RED_ZONE != 0 {
            expected.insert(0, "lea rsp,[rsp-80h]".into());
            expected.push("lea rsp,[rsp+80h]".into());
        }
        assert_eq!(relocate_one(instr, FAR)[..expected.len()], expected);
    }

    #[test]
    fn far_stack_users_are_refused() {
        let code = assemble(&[Instruction::with1(Code::Push_rm64, rip_data()).unwrap()]);
        assert!(matches!(
            relocate_from(&code, FAR, 1),
            Err(AssemblyError::UnsupportedRelocation(Code::Push_rm64))
        ));
    }

    #[test]
    fn far_conditional_branches_reach_original_target() {
        let target = (FROM + 0x50) as u64;
        let branches = [
            (Code::Je_rel8_64, Code::Jne_rel8_64),
            (Code::Je_rel32_64, Code::Jne_rel8_64),
            (Code::Jb_rel32_64, Code::Jae_rel8_64),
            (Code::Jl_rel8_64, Code::Jge_rel8_64),
            (Code::Js_rel32_64, Code::Jns_rel8_64),
        ];

        for (code, inverted) in branches {
            let original = assemble(&[Instruction::with_branch(code, target).unwrap()]);
            let branch_len = original.len() - 1;
            let relocated = relocate_from(&original, FAR, 1).unwrap();
            let out = decode(&relocated, FAR);

            // The inverted condition skips an absolute jump to the original target...
            let (skip, jmp, back) = (&out[0], &out[1], &out[2]);
            assert_eq!(skip.code(), inverted, "{code:?}");
            assert_eq!(skip.near_branch_target(), jmp.next_ip(), "{code:?}");
            assert_eq!(jmp.code(), Code::Jmp_rm64, "{code:?}");
            assert_eq!(pointer_read_by(jmp, &relocated, FAR), target, "{code:?}");

            // ...to the jump back to the original function.
            assert_eq!(back.ip(), jmp.next_ip(), "{code:?}");
            assert_eq!(
                pointer_read_by(back, &relocated, FAR),
                (FROM + branch_len) as u64
            );
        }
    }

    #[test]
    fn far_loop_and_jrcxz_reach_original_target() {
        let target = (FROM + 0x50) as u64;
        for code in [Code::Loop_rel8_64_RCX, Code::Jrcxz_rel8_64] {
            let original = assemble(&[Instruction::with_branch(code, target).unwrap()]);
            let relocated = relocate_from(&original, FAR, 1).unwrap();
            let out = decode(&relocated, FAR);

            // The branch keeps its condition and lands on an absolute jump
            // to the original target.
            let branch = &out[0];
            assert_eq!(branch.code(), code);
            let landing = out
                .iter()
                .find(|instr| instr.ip() == branch.near_branch_target())
                .expect("branch lands on an instruction");
            assert_eq!(landing.code(), Code::Jmp_rm64, "{code:?}");
            assert_eq!(
                pointer_read_by(landing, &relocated, FAR),
                target,
                "{code:?}"
            );
        }
    }

    #[test]
    fn far_call_uses_long_form() {
        let target = (FROM + 0x50) as u64;
        let original = assemble(&[Instruction::with_branch(Code::Call_rel32_64, target).unwrap()]);
        let relocated = relocate_from(&original, FAR, 1).unwrap();
        let call = &decode(&relocated, FAR)[0];
        assert_eq!(call.code(), Code::Call_rm64);
        assert_eq!(pointer_read_by(call, &relocated, FAR), target);
    }

    #[test]
    fn copies_whole_instructions_then_jumps_back() {
        let code = assemble(&[
            Instruction::with1(Code::Push_r64, Register::RBP).unwrap(),
            Instruction::with2(Code::Mov_rm64_r64, Register::RBP, Register::RSP).unwrap(),
            Instruction::with2(Code::Sub_rm64_imm8, Register::RSP, 0x20u32).unwrap(),
        ]);
        // 5 bytes ends inside `sub rsp, 0x20`, so all 8 bytes are copied.
        let out = disassemble(&relocate_from(&code, NEAR, 5).unwrap(), NEAR);
        assert_eq!(out[3], format!("jmp {:016X}h", FROM + 8));
    }
}

#[cfg(all(test, target_arch = "x86"))]
mod tests {
    use super::*;

    const LOW: usize = 0x1000_0000;
    const HIGH: usize = 0xF000_0000;

    fn decode(bytes: &[u8], ip: usize) -> Vec<Instruction> {
        Decoder::with_ip(32, bytes, ip as u64, DecoderOptions::NONE)
            .into_iter()
            .collect()
    }

    #[test]
    fn patch_reaches_across_the_address_space() {
        for (from, to) in [(LOW, HIGH), (HIGH, LOW)] {
            let patch = patch(from, to).unwrap();
            assert_eq!(patch.len(), MAX_PATCH_LEN);
            let jmp = &decode(&patch, from)[0];
            assert_eq!(jmp.code(), Code::Jmp_rel32_32);
            assert_eq!(jmp.near_branch_target(), to as u64);
        }
    }

    #[test]
    fn trampoline_only_jumps() {
        let trampoline = decode(&trampoline(LOW, HIGH, LOW - 4).unwrap(), LOW);
        assert_eq!(trampoline.len(), 1);
        assert_eq!(trampoline[0].near_branch_target(), HIGH as u64);
    }

    /// The bytes of `__x86.get_pc_thunk.bx`: mov ebx, [esp]; ret
    static PC_THUNK_BX: [u8; 4] = [0x8B, 0x1C, 0x24, 0xC3];
    /// Something that isn't a thunk, for calls to be read from.
    static NOT_A_THUNK: [u8; 4] = [0x90, 0x90, 0x90, 0xC3];

    fn relocate_from_low(instructions: &[Instruction], min_len: usize) -> Vec<Instruction> {
        let mut instructions = instructions.to_vec();
        instructions.push(Instruction::with(Code::Int3));
        let original = encode(LOW, &instructions).unwrap();
        decode(
            &unsafe { relocate(&original, LOW, HIGH, min_len) }.unwrap(),
            HIGH,
        )
    }

    #[test]
    fn call_next_instruction_pushes_original_address() {
        let call_next = Instruction::with_branch(Code::Call_rel32_32, (LOW + 5) as u64).unwrap();
        let out = relocate_from_low(&[call_next], 1);
        assert_eq!(out[0].code(), Code::Pushd_imm32);
        assert_eq!(out[0].immediate32(), (LOW + 5) as u32);
    }

    #[test]
    fn call_pc_thunk_loads_original_address() {
        let thunk = PC_THUNK_BX.as_ptr() as u64;
        let call_thunk = Instruction::with_branch(Code::Call_rel32_32, thunk).unwrap();
        let out = relocate_from_low(&[call_thunk], 1);
        assert_eq!(out[0].code(), Code::Mov_r32_imm32);
        assert_eq!(out[0].op0_register(), Register::EBX);
        assert_eq!(out[0].immediate32(), (LOW + 5) as u32);
    }

    #[test]
    fn relocated_branches_keep_their_targets() {
        let target = NOT_A_THUNK.as_ptr() as u64;
        let je = Instruction::with_branch(Code::Je_rel32_32, target).unwrap();
        let call = Instruction::with_branch(Code::Call_rel32_32, target).unwrap();
        let copied_len = 6 + 5;

        let out = relocate_from_low(&[je, call], copied_len);
        assert_eq!(out[0].code(), Code::Je_rel32_32);
        assert_eq!(out[0].near_branch_target(), target);
        assert_eq!(out[1].code(), Code::Call_rel32_32);
        assert_eq!(out[1].near_branch_target(), target);
        assert_eq!(out[2].near_branch_target(), (LOW + copied_len) as u64);
    }
}
