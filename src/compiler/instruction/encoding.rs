use super::*;

impl EbpfInsn {
    /// Create a new instruction
    pub const fn new(opcode: u8, dst_reg: u8, src_reg: u8, offset: i16, imm: i32) -> Self {
        Self {
            opcode,
            dst_reg,
            src_reg,
            offset,
            imm,
        }
    }

    /// Encode the instruction to 8 bytes (little-endian)
    pub fn encode(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0] = self.opcode;
        bytes[1] = (self.src_reg << 4) | (self.dst_reg & 0x0f);
        bytes[2..4].copy_from_slice(&self.offset.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.imm.to_le_bytes());
        bytes
    }

    // ===== Instruction builders =====

    /// MOV64 dst, imm - Load 32-bit immediate into 64-bit register (sign-extends)
    pub const fn mov64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::MOV64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// MOV32 dst, imm - Load 32-bit immediate into lower 32 bits of register (zeros upper bits)
    pub const fn mov32_imm(dst: EbpfReg, imm: i32) -> Self {
        // BPF_ALU (32-bit) | BPF_MOV | BPF_K = 0x04 | 0xb0 | 0x00 = 0xb4
        Self::new(0xb4, dst.as_u8(), 0, 0, imm)
    }

    /// MOV64 dst, src - Copy register
    pub const fn mov64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::MOV64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// ADD64 dst, imm - Add immediate to register
    pub const fn add64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::ADD64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// ADD64 dst, src - Add register to register
    pub const fn add64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::ADD64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// SUB64 dst, imm - Subtract immediate from register
    pub const fn sub64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::SUB64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// SUB64 dst, src - Subtract register from register
    pub const fn sub64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::SUB64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// MUL64 dst, imm - Multiply register by immediate
    pub const fn mul64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::MUL64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// MUL64 dst, src - Multiply register by register
    pub const fn mul64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::MUL64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// DIV64 dst, imm - Divide register by immediate
    pub const fn div64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::DIV64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// DIV64 dst, src - Divide register by register
    pub const fn div64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::DIV64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// MOD64 dst, imm - Modulo register by immediate
    pub const fn mod64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::MOD64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// MOD64 dst, src - Modulo register by register
    pub const fn mod64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::MOD64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// OR64 dst, imm - Bitwise OR register with immediate
    pub const fn or64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::OR64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// OR64 dst, src - Bitwise OR register with register
    pub const fn or64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::OR64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// AND64 dst, imm - Bitwise AND register with immediate
    pub const fn and64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::AND64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// AND32 dst, imm - Bitwise AND lower 32 bits with immediate (zeros upper bits)
    pub const fn and32_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(
            opcode::BPF_ALU | opcode::BPF_AND | opcode::BPF_K,
            dst.as_u8(),
            0,
            0,
            imm,
        )
    }

    /// AND64 dst, src - Bitwise AND register with register
    pub const fn and64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::AND64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// XOR64 dst, imm - Bitwise XOR register with immediate
    pub const fn xor64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::XOR64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// XOR64 dst, src - Bitwise XOR register with register
    pub const fn xor64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::XOR64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// LSH64 dst, imm - Left shift register by immediate
    pub const fn lsh64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::LSH64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// LSH64 dst, src - Left shift register by register
    pub const fn lsh64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::LSH64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// RSH64 dst, imm - Right shift register by immediate
    pub const fn rsh64_imm(dst: EbpfReg, imm: i32) -> Self {
        Self::new(opcode::RSH64_IMM, dst.as_u8(), 0, 0, imm)
    }

    /// RSH64 dst, src - Right shift register by register
    pub const fn rsh64_reg(dst: EbpfReg, src: EbpfReg) -> Self {
        Self::new(opcode::RSH64_REG, dst.as_u8(), src.as_u8(), 0, 0)
    }

    /// CALL helper - Call a BPF helper function
    pub const fn call(helper: BpfHelper) -> Self {
        Self::new(opcode::CALL, 0, 0, 0, helper as i32)
    }

    /// CALL local - BPF-to-BPF function call (src=1 indicates local call)
    /// The imm field contains the offset to the target function in instructions
    pub const fn call_local(offset: i32) -> Self {
        // src_reg = 1 (BPF_PSEUDO_CALL) indicates this is a local function call
        Self::new(opcode::CALL, 0, 1, 0, offset)
    }

    /// CALL kfunc - BPF kfunc call (src=2 indicates BPF_PSEUDO_KFUNC_CALL)
    /// The imm field contains the kernel BTF ID for a BTF_KIND_FUNC.
    pub const fn call_kfunc(btf_id: i32) -> Self {
        Self::new(opcode::CALL, 0, 2, 0, btf_id)
    }

    /// EXIT - Exit the eBPF program (return value in r0)
    pub const fn exit() -> Self {
        Self::new(opcode::EXIT, 0, 0, 0, 0)
    }

    /// JA offset - Unconditional jump (offset is relative to next instruction)
    pub const fn jump(offset: i16) -> Self {
        Self::new(opcode::BPF_JMP | opcode::BPF_JA, 0, 0, offset, 0)
    }

    /// JNE dst, src, offset - Jump if dst != src (unsigned)
    pub const fn jne_reg(dst: EbpfReg, src: EbpfReg, offset: i16) -> Self {
        Self::new(
            opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_X,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// JEQ dst, imm, offset - Jump if dst == imm
    pub const fn jeq_imm(dst: EbpfReg, imm: i32, offset: i16) -> Self {
        Self::new(
            opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_K,
            dst.as_u8(),
            0,
            offset,
            imm,
        )
    }

    /// JEQ dst, src, offset - Jump if dst == src (register comparison)
    pub const fn jeq_reg(dst: EbpfReg, src: EbpfReg, offset: i16) -> Self {
        Self::new(
            opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_X,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// NEG64 dst - Negate register (dst = -dst)
    pub const fn neg64(dst: EbpfReg) -> Self {
        Self::new(opcode::BPF_ALU64 | opcode::BPF_NEG, dst.as_u8(), 0, 0, 0)
    }

    /// STXDW [dst+off], src - Store 64-bit value from register to memory
    pub const fn stxdw(dst: EbpfReg, offset: i16, src: EbpfReg) -> Self {
        Self::new(
            opcode::BPF_STX | opcode::BPF_DW | opcode::BPF_MEM,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// STXW [dst+off], src - Store 32-bit value from register to memory
    pub const fn stxw(dst: EbpfReg, offset: i16, src: EbpfReg) -> Self {
        Self::new(
            opcode::BPF_STX | opcode::BPF_W | opcode::BPF_MEM,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// STXH [dst+off], src - Store 16-bit value from register to memory
    pub const fn stxh(dst: EbpfReg, offset: i16, src: EbpfReg) -> Self {
        Self::new(
            opcode::BPF_STX | opcode::BPF_H | opcode::BPF_MEM,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// STXB [dst+off], src - Store 8-bit value from register to memory
    pub const fn stxb(dst: EbpfReg, offset: i16, src: EbpfReg) -> Self {
        Self::new(
            opcode::BPF_STX | opcode::BPF_B | opcode::BPF_MEM,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// LDXB dst, [src+off] - Load 8-bit value from memory to register
    pub const fn ldxb(dst: EbpfReg, src: EbpfReg, offset: i16) -> Self {
        Self::new(
            opcode::BPF_LDX | opcode::BPF_B | opcode::BPF_MEM,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// LDXH dst, [src+off] - Load 16-bit value from memory to register
    pub const fn ldxh(dst: EbpfReg, src: EbpfReg, offset: i16) -> Self {
        Self::new(
            opcode::BPF_LDX | opcode::BPF_H | opcode::BPF_MEM,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// LDXW dst, [src+off] - Load 32-bit value from memory to register
    pub const fn ldxw(dst: EbpfReg, src: EbpfReg, offset: i16) -> Self {
        Self::new(
            opcode::BPF_LDX | opcode::BPF_W | opcode::BPF_MEM,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// LDXDW dst, [src+off] - Load 64-bit value from memory to register
    pub const fn ldxdw(dst: EbpfReg, src: EbpfReg, offset: i16) -> Self {
        Self::new(
            opcode::BPF_LDX | opcode::BPF_DW | opcode::BPF_MEM,
            dst.as_u8(),
            src.as_u8(),
            offset,
            0,
        )
    }

    /// LD_MAP_FD - Load map file descriptor (pseudo instruction, needs relocation)
    /// This creates a 16-byte instruction (two slots) that will be patched by the loader
    pub fn ld_map_fd(dst: EbpfReg) -> [Self; 2] {
        [
            Self::new(
                opcode::LD_DW_IMM,
                dst.as_u8(),
                1, // src_reg=1 means "load map by fd"
                0,
                0, // Will be filled by relocation
            ),
            Self::new(0, 0, 0, 0, 0), // Second half of 128-bit instruction
        ]
    }
}

impl EbpfBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an instruction
    pub fn push(&mut self, insn: EbpfInsn) -> &mut Self {
        self.instructions.push(insn);
        self
    }

    /// Get the current instruction count
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Build the raw bytecode
    pub fn build(self) -> Vec<u8> {
        let mut bytecode = Vec::with_capacity(self.instructions.len() * 8);
        for insn in self.instructions {
            bytecode.extend_from_slice(&insn.encode());
        }
        bytecode
    }

    /// Get instructions for inspection
    pub fn instructions(&self) -> &[EbpfInsn] {
        &self.instructions
    }

    /// Set the offset field of an instruction (for fixup of jumps)
    pub fn set_offset(&mut self, idx: usize, offset: i16) {
        if let Some(insn) = self.instructions.get_mut(idx) {
            insn.offset = offset;
        }
    }
}
