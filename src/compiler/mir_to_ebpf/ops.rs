use super::*;
use crate::compiler::{EbpfProgramType, ProgramValueAccess};
use crate::kernel_btf::{TrampolineValueKind, TrampolineValueSpec};

impl<'a> MirToEbpfCompiler<'a> {
    fn xdp_md_offsets() -> (i16, i16, i16, i16, i16, i16) {
        // struct xdp_md {
        //     __u32 data;
        //     __u32 data_end;
        //     __u32 data_meta;
        //     __u32 ingress_ifindex;
        //     __u32 rx_queue_index;
        //     __u32 egress_ifindex;
        // };
        (0, 4, 8, 12, 16, 20)
    }

    fn sk_buff_offsets() -> (i16, i16, i16, i16) {
        // struct __sk_buff {
        //     __u32 len;
        //     ...
        //     __u32 ingress_ifindex;
        //     __u32 ifindex;
        //     ...
        //     __u32 data;
        //     __u32 data_end;
        // };
        (0, 76, 80, 36)
    }

    fn bpf_sock_addr_offsets() -> (i16, i16, i16, i16, i16, i16, i16, i16, i16) {
        // struct bpf_sock_addr {
        //     __u32 user_family;
        //     __u32 user_ip4;
        //     __u32 user_ip6[4];
        //     ...
        //     __u32 user_port;
        //     ...
        //     __u32 family;
        //     __u32 type;
        //     __u32 protocol;
        //     __u32 msg_src_ip4;
        //     __u32 msg_src_ip6[4];
        // };
        (0, 4, 8, 24, 28, 32, 36, 40, 44)
    }

    fn bpf_sysctl_offsets() -> (i16, i16) {
        // struct bpf_sysctl {
        //     __u32 write;
        //     __u32 file_pos;
        // };
        (0, 4)
    }

    fn bpf_sockopt_offsets() -> (i16, i16, i16, i16) {
        // struct bpf_sockopt {
        //     __u64 sk;
        //     __u64 optval;
        //     __u64 optval_end;
        //     __s32 level;
        //     __s32 optname;
        //     __s32 optlen;
        //     __s32 retval;
        // };
        (24, 28, 32, 36)
    }

    fn bpf_sock_offsets() -> (i16, i16, i16, i16, i16, i16) {
        // struct bpf_sock {
        //     __u32 bound_dev_if;
        //     __u32 family;
        //     __u32 type;
        //     __u32 protocol;
        //     __u32 mark;
        //     __u32 priority;
        // };
        (0, 4, 8, 12, 16, 20)
    }

    fn compile_ctx_u32_array_to_stack(
        &mut self,
        dst: EbpfReg,
        slot: Option<StackSlotId>,
        base_offset: i16,
        count: usize,
        field_name: &str,
    ) -> Result<(), CompileError> {
        let slot = slot.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{field_name} requires a stack backing slot"
            ))
        })?;
        let slot_offset = *self.slot_offsets.get(&slot).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!("{field_name} stack slot not found"))
        })?;

        for index in 0..count {
            let word_offset = base_offset + (index as i16 * 4);
            let dst_offset = slot_offset + (index as i16 * 4);
            self.instructions
                .push(EbpfInsn::ldxw(EbpfReg::R0, EbpfReg::R9, word_offset));
            self.instructions
                .push(EbpfInsn::stxw(EbpfReg::R10, dst_offset, EbpfReg::R0));
        }

        self.instructions
            .push(EbpfInsn::mov64_reg(dst, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(dst, slot_offset as i32));
        Ok(())
    }

    fn packet_context_kind(&self) -> Result<PacketContextKind, CompileError> {
        self.probe_ctx
            .and_then(|ctx| ctx.probe_type.packet_context_kind())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "packet context fields require a packet-context program type".to_string(),
                )
            })
    }

    /// Emit binary operation with register operand
    pub(super) fn emit_binop_reg(
        &mut self,
        dst: EbpfReg,
        op: BinOpKind,
        rhs: EbpfReg,
        unsigned_compare: bool,
    ) -> Result<(), CompileError> {
        match op {
            BinOpKind::Add => self.instructions.push(EbpfInsn::add64_reg(dst, rhs)),
            BinOpKind::Sub => self.instructions.push(EbpfInsn::sub64_reg(dst, rhs)),
            BinOpKind::Mul => self.instructions.push(EbpfInsn::mul64_reg(dst, rhs)),
            BinOpKind::Div => self.instructions.push(EbpfInsn::div64_reg(dst, rhs)),
            BinOpKind::Mod => self.instructions.push(EbpfInsn::mod64_reg(dst, rhs)),
            BinOpKind::And => self.instructions.push(EbpfInsn::and64_reg(dst, rhs)),
            BinOpKind::Or => self.instructions.push(EbpfInsn::or64_reg(dst, rhs)),
            BinOpKind::Xor => self.instructions.push(EbpfInsn::xor64_reg(dst, rhs)),
            BinOpKind::Shl => self.instructions.push(EbpfInsn::lsh64_reg(dst, rhs)),
            BinOpKind::Shr => self.instructions.push(EbpfInsn::rsh64_reg(dst, rhs)),
            // Comparisons - set to 1, conditionally jump over setting to 0
            BinOpKind::Eq
            | BinOpKind::Ne
            | BinOpKind::Lt
            | BinOpKind::Le
            | BinOpKind::Gt
            | BinOpKind::Ge => {
                self.emit_comparison_reg(dst, op, rhs, unsigned_compare)?;
            }
        }
        Ok(())
    }

    /// Emit binary operation with immediate operand
    pub(super) fn emit_binop_imm(
        &mut self,
        dst: EbpfReg,
        op: BinOpKind,
        imm: i32,
        unsigned_compare: bool,
    ) -> Result<(), CompileError> {
        match op {
            BinOpKind::Add => self.instructions.push(EbpfInsn::add64_imm(dst, imm)),
            BinOpKind::Sub => self.instructions.push(EbpfInsn::sub64_imm(dst, imm)),
            BinOpKind::Mul => self.instructions.push(EbpfInsn::mul64_imm(dst, imm)),
            BinOpKind::Div => self.instructions.push(EbpfInsn::div64_imm(dst, imm)),
            BinOpKind::Mod => self.instructions.push(EbpfInsn::mod64_imm(dst, imm)),
            BinOpKind::And => self.instructions.push(EbpfInsn::and64_imm(dst, imm)),
            BinOpKind::Or => self.instructions.push(EbpfInsn::or64_imm(dst, imm)),
            BinOpKind::Xor => self.instructions.push(EbpfInsn::xor64_imm(dst, imm)),
            BinOpKind::Shl => self.instructions.push(EbpfInsn::lsh64_imm(dst, imm)),
            BinOpKind::Shr => self.instructions.push(EbpfInsn::rsh64_imm(dst, imm)),
            // Comparisons
            BinOpKind::Eq
            | BinOpKind::Ne
            | BinOpKind::Lt
            | BinOpKind::Le
            | BinOpKind::Gt
            | BinOpKind::Ge => {
                self.emit_comparison_imm(dst, op, imm, unsigned_compare)?;
            }
        }
        Ok(())
    }

    /// Emit comparison with register, result in dst as 0 or 1
    fn emit_comparison_reg(
        &mut self,
        dst: EbpfReg,
        op: BinOpKind,
        rhs: EbpfReg,
        unsigned_compare: bool,
    ) -> Result<(), CompileError> {
        // Compare the current dst value directly, then materialize the boolean result.
        let jmp_opcode = match op {
            BinOpKind::Eq => opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_X,
            BinOpKind::Ne => opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_X,
            BinOpKind::Lt if unsigned_compare => opcode::BPF_JMP | opcode::BPF_JLT | opcode::BPF_X,
            BinOpKind::Le if unsigned_compare => opcode::BPF_JMP | opcode::BPF_JLE | opcode::BPF_X,
            BinOpKind::Gt if unsigned_compare => opcode::BPF_JMP | opcode::BPF_JGT | opcode::BPF_X,
            BinOpKind::Ge if unsigned_compare => opcode::BPF_JMP | opcode::BPF_JGE | opcode::BPF_X,
            BinOpKind::Lt => opcode::BPF_JMP | opcode::BPF_JSLT | opcode::BPF_X,
            BinOpKind::Le => opcode::BPF_JMP | opcode::BPF_JSLE | opcode::BPF_X,
            BinOpKind::Gt => opcode::BPF_JMP | opcode::BPF_JSGT | opcode::BPF_X,
            BinOpKind::Ge => opcode::BPF_JMP | opcode::BPF_JSGE | opcode::BPF_X,
            _ => unreachable!(),
        };

        self.instructions
            .push(EbpfInsn::new(jmp_opcode, dst.as_u8(), rhs.as_u8(), 2, 0));

        self.instructions.push(EbpfInsn::mov64_imm(dst, 0));
        self.instructions.push(EbpfInsn::jump(1));
        self.instructions.push(EbpfInsn::mov64_imm(dst, 1));
        Ok(())
    }

    /// Emit comparison with immediate, result in dst as 0 or 1
    fn emit_comparison_imm(
        &mut self,
        dst: EbpfReg,
        op: BinOpKind,
        imm: i32,
        unsigned_compare: bool,
    ) -> Result<(), CompileError> {
        let jmp_opcode = match op {
            BinOpKind::Eq => opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_K,
            BinOpKind::Ne => opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_K,
            BinOpKind::Lt if unsigned_compare => opcode::BPF_JMP | opcode::BPF_JLT | opcode::BPF_K,
            BinOpKind::Le if unsigned_compare => opcode::BPF_JMP | opcode::BPF_JLE | opcode::BPF_K,
            BinOpKind::Gt if unsigned_compare => opcode::BPF_JMP | opcode::BPF_JGT | opcode::BPF_K,
            BinOpKind::Ge if unsigned_compare => opcode::BPF_JMP | opcode::BPF_JGE | opcode::BPF_K,
            BinOpKind::Lt => opcode::BPF_JMP | opcode::BPF_JSLT | opcode::BPF_K,
            BinOpKind::Le => opcode::BPF_JMP | opcode::BPF_JSLE | opcode::BPF_K,
            BinOpKind::Gt => opcode::BPF_JMP | opcode::BPF_JSGT | opcode::BPF_K,
            BinOpKind::Ge => opcode::BPF_JMP | opcode::BPF_JSGE | opcode::BPF_K,
            _ => unreachable!(),
        };

        self.instructions
            .push(EbpfInsn::new(jmp_opcode, dst.as_u8(), 0, 2, imm));

        self.instructions.push(EbpfInsn::mov64_imm(dst, 0));
        self.instructions.push(EbpfInsn::jump(1));
        self.instructions.push(EbpfInsn::mov64_imm(dst, 1));
        Ok(())
    }

    pub(super) fn slot_offset_i16(
        &self,
        slot: StackSlotId,
        offset: i32,
    ) -> Result<i16, CompileError> {
        let base = self.slot_offsets.get(&slot).copied().unwrap_or(0) as i32;
        let total = base + offset;
        i16::try_from(total).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "stack slot offset {} out of range",
                total
            ))
        })
    }

    pub(super) fn add_i16_offset(&self, base: i16, add: usize) -> Result<i16, CompileError> {
        let total = i32::from(base)
            + i32::try_from(add).map_err(|_| {
                CompileError::UnsupportedInstruction(format!("offset {} out of range", add))
            })?;
        i16::try_from(total).map_err(|_| {
            CompileError::UnsupportedInstruction(format!("offset {} out of range", total))
        })
    }

    pub(super) fn value_to_reg(&mut self, value: &MirValue) -> Result<EbpfReg, CompileError> {
        match value {
            MirValue::VReg(v) => self.ensure_reg(*v),
            MirValue::Const(c) => {
                if *c >= i32::MIN as i64 && *c <= i32::MAX as i64 {
                    self.instructions
                        .push(EbpfInsn::mov64_imm(EbpfReg::R0, *c as i32));
                } else {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "constant {} too large for store",
                        c
                    )));
                }
                Ok(EbpfReg::R0)
            }
            MirValue::StackSlot(slot) => {
                let offset = self.slot_offsets.get(slot).copied().unwrap_or(0);
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R0, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(EbpfReg::R0, offset as i32));
                Ok(EbpfReg::R0)
            }
        }
    }

    pub(super) fn emit_load(
        &mut self,
        dst: EbpfReg,
        base: EbpfReg,
        offset: i16,
        size: usize,
    ) -> Result<(), CompileError> {
        match size {
            1 => self.instructions.push(EbpfInsn::ldxb(dst, base, offset)),
            2 => self.instructions.push(EbpfInsn::ldxh(dst, base, offset)),
            4 => self.instructions.push(EbpfInsn::ldxw(dst, base, offset)),
            8 => self.instructions.push(EbpfInsn::ldxdw(dst, base, offset)),
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "load size {} not supported",
                    size
                )));
            }
        }
        Ok(())
    }

    pub(super) fn emit_store(
        &mut self,
        base: EbpfReg,
        offset: i16,
        src: EbpfReg,
        size: usize,
    ) -> Result<(), CompileError> {
        match size {
            1 => self.instructions.push(EbpfInsn::stxb(base, offset, src)),
            2 => self.instructions.push(EbpfInsn::stxh(base, offset, src)),
            4 => self.instructions.push(EbpfInsn::stxw(base, offset, src)),
            8 => self.instructions.push(EbpfInsn::stxdw(base, offset, src)),
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "store size {} not supported",
                    size
                )));
            }
        }
        Ok(())
    }

    pub(super) fn emit_copy_bytes(
        &mut self,
        src_base: EbpfReg,
        src_offset: i16,
        dst_base: EbpfReg,
        dst_offset: i16,
        size: usize,
        scratch: EbpfReg,
    ) -> Result<(), CompileError> {
        if src_base == scratch {
            let temp_base = [
                EbpfReg::R9,
                EbpfReg::R8,
                EbpfReg::R7,
                EbpfReg::R6,
                EbpfReg::R5,
                EbpfReg::R4,
                EbpfReg::R3,
                EbpfReg::R2,
                EbpfReg::R1,
            ]
            .into_iter()
            .find(|reg| *reg != scratch && *reg != dst_base)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "no temporary register available for byte copy".into(),
                )
            })?;

            self.check_stack_space(8)?;
            self.stack_offset -= 8;
            let spill_offset = self.stack_offset;

            self.emit_store(EbpfReg::R10, spill_offset, temp_base, 8)?;
            self.instructions
                .push(EbpfInsn::mov64_reg(temp_base, src_base));
            let copy_result = self
                .emit_copy_bytes_inner(temp_base, src_offset, dst_base, dst_offset, size, scratch);
            self.emit_load(temp_base, EbpfReg::R10, spill_offset, 8)?;
            self.stack_offset += 8;
            return copy_result;
        }

        self.emit_copy_bytes_inner(src_base, src_offset, dst_base, dst_offset, size, scratch)
    }

    fn emit_copy_bytes_inner(
        &mut self,
        src_base: EbpfReg,
        src_offset: i16,
        dst_base: EbpfReg,
        dst_offset: i16,
        size: usize,
        scratch: EbpfReg,
    ) -> Result<(), CompileError> {
        let mut copied = 0usize;
        while copied < size {
            let cur_src = self.add_i16_offset(src_offset, copied)?;
            let cur_dst = self.add_i16_offset(dst_offset, copied)?;
            let remaining = size - copied;
            let chunk = Self::largest_aligned_chunk(remaining, &[cur_src, cur_dst]);
            self.emit_load(scratch, src_base, cur_src, chunk)?;
            self.emit_store(dst_base, cur_dst, scratch, chunk)?;
            copied += chunk;
        }
        Ok(())
    }

    pub(super) fn emit_zero_bytes(
        &mut self,
        base: EbpfReg,
        offset: i16,
        size: usize,
        scratch: EbpfReg,
    ) -> Result<(), CompileError> {
        self.instructions.push(EbpfInsn::mov64_imm(scratch, 0));
        let mut written = 0usize;
        while written < size {
            let cur_offset = self.add_i16_offset(offset, written)?;
            let remaining = size - written;
            let chunk = Self::largest_aligned_chunk(remaining, &[cur_offset]);
            self.emit_store(base, cur_offset, scratch, chunk)?;
            written += chunk;
        }
        Ok(())
    }

    fn largest_aligned_chunk(remaining: usize, offsets: &[i16]) -> usize {
        for chunk in [8usize, 4, 2, 1] {
            if remaining >= chunk
                && offsets
                    .iter()
                    .all(|offset| i32::from(*offset).rem_euclid(chunk as i32) == 0)
            {
                return chunk;
            }
        }
        1
    }

    fn trampoline_slot_offset(field_name: &str, slot_index: usize) -> Result<i16, CompileError> {
        let byte_offset = slot_index.checked_mul(8).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!("{field_name} slot offset overflowed"))
        })?;
        i16::try_from(byte_offset).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "{field_name} slot offset {} is too large",
                byte_offset
            ))
        })
    }

    fn compile_trampoline_value_load(
        &mut self,
        dst: EbpfReg,
        slot: Option<StackSlotId>,
        spec: TrampolineValueSpec,
        field_name: &str,
    ) -> Result<(), CompileError> {
        match spec.kind {
            TrampolineValueKind::Scalar | TrampolineValueKind::Pointer { .. } => {
                let offset = Self::trampoline_slot_offset(field_name, spec.slot_index)?;
                self.instructions
                    .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
            }
            TrampolineValueKind::Aggregate { size_bytes } => {
                let slot = slot.ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "{field_name} requires a stack backing slot"
                    ))
                })?;
                let dst_offset = self.slot_offset_i16(slot, 0)?;
                let src_offset = Self::trampoline_slot_offset(field_name, spec.slot_index)?;
                let aligned_size = size_bytes.div_ceil(8) * 8;
                if aligned_size > size_bytes {
                    self.emit_zero_bytes(EbpfReg::R10, dst_offset, aligned_size, EbpfReg::R0)?;
                }
                self.emit_copy_bytes(
                    EbpfReg::R9,
                    src_offset,
                    EbpfReg::R10,
                    dst_offset,
                    size_bytes,
                    EbpfReg::R0,
                )?;
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(dst, dst_offset as i32));
            }
        }
        Ok(())
    }

    /// Compile context field load
    pub(super) fn compile_load_ctx_field(
        &mut self,
        dst: EbpfReg,
        field: &CtxField,
        slot: Option<StackSlotId>,
    ) -> Result<(), CompileError> {
        if let Some(ctx) = self.probe_ctx {
            ctx.validate_ctx_field_access(field)?;
        }

        match field {
            CtxField::Pid => {
                // bpf_get_current_pid_tgid() returns (tgid << 32) | pid
                // Lower 32 bits = thread ID (what Linux calls PID)
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
                // Keep lower 32 bits, zero upper bits
                self.instructions.push(EbpfInsn::and32_imm(dst, -1));
            }
            CtxField::Tid => {
                // Upper 32 bits = thread group ID (what userspace calls PID)
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
                self.instructions.push(EbpfInsn::rsh64_imm(EbpfReg::R0, 32));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::Uid => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentUidGid));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
                self.instructions.push(EbpfInsn::and32_imm(dst, -1));
            }
            CtxField::Gid => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentUidGid));
                self.instructions.push(EbpfInsn::rsh64_imm(EbpfReg::R0, 32));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::Timestamp => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::KtimeGetNs));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::Cpu => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetSmpProcessorId));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::PacketLen => match self.packet_context_kind()? {
                PacketContextKind::XdpMd => {
                    let (data_offset, data_end_offset, _, _, _, _) = Self::xdp_md_offsets();
                    self.instructions
                        .push(EbpfInsn::ldxw(dst, EbpfReg::R9, data_end_offset));
                    self.instructions
                        .push(EbpfInsn::ldxw(EbpfReg::R0, EbpfReg::R9, data_offset));
                    self.instructions
                        .push(EbpfInsn::sub64_reg(dst, EbpfReg::R0));
                }
                PacketContextKind::SkBuff => {
                    let (len_offset, _, _, _) = Self::sk_buff_offsets();
                    self.instructions
                        .push(EbpfInsn::ldxw(dst, EbpfReg::R9, len_offset));
                }
            },
            CtxField::Data => {
                let data_offset = match self.packet_context_kind()? {
                    PacketContextKind::XdpMd => Self::xdp_md_offsets().0,
                    PacketContextKind::SkBuff => Self::sk_buff_offsets().1,
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, data_offset));
            }
            CtxField::DataEnd => {
                let data_end_offset = match self.packet_context_kind()? {
                    PacketContextKind::XdpMd => Self::xdp_md_offsets().1,
                    PacketContextKind::SkBuff => Self::sk_buff_offsets().2,
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, data_end_offset));
            }
            CtxField::IngressIfindex => {
                let ingress_ifindex_offset = match self.packet_context_kind()? {
                    PacketContextKind::XdpMd => Self::xdp_md_offsets().3,
                    PacketContextKind::SkBuff => Self::sk_buff_offsets().3,
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, ingress_ifindex_offset));
            }
            CtxField::RxQueueIndex => {
                let PacketContextKind::XdpMd = self.packet_context_kind()? else {
                    return Err(CompileError::UnsupportedInstruction(
                        "ctx.rx_queue_index is only available on xdp programs".to_string(),
                    ));
                };
                let (_, _, _, _, rx_queue_index_offset, _) = Self::xdp_md_offsets();
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, rx_queue_index_offset));
            }
            CtxField::EgressIfindex => {
                let PacketContextKind::XdpMd = self.packet_context_kind()? else {
                    return Err(CompileError::UnsupportedInstruction(
                        "ctx.egress_ifindex is only available on xdp programs".to_string(),
                    ));
                };
                let (_, _, _, _, _, egress_ifindex_offset) = Self::xdp_md_offsets();
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, egress_ifindex_offset));
            }
            CtxField::UserFamily => {
                let offset = Self::bpf_sock_addr_offsets().0;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::UserIp4 => {
                let offset = Self::bpf_sock_addr_offsets().1;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::UserIp6 => {
                let offset = Self::bpf_sock_addr_offsets().2;
                self.compile_ctx_u32_array_to_stack(dst, slot, offset, 4, "ctx.user_ip6")?;
            }
            CtxField::UserPort => {
                let offset = Self::bpf_sock_addr_offsets().3;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::Family => {
                let offset = if matches!(
                    self.probe_ctx.as_ref().map(|ctx| ctx.probe_type),
                    Some(EbpfProgramType::CgroupSock)
                ) {
                    Self::bpf_sock_offsets().1
                } else {
                    Self::bpf_sock_addr_offsets().4
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockType => {
                let offset = if matches!(
                    self.probe_ctx.as_ref().map(|ctx| ctx.probe_type),
                    Some(EbpfProgramType::CgroupSock)
                ) {
                    Self::bpf_sock_offsets().2
                } else {
                    Self::bpf_sock_addr_offsets().5
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::Protocol => {
                let offset = if matches!(
                    self.probe_ctx.as_ref().map(|ctx| ctx.probe_type),
                    Some(EbpfProgramType::CgroupSock)
                ) {
                    Self::bpf_sock_offsets().3
                } else {
                    Self::bpf_sock_addr_offsets().6
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::BoundDevIf => {
                let offset = Self::bpf_sock_offsets().0;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockMark => {
                let offset = Self::bpf_sock_offsets().4;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockPriority => {
                let offset = Self::bpf_sock_offsets().5;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::MsgSrcIp4 => {
                let offset = Self::bpf_sock_addr_offsets().7;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::MsgSrcIp6 => {
                let offset = Self::bpf_sock_addr_offsets().8;
                self.compile_ctx_u32_array_to_stack(dst, slot, offset, 4, "ctx.msg_src_ip6")?;
            }
            CtxField::SysctlWrite => {
                let offset = Self::bpf_sysctl_offsets().0;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SysctlFilePos => {
                let offset = Self::bpf_sysctl_offsets().1;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockoptLevel => {
                let offset = Self::bpf_sockopt_offsets().0;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockoptOptname => {
                let offset = Self::bpf_sockopt_offsets().1;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockoptOptlen => {
                let offset = Self::bpf_sockopt_offsets().2;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockoptRetval => {
                let offset = Self::bpf_sockopt_offsets().3;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::Comm => {
                let comm_offset = if let Some(slot) = slot {
                    *self.slot_offsets.get(&slot).ok_or_else(|| {
                        CompileError::UnsupportedInstruction("comm stack slot not found".into())
                    })?
                } else {
                    // Fallback: allocate temporary stack space if no slot was provided.
                    self.check_stack_space(16)?;
                    self.stack_offset -= 16;
                    self.stack_offset
                };

                // bpf_get_current_comm(buf, size)
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(EbpfReg::R1, comm_offset as i32));
                self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R2, 16));
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentComm));

                // Return pointer to comm on stack
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(dst, comm_offset as i32));
            }
            CtxField::Arg(n) => {
                let n = *n as usize;
                match self.probe_ctx {
                    Some(ctx) if ctx.probe_type.uses_btf_trampoline() => {
                        let spec = match ctx.probe_type {
                            EbpfProgramType::StructOps => {
                                let value_type_name =
                                    ctx.struct_ops_value_type_name.as_deref().ok_or_else(|| {
                                        CompileError::UnsupportedInstruction(format!(
                                            "missing struct_ops value type for callback '{}'",
                                            ctx.target
                                        ))
                                    })?;
                                KernelBtf::get()
                                    .struct_ops_callback_arg(value_type_name, &ctx.target, n)
                                    .map_err(|e| {
                                        CompileError::UnsupportedInstruction(format!(
                                            "failed to resolve ctx.arg{} for struct_ops {}.{}: {}",
                                            n, value_type_name, ctx.target, e
                                        ))
                                    })?
                                    .ok_or_else(|| {
                                        CompileError::UnsupportedInstruction(format!(
                                            "ctx.arg{} is not available on struct_ops {}.{}",
                                            n, value_type_name, ctx.target
                                        ))
                                    })?
                            }
                            EbpfProgramType::Lsm => KernelBtf::get()
                                .lsm_hook_arg(&ctx.target, n)
                                .map_err(|e| {
                                    CompileError::UnsupportedInstruction(format!(
                                        "failed to resolve ctx.arg{} for lsm:{}: {}",
                                        n, ctx.target, e
                                    ))
                                })?
                                .ok_or_else(|| {
                                    CompileError::UnsupportedInstruction(format!(
                                        "ctx.arg{} is not available on lsm:{}",
                                        n, ctx.target
                                    ))
                                })?,
                            _ => KernelBtf::get()
                                .function_trampoline_arg(&ctx.target, n)
                                .map_err(|e| {
                                    CompileError::UnsupportedInstruction(format!(
                                        "failed to resolve ctx.arg{} for {}:{}: {}",
                                        n,
                                        ctx.probe_type.section_prefix(),
                                        ctx.target,
                                        e
                                    ))
                                })?
                                .ok_or_else(|| {
                                    CompileError::UnsupportedInstruction(format!(
                                        "ctx.arg{} is not available on {}:{}",
                                        n,
                                        ctx.probe_type.section_prefix(),
                                        ctx.target
                                    ))
                                })?,
                        };
                        self.compile_trampoline_value_load(
                            dst,
                            slot,
                            spec,
                            &format!("ctx.arg{n}"),
                        )?;
                    }
                    _ => {
                        if n >= 6 {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "Argument index {} out of range",
                                n
                            )));
                        }
                        let offsets = KernelBtf::get().pt_regs_offsets().map_err(|e| {
                            CompileError::UnsupportedInstruction(format!(
                                "pt_regs argument access unavailable: {e}"
                            ))
                        })?;
                        let offset = offsets.arg_offsets[n];
                        // R9 contains the saved pt_regs context pointer for kprobe/uprobe paths.
                        self.instructions
                            .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
                    }
                }
            }
            CtxField::RetVal => match self.probe_ctx {
                Some(ctx)
                    if matches!(
                        ctx.probe_type.retval_access(),
                        ProgramValueAccess::Trampoline
                    ) =>
                {
                    let spec = KernelBtf::get()
                            .function_trampoline_ret(&ctx.target)
                            .map_err(|e| {
                                CompileError::UnsupportedInstruction(format!(
                                    "failed to resolve ctx.retval for fexit:{}: {}",
                                    ctx.target, e
                                ))
                            })?
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "ctx.retval is not available on fexit:{} because the target returns void",
                                    ctx.target
                                ))
                            })?;
                    self.compile_trampoline_value_load(dst, slot, spec, "ctx.retval")?;
                }
                _ => {
                    if let Some(ctx) = self.probe_ctx
                        && !ctx.probe_type.supports_ctx_retval()
                    {
                        return Err(CompileError::RetvalOnNonReturnProbe);
                    }
                    let offsets = KernelBtf::get().pt_regs_offsets().map_err(|e| {
                        CompileError::UnsupportedInstruction(format!(
                            "pt_regs return value access unavailable: {e}"
                        ))
                    })?;
                    let offset = offsets.retval_offset;
                    self.instructions
                        .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
                }
            },
            CtxField::KStack => {
                self.needs_kstack_map = true;
                self.compile_get_stackid(dst, KSTACK_MAP_NAME, false)?;
            }
            CtxField::UStack => {
                self.needs_ustack_map = true;
                self.compile_get_stackid(dst, USTACK_MAP_NAME, true)?;
            }
            CtxField::TracepointField(name) => {
                // Get tracepoint context from probe context
                let probe_ctx = self.probe_ctx.ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "Tracepoint field access requires probe context".into(),
                    )
                })?;

                let (category, tp_name) = probe_ctx.tracepoint_parts().ok_or_else(|| {
                    CompileError::TracepointContextError {
                        category: "unknown".into(),
                        name: probe_ctx.target.clone(),
                        reason: "Invalid tracepoint format. Expected 'category/name'".into(),
                    }
                })?;

                let btf = KernelBtf::get();
                let ctx = btf.get_tracepoint_context(category, tp_name).map_err(|e| {
                    CompileError::TracepointContextError {
                        category: category.into(),
                        name: tp_name.into(),
                        reason: e.to_string(),
                    }
                })?;

                // Look up the field in the tracepoint context
                let field_info =
                    ctx.get_field(name)
                        .ok_or_else(|| CompileError::TracepointFieldNotFound {
                            field: name.clone(),
                            available: ctx.field_names().join(", "),
                        })?;

                // Load the field from the context struct
                // R9 contains the saved context pointer (tracepoint context struct)
                let offset = field_info.offset as i16;

                // Choose load instruction based on field size
                match field_info.size {
                    1 => {
                        self.instructions
                            .push(EbpfInsn::ldxb(dst, EbpfReg::R9, offset));
                    }
                    2 => {
                        self.instructions
                            .push(EbpfInsn::ldxh(dst, EbpfReg::R9, offset));
                    }
                    4 => {
                        self.instructions
                            .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
                    }
                    _ => {
                        // Default to 64-bit load for 8+ byte fields
                        self.instructions
                            .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
                    }
                }
            }
        }
        Ok(())
    }
}
