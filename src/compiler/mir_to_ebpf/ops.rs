use super::*;
use crate::compiler::ProgramValueAccess;
use crate::compiler::elf::{IngressIfindexContextLayout, SocketContextLayout};
use crate::kernel_btf::{TrampolineValueKind, TrampolineValueSpec, TypeInfo};

mod context;

impl<'a> MirToEbpfCompiler<'a> {
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
            ctx.validate_load_ctx_field(field)?;
        }

        match field {
            CtxField::Context => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R9));
            }
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
            CtxField::CgroupId => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentCgroupId));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::SocketCookie => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetSocketCookie));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::SocketUid => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetSocketUid));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::NetnsCookie => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetNetnsCookie));
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
                    let (len_offset, _, _, _, _, _, _) = Self::sk_buff_offsets();
                    self.instructions
                        .push(EbpfInsn::ldxw(dst, EbpfReg::R9, len_offset));
                }
                PacketContextKind::SkMsg => {
                    let (_, _, _, _, _, _, _, _, _, size_offset) = Self::sk_msg_md_offsets();
                    self.instructions
                        .push(EbpfInsn::ldxw(dst, EbpfReg::R9, size_offset));
                }
                PacketContextKind::SockOps => {
                    let skb_len_offset = Self::bpf_sock_ops_skb_field_offsets().0;
                    self.instructions
                        .push(EbpfInsn::ldxw(dst, EbpfReg::R9, skb_len_offset));
                }
            },
            CtxField::PktType => {
                let pkt_type_offset = match self.packet_context_kind()? {
                    PacketContextKind::SkBuff => Self::sk_buff_packet_meta_offsets().0,
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.pkt_type is only available on skb-backed packet programs"
                                .to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, pkt_type_offset));
            }
            CtxField::QueueMapping => {
                let queue_mapping_offset = match self.packet_context_kind()? {
                    PacketContextKind::SkBuff => Self::sk_buff_packet_meta_offsets().1,
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.queue_mapping is only available on skb-backed packet programs"
                                .to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, queue_mapping_offset));
            }
            CtxField::EthProtocol => {
                let protocol_offset = match self.packet_context_kind()? {
                    PacketContextKind::SkBuff => Self::sk_buff_vlan_offsets().0,
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.eth_protocol is only available on skb-backed packet programs"
                                .to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxh(dst, EbpfReg::R9, protocol_offset));
                self.instructions.push(EbpfInsn::end16_to_be(dst));
            }
            CtxField::VlanPresent => {
                let vlan_present_offset = match self.packet_context_kind()? {
                    PacketContextKind::SkBuff => Self::sk_buff_vlan_offsets().1,
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.vlan_present is only available on skb-backed packet programs"
                                .to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, vlan_present_offset));
            }
            CtxField::VlanTci => {
                let vlan_tci_offset = match self.packet_context_kind()? {
                    PacketContextKind::SkBuff => Self::sk_buff_vlan_offsets().2,
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.vlan_tci is only available on skb-backed packet programs"
                                .to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, vlan_tci_offset));
            }
            CtxField::VlanProto => {
                let vlan_proto_offset = match self.packet_context_kind()? {
                    PacketContextKind::SkBuff => Self::sk_buff_vlan_offsets().3,
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.vlan_proto is only available on skb-backed packet programs"
                                .to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxh(dst, EbpfReg::R9, vlan_proto_offset));
                self.instructions.push(EbpfInsn::end16_to_be(dst));
            }
            CtxField::SkbCb => {
                let cb_offset = match self.packet_context_kind()? {
                    PacketContextKind::SkBuff => Self::sk_buff_cb_offset(),
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.cb is only available on skb-backed packet programs".to_string(),
                        ));
                    }
                };
                self.compile_ctx_u32_array_to_stack(dst, slot, cb_offset, 5, "ctx.cb", false)?;
            }
            CtxField::TcClassid => {
                let tc_classid_offset = match self.packet_context_kind()? {
                    PacketContextKind::SkBuff => Self::sk_buff_extended_meta_offsets().0,
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.tc_classid is only available on skb-backed packet programs"
                                .to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, tc_classid_offset));
            }
            CtxField::NapiId => {
                let napi_id_offset = match self.packet_context_kind()? {
                    PacketContextKind::SkBuff => Self::sk_buff_extended_meta_offsets().1,
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.napi_id is only available on skb-backed packet programs"
                                .to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, napi_id_offset));
            }
            CtxField::WireLen => {
                let wire_len_offset = match self.packet_context_kind()? {
                    PacketContextKind::SkBuff => Self::sk_buff_extended_meta_offsets().2,
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.wire_len is only available on skb-backed packet programs"
                                .to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, wire_len_offset));
            }
            CtxField::GsoSegs => {
                let gso_segs_offset = match self.packet_context_kind()? {
                    PacketContextKind::SkBuff => Self::sk_buff_extended_meta_offsets().3,
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.gso_segs is only available on skb-backed packet programs"
                                .to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, gso_segs_offset));
            }
            CtxField::GsoSize => {
                let gso_size_offset = match self.packet_context_kind()? {
                    PacketContextKind::SkBuff => Self::sk_buff_extended_meta_offsets().4,
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.gso_size is only available on skb-backed packet programs"
                                .to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, gso_size_offset));
            }
            CtxField::Hwtstamp => {
                let hwtstamp_offset = match self.packet_context_kind()? {
                    PacketContextKind::SkBuff => Self::sk_buff_extended_meta_offsets().5,
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.hwtstamp is only available on skb-backed packet programs"
                                .to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, hwtstamp_offset));
            }
            CtxField::Data => {
                match self.packet_context_kind()? {
                    PacketContextKind::XdpMd => {
                        let data_offset = Self::xdp_md_offsets().0;
                        self.instructions
                            .push(EbpfInsn::ldxw(dst, EbpfReg::R9, data_offset));
                    }
                    PacketContextKind::SkBuff => {
                        let data_offset = Self::sk_buff_offsets().1;
                        self.instructions
                            .push(EbpfInsn::ldxw(dst, EbpfReg::R9, data_offset));
                    }
                    PacketContextKind::SkMsg => {
                        let data_offset = Self::sk_msg_md_offsets().0;
                        self.instructions
                            .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, data_offset));
                    }
                    PacketContextKind::SockOps => {
                        let data_offset = Self::bpf_sock_ops_packet_data_offsets().0;
                        self.instructions
                            .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, data_offset));
                    }
                };
            }
            CtxField::DataMeta => {
                let PacketContextKind::XdpMd = self.packet_context_kind()? else {
                    return Err(CompileError::UnsupportedInstruction(
                        "ctx.data_meta is only available on xdp programs".to_string(),
                    ));
                };
                let data_meta_offset = Self::xdp_md_offsets().2;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, data_meta_offset));
            }
            CtxField::DataEnd => {
                match self.packet_context_kind()? {
                    PacketContextKind::XdpMd => {
                        let data_end_offset = Self::xdp_md_offsets().1;
                        self.instructions
                            .push(EbpfInsn::ldxw(dst, EbpfReg::R9, data_end_offset));
                    }
                    PacketContextKind::SkBuff => {
                        let data_end_offset = Self::sk_buff_offsets().2;
                        self.instructions
                            .push(EbpfInsn::ldxw(dst, EbpfReg::R9, data_end_offset));
                    }
                    PacketContextKind::SkMsg => {
                        let data_end_offset = Self::sk_msg_md_offsets().1;
                        self.instructions
                            .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, data_end_offset));
                    }
                    PacketContextKind::SockOps => {
                        let data_end_offset = Self::bpf_sock_ops_packet_data_offsets().1;
                        self.instructions
                            .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, data_end_offset));
                    }
                };
            }
            CtxField::IngressIfindex => {
                let ingress_ifindex_offset = match self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.ingress_ifindex_context_layout())
                {
                    Some(IngressIfindexContextLayout::SkLookup) => Self::bpf_sk_lookup_offsets().9,
                    Some(IngressIfindexContextLayout::XdpMd) => Self::xdp_md_offsets().3,
                    Some(IngressIfindexContextLayout::SkBuff) => Self::sk_buff_offsets().3,
                    None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.ingress_ifindex is only available on xdp, socket_filter, tc, cgroup_skb, sk_lookup, sk_skb, and sk_skb_parser programs".to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, ingress_ifindex_offset));
            }
            CtxField::Ifindex => {
                let ifindex_offset = match self.packet_context_kind()? {
                    PacketContextKind::SkBuff => Self::sk_buff_offsets().4,
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.ifindex is only available on skb-backed packet programs"
                                .to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, ifindex_offset));
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
            CtxField::TcIndex => {
                let tc_index_offset = match self.packet_context_kind()? {
                    PacketContextKind::SkBuff => Self::sk_buff_offsets().5,
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.tc_index is only available on skb-backed packet programs"
                                .to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, tc_index_offset));
            }
            CtxField::SkbHash => {
                let hash_offset = match self.packet_context_kind()? {
                    PacketContextKind::SkBuff => Self::sk_buff_offsets().6,
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.hash is only available on skb-backed packet programs".to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, hash_offset));
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
                self.compile_ctx_u32_array_to_stack(dst, slot, offset, 4, "ctx.user_ip6", false)?;
            }
            CtxField::UserPort => {
                let offset = Self::bpf_sock_addr_offsets().3;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::Family => {
                let offset = match self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.socket_family_context_layout())
                {
                    Some(SocketContextLayout::CgroupSock) => Self::bpf_sock_offsets().1,
                    Some(SocketContextLayout::SockOps) => Self::bpf_sock_ops_offsets().1,
                    Some(SocketContextLayout::SkLookup) => Self::bpf_sk_lookup_offsets().1,
                    Some(SocketContextLayout::SkMsg) => Self::sk_msg_md_offsets().2,
                    Some(SocketContextLayout::SkBuff) => Self::sk_buff_socket_offsets().0,
                    Some(SocketContextLayout::SockAddr) => Self::bpf_sock_addr_offsets().4,
                    Some(SocketContextLayout::CgroupSockopt) | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.family is only available on cgroup_sock, cgroup_sock_addr, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs".to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockType => {
                let offset = match self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.sock_type_context_layout())
                {
                    Some(SocketContextLayout::CgroupSock) => Self::bpf_sock_offsets().2,
                    Some(SocketContextLayout::SockAddr) => Self::bpf_sock_addr_offsets().5,
                    Some(
                        SocketContextLayout::CgroupSockopt
                        | SocketContextLayout::SkLookup
                        | SocketContextLayout::SkMsg
                        | SocketContextLayout::SkBuff
                        | SocketContextLayout::SockOps,
                    )
                    | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.type is only available on cgroup_sock and cgroup_sock_addr programs"
                                .to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::Protocol => {
                let offset = match self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.protocol_context_layout())
                {
                    Some(SocketContextLayout::CgroupSock) => Self::bpf_sock_offsets().3,
                    Some(SocketContextLayout::SkLookup) => Self::bpf_sk_lookup_offsets().2,
                    Some(SocketContextLayout::SockAddr) => Self::bpf_sock_addr_offsets().6,
                    Some(
                        SocketContextLayout::CgroupSockopt
                        | SocketContextLayout::SkMsg
                        | SocketContextLayout::SkBuff
                        | SocketContextLayout::SockOps,
                    )
                    | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.protocol is only available on cgroup_sock, cgroup_sock_addr, and sk_lookup programs".to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::Socket => {
                let offset = match self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.socket_ref_context_layout())
                {
                    Some(SocketContextLayout::CgroupSock) => {
                        self.instructions
                            .push(EbpfInsn::mov64_reg(dst, EbpfReg::R9));
                        return Ok(());
                    }
                    Some(SocketContextLayout::CgroupSockopt) => Self::bpf_sockopt_offsets().0,
                    Some(SocketContextLayout::SockAddr) => Self::bpf_sock_addr_offsets().9,
                    Some(SocketContextLayout::SkLookup) => Self::bpf_sk_lookup_offsets().0,
                    Some(SocketContextLayout::SkMsg) => Self::sk_msg_md_sock_offset(),
                    Some(SocketContextLayout::SockOps) => Self::bpf_sock_ops_offsets().11,
                    Some(SocketContextLayout::SkBuff) | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.sk is only available on cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sk_lookup, sk_msg, and sock_ops programs".to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
            }
            CtxField::BoundDevIf => {
                let offset = Self::bpf_sock_offsets().0;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockMark => {
                let offset = match self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.sock_mark_priority_context_layout())
                {
                    Some(SocketContextLayout::CgroupSock) => Self::bpf_sock_offsets().4,
                    Some(SocketContextLayout::SkBuff) => Self::sk_buff_mark_priority_offsets().0,
                    Some(
                        SocketContextLayout::SockAddr
                        | SocketContextLayout::CgroupSockopt
                        | SocketContextLayout::SkLookup
                        | SocketContextLayout::SkMsg
                        | SocketContextLayout::SockOps,
                    )
                    | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.mark is only available on cgroup_sock and skb-backed packet programs"
                                .to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockPriority => {
                let offset = match self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.sock_mark_priority_context_layout())
                {
                    Some(SocketContextLayout::CgroupSock) => Self::bpf_sock_offsets().5,
                    Some(SocketContextLayout::SkBuff) => Self::sk_buff_mark_priority_offsets().1,
                    Some(
                        SocketContextLayout::SockAddr
                        | SocketContextLayout::CgroupSockopt
                        | SocketContextLayout::SkLookup
                        | SocketContextLayout::SkMsg
                        | SocketContextLayout::SockOps,
                    )
                    | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.priority is only available on cgroup_sock and skb-backed packet programs"
                                .to_string(),
                        ));
                    }
                };
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
                self.compile_ctx_u32_array_to_stack(
                    dst,
                    slot,
                    offset,
                    4,
                    "ctx.msg_src_ip6",
                    false,
                )?;
            }
            CtxField::RemoteIp4 => {
                let offset = match self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.socket_tuple_context_layout())
                {
                    Some(SocketContextLayout::SockOps) => Self::bpf_sock_ops_offsets().2,
                    Some(SocketContextLayout::SkMsg) => Self::sk_msg_md_offsets().3,
                    Some(SocketContextLayout::SkBuff) => Self::sk_buff_socket_offsets().1,
                    Some(SocketContextLayout::SkLookup) => Self::bpf_sk_lookup_offsets().3,
                    Some(
                        SocketContextLayout::SockAddr
                        | SocketContextLayout::CgroupSock
                        | SocketContextLayout::CgroupSockopt,
                    )
                    | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.remote_ip4 is only available on sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs".to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
                self.instructions.push(EbpfInsn::end32_to_be(dst));
            }
            CtxField::RemoteIp6 => {
                let offset = match self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.socket_tuple_context_layout())
                {
                    Some(SocketContextLayout::SockOps) => Self::bpf_sock_ops_offsets().4,
                    Some(SocketContextLayout::SkMsg) => Self::sk_msg_md_offsets().5,
                    Some(SocketContextLayout::SkBuff) => Self::sk_buff_socket_offsets().3,
                    Some(SocketContextLayout::SkLookup) => Self::bpf_sk_lookup_offsets().4,
                    Some(
                        SocketContextLayout::SockAddr
                        | SocketContextLayout::CgroupSock
                        | SocketContextLayout::CgroupSockopt,
                    )
                    | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.remote_ip6 is only available on sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs".to_string(),
                        ));
                    }
                };
                self.compile_ctx_u32_array_to_stack(dst, slot, offset, 4, "ctx.remote_ip6", true)?;
            }
            CtxField::RemotePort => {
                let layout = self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.socket_tuple_context_layout());
                let offset = match layout {
                    Some(SocketContextLayout::SockOps) => Self::bpf_sock_ops_offsets().6,
                    Some(SocketContextLayout::SkMsg) => Self::sk_msg_md_offsets().7,
                    Some(SocketContextLayout::SkBuff) => Self::sk_buff_socket_offsets().5,
                    Some(SocketContextLayout::SkLookup) => Self::bpf_sk_lookup_offsets().5,
                    Some(
                        SocketContextLayout::SockAddr
                        | SocketContextLayout::CgroupSock
                        | SocketContextLayout::CgroupSockopt,
                    )
                    | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.remote_port is only available on sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs".to_string(),
                        ));
                    }
                };
                if matches!(
                    layout,
                    Some(SocketContextLayout::SkMsg) | Some(SocketContextLayout::SkBuff)
                ) {
                    self.instructions
                        .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
                    self.instructions.push(EbpfInsn::end32_to_be(dst));
                } else {
                    self.instructions
                        .push(EbpfInsn::ldxh(dst, EbpfReg::R9, offset));
                    self.instructions.push(EbpfInsn::end16_to_be(dst));
                }
            }
            CtxField::LocalIp4 => {
                let offset = match self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.socket_tuple_context_layout())
                {
                    Some(SocketContextLayout::SockOps) => Self::bpf_sock_ops_offsets().3,
                    Some(SocketContextLayout::SkMsg) => Self::sk_msg_md_offsets().4,
                    Some(SocketContextLayout::SkBuff) => Self::sk_buff_socket_offsets().2,
                    Some(SocketContextLayout::SkLookup) => Self::bpf_sk_lookup_offsets().6,
                    Some(
                        SocketContextLayout::SockAddr
                        | SocketContextLayout::CgroupSock
                        | SocketContextLayout::CgroupSockopt,
                    )
                    | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.local_ip4 is only available on sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs".to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
                self.instructions.push(EbpfInsn::end32_to_be(dst));
            }
            CtxField::LocalIp6 => {
                let offset = match self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.socket_tuple_context_layout())
                {
                    Some(SocketContextLayout::SockOps) => Self::bpf_sock_ops_offsets().5,
                    Some(SocketContextLayout::SkMsg) => Self::sk_msg_md_offsets().6,
                    Some(SocketContextLayout::SkBuff) => Self::sk_buff_socket_offsets().4,
                    Some(SocketContextLayout::SkLookup) => Self::bpf_sk_lookup_offsets().7,
                    Some(
                        SocketContextLayout::SockAddr
                        | SocketContextLayout::CgroupSock
                        | SocketContextLayout::CgroupSockopt,
                    )
                    | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.local_ip6 is only available on sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs".to_string(),
                        ));
                    }
                };
                self.compile_ctx_u32_array_to_stack(dst, slot, offset, 4, "ctx.local_ip6", true)?;
            }
            CtxField::LocalPort => {
                let offset = match self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.socket_tuple_context_layout())
                {
                    Some(SocketContextLayout::SockOps) => Self::bpf_sock_ops_offsets().7,
                    Some(SocketContextLayout::SkMsg) => Self::sk_msg_md_offsets().8,
                    Some(SocketContextLayout::SkBuff) => Self::sk_buff_socket_offsets().6,
                    Some(SocketContextLayout::SkLookup) => Self::bpf_sk_lookup_offsets().8,
                    Some(
                        SocketContextLayout::SockAddr
                        | SocketContextLayout::CgroupSock
                        | SocketContextLayout::CgroupSockopt,
                    )
                    | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.local_port is only available on sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs".to_string(),
                        ));
                    }
                };
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::LookupCookie => {
                self.instructions.push(EbpfInsn::ldxdw(
                    dst,
                    EbpfReg::R9,
                    Self::bpf_sk_lookup_offsets().0,
                ));
            }
            CtxField::LircSample => {
                self.instructions.push(EbpfInsn::ldxw(dst, EbpfReg::R9, 0));
            }
            CtxField::LircValue => {
                self.instructions.push(EbpfInsn::ldxw(dst, EbpfReg::R9, 0));
                self.instructions
                    .push(EbpfInsn::and32_imm(dst, 0x00ff_ffff));
            }
            CtxField::LircMode => {
                self.instructions.push(EbpfInsn::ldxw(dst, EbpfReg::R9, 0));
                self.instructions
                    .push(EbpfInsn::and32_imm(dst, 0xff00_0000u32 as i32));
            }
            CtxField::DeviceAccessType => {
                let offset = Self::bpf_cgroup_dev_ctx_offsets().0;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::DeviceMajor => {
                let offset = Self::bpf_cgroup_dev_ctx_offsets().1;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::DeviceMinor => {
                let offset = Self::bpf_cgroup_dev_ctx_offsets().2;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOp => {
                let offset = Self::bpf_sock_ops_offsets().0;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsArgs => {
                let offset = Self::bpf_sock_ops_args_offset();
                self.compile_ctx_u32_array_to_stack(dst, slot, offset, 4, "ctx.args", false)?;
            }
            CtxField::IsFullsock => {
                let offset = Self::bpf_sock_ops_offsets().8;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsSndCwnd => {
                let offset = Self::bpf_sock_ops_tcp_field_offsets().0;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsSrttUs => {
                let offset = Self::bpf_sock_ops_tcp_field_offsets().1;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsCbFlags => {
                let offset = Self::bpf_sock_ops_offsets().9;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockState => {
                let offset = Self::bpf_sock_ops_offsets().10;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsRttMin => {
                let offset = Self::bpf_sock_ops_tcp_field_offsets().2;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsSndSsthresh => {
                let offset = Self::bpf_sock_ops_tcp_field_offsets().3;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsRcvNxt => {
                let offset = Self::bpf_sock_ops_progress_offsets().0;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsSndNxt => {
                let offset = Self::bpf_sock_ops_progress_offsets().1;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsSndUna => {
                let offset = Self::bpf_sock_ops_progress_offsets().2;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsMssCache => {
                let offset = Self::bpf_sock_ops_extra_metric_offsets().0;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsEcnFlags => {
                let offset = Self::bpf_sock_ops_extra_metric_offsets().1;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsRateDelivered => {
                let offset = Self::bpf_sock_ops_extra_metric_offsets().2;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsRateIntervalUs => {
                let offset = Self::bpf_sock_ops_extra_metric_offsets().3;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsPacketsOut => {
                let offset = Self::bpf_sock_ops_progress_offsets().3;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsRetransOut => {
                let offset = Self::bpf_sock_ops_progress_offsets().4;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsTotalRetrans => {
                let offset = Self::bpf_sock_ops_progress_offsets().5;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsSegsIn => {
                let offset = Self::bpf_sock_ops_extra_metric_offsets().4;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsDataSegsIn => {
                let offset = Self::bpf_sock_ops_extra_metric_offsets().5;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsSegsOut => {
                let offset = Self::bpf_sock_ops_extra_metric_offsets().6;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsDataSegsOut => {
                let offset = Self::bpf_sock_ops_extra_metric_offsets().7;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsLostOut => {
                let offset = Self::bpf_sock_ops_extra_metric_offsets().8;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsSackedOut => {
                let offset = Self::bpf_sock_ops_extra_metric_offsets().9;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsSkTxhash => {
                let offset = Self::bpf_sock_ops_extra_metric_offsets().10;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsBytesReceived => {
                let offset = Self::bpf_sock_ops_progress_offsets().6;
                self.instructions
                    .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsBytesAcked => {
                let offset = Self::bpf_sock_ops_progress_offsets().7;
                self.instructions
                    .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsSkbLen => {
                let offset = Self::bpf_sock_ops_skb_field_offsets().0;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsSkbTcpFlags => {
                let offset = Self::bpf_sock_ops_skb_field_offsets().1;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockOpsSkbHwtstamp => {
                let offset = Self::bpf_sock_ops_skb_field_offsets().2;
                self.instructions
                    .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
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
                let offset = Self::bpf_sockopt_offsets().3;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockoptOptname => {
                let offset = Self::bpf_sockopt_offsets().4;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockoptOptlen => {
                let offset = Self::bpf_sockopt_offsets().5;
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockoptOptval => {
                let offset = Self::bpf_sockopt_offsets().1;
                self.instructions
                    .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockoptOptvalEnd => {
                let offset = Self::bpf_sockopt_offsets().2;
                self.instructions
                    .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
            }
            CtxField::SockoptRetval => {
                let offset = Self::bpf_sockopt_offsets().6;
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
                        let spec = ctx
                            .btf_arg_spec(n)
                            .map_err(CompileError::UnsupportedInstruction)?
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(
                                    ctx.btf_arg_unavailable_error(n),
                                )
                            })?;
                        self.compile_trampoline_value_load(
                            dst,
                            slot,
                            spec,
                            &format!("ctx.arg{n}"),
                        )?;
                    }
                    Some(ctx) if ctx.probe_type.uses_raw_tracepoint_args() => {
                        let offset = Self::raw_tracepoint_arg_offset(n)?;
                        self.instructions
                            .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
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
                    let spec = ctx
                        .btf_ret_spec()
                        .map_err(CompileError::UnsupportedInstruction)?
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(ctx.btf_ret_unavailable_error())
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
                let ctx = btf
                    .get_tracepoint_context(&category, &tp_name)
                    .map_err(|e| CompileError::TracepointContextError {
                        category: category.clone(),
                        name: tp_name.clone(),
                        reason: e.to_string(),
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
                let offset = i16::try_from(field_info.offset).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "tracepoint field '{}' offset {} is too large",
                        name, field_info.offset
                    ))
                })?;

                if matches!(
                    field_info.type_info,
                    TypeInfo::Struct { .. } | TypeInfo::Array { .. }
                ) {
                    let slot = slot.ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "ctx.{} requires a stack backing slot",
                            name
                        ))
                    })?;
                    let dst_offset = self.slot_offset_i16(slot, 0)?;
                    let aligned_size = field_info.size.div_ceil(8) * 8;
                    if aligned_size > field_info.size {
                        self.emit_zero_bytes(EbpfReg::R10, dst_offset, aligned_size, EbpfReg::R0)?;
                    }
                    self.emit_copy_bytes(
                        EbpfReg::R9,
                        offset,
                        EbpfReg::R10,
                        dst_offset,
                        field_info.size,
                        EbpfReg::R0,
                    )?;
                    self.instructions
                        .push(EbpfInsn::mov64_reg(dst, EbpfReg::R10));
                    self.instructions
                        .push(EbpfInsn::add64_imm(dst, dst_offset as i32));
                    return Ok(());
                }

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
