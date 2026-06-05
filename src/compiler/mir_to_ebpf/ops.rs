use super::*;
use crate::compiler::ctx_field_schema::SYSCTL_STRING_FIELD_LEN;
use crate::compiler::elf::{
    ContextFieldArrayLoad, ContextFieldDirectLoad, ContextFieldDirectLoadWidth,
    ContextFieldNestedLoad, SocketContextLayout,
};
use crate::kernel_btf::{TrampolineValueKind, TrampolineValueSpec, TypeInfo};

mod context;

const BPF_CSUM_LEVEL_QUERY: i32 = 0;
const BPF_F_SYSCTL_BASE_NAME: i32 = 1;

impl<'a> MirToEbpfCompiler<'a> {
    fn cgroup_sock_addr_tuple_alias_field(&self, field: &CtxField) -> Option<CtxField> {
        self.probe_ctx
            .as_ref()?
            .parsed_program_spec()?
            .cgroup_sock_addr_tuple_alias_field(field)
    }

    fn ctx_field_direct_load(
        &self,
        field: &CtxField,
    ) -> Result<ContextFieldDirectLoad, CompileError> {
        self.probe_ctx
            .as_ref()
            .and_then(|ctx| {
                ctx.parsed_program_spec()
                    .and_then(|spec| spec.ctx_field_direct_load(field))
                    .or_else(|| ctx.program_type().ctx_field_direct_load(field))
            })
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "ctx.{} is not available as a direct context load for this program",
                    field.display_name()
                ))
            })
    }

    fn ctx_field_array_load(
        &self,
        field: &CtxField,
    ) -> Result<ContextFieldArrayLoad, CompileError> {
        self.probe_ctx
            .as_ref()
            .and_then(|ctx| {
                ctx.parsed_program_spec()
                    .and_then(|spec| spec.ctx_field_array_load(field))
                    .or_else(|| ctx.program_type().ctx_field_array_load(field))
            })
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "ctx.{} is not available as a context array load for this program",
                    field.display_name()
                ))
            })
    }

    fn ctx_field_nested_load(
        &self,
        field: &CtxField,
    ) -> Result<ContextFieldNestedLoad, CompileError> {
        self.probe_ctx
            .as_ref()
            .and_then(|ctx| {
                ctx.parsed_program_spec()
                    .and_then(|spec| spec.ctx_field_nested_load(field))
                    .or_else(|| ctx.program_type().ctx_field_nested_load(field))
            })
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "ctx.{} is not available as a nested context load for this program",
                    field.display_name()
                ))
            })
    }

    fn compile_ctx_array_field_to_stack(
        &mut self,
        dst: EbpfReg,
        field: &CtxField,
        slot: Option<StackSlotId>,
        field_name: &str,
    ) -> Result<(), CompileError> {
        let load = self.ctx_field_array_load(field)?;
        self.compile_ctx_u32_array_to_stack(
            dst,
            slot,
            load.base_offset,
            load.count,
            field_name,
            load.normalize_big_endian,
        )
    }

    fn emit_ctx_direct_load(&mut self, dst: EbpfReg, load: ContextFieldDirectLoad) {
        match load.width {
            ContextFieldDirectLoadWidth::U8 => {
                self.instructions
                    .push(EbpfInsn::ldxb(dst, EbpfReg::R9, load.offset));
            }
            ContextFieldDirectLoadWidth::U16 => {
                self.instructions
                    .push(EbpfInsn::ldxh(dst, EbpfReg::R9, load.offset));
            }
            ContextFieldDirectLoadWidth::U32 => {
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R9, load.offset));
            }
            ContextFieldDirectLoadWidth::U64 => {
                self.instructions
                    .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, load.offset));
            }
        }
    }

    fn emit_ctx_nested_load(&mut self, dst: EbpfReg, load: ContextFieldNestedLoad) {
        self.instructions.push(EbpfInsn::ldxdw(
            EbpfReg::R0,
            EbpfReg::R9,
            load.pointer_offset,
        ));
        match load.field_load.width {
            ContextFieldDirectLoadWidth::U8 => {
                self.instructions
                    .push(EbpfInsn::ldxb(dst, EbpfReg::R0, load.field_load.offset));
            }
            ContextFieldDirectLoadWidth::U16 => {
                self.instructions
                    .push(EbpfInsn::ldxh(dst, EbpfReg::R0, load.field_load.offset));
            }
            ContextFieldDirectLoadWidth::U32 => {
                self.instructions
                    .push(EbpfInsn::ldxw(dst, EbpfReg::R0, load.field_load.offset));
            }
            ContextFieldDirectLoadWidth::U64 => {
                self.instructions
                    .push(EbpfInsn::ldxdw(dst, EbpfReg::R0, load.field_load.offset));
            }
        }
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
            BinOpKind::ArShr => self.instructions.push(EbpfInsn::arsh64_reg(dst, rhs)),
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
            BinOpKind::ArShr => self.instructions.push(EbpfInsn::arsh64_imm(dst, imm)),
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
                self.emit_load_const(EbpfReg::R0, *c);
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
            CtxField::Tgid => {
                // Upper 32 bits = thread group ID (what userspace calls PID)
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
                self.instructions.push(EbpfInsn::rsh64_imm(EbpfReg::R0, 32));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::PidTgid => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentPidTgid));
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
            CtxField::UidGid => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentUidGid));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::Task => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentTaskBtf));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::IterTask
            | CtxField::IterMeta
            | CtxField::IterFd
            | CtxField::IterFile
            | CtxField::IterVma
            | CtxField::IterCgroup
            | CtxField::IterMap
            | CtxField::IterMapKey
            | CtxField::IterMapValue
            | CtxField::IterProg
            | CtxField::IterLink
            | CtxField::IterSkCommon
            | CtxField::IterUdpSk
            | CtxField::IterUnixSk
            | CtxField::IterUid
            | CtxField::IterBucket
            | CtxField::IterDmabuf
            | CtxField::IterIpv6Route
            | CtxField::IterKmemCache
            | CtxField::IterKsym
            | CtxField::IterNetlinkSk
            | CtxField::IterSock => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::Cgroup => {
                return Err(CompileError::UnsupportedInstruction(
                    "ctx.cgroup must be lowered through task_struct.cgroups.dfl_cgrp before codegen"
                        .into(),
                ));
            }
            CtxField::Timestamp => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::KtimeGetNs));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::BootTimestamp => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::KtimeGetBootNs));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::CoarseTimestamp => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::KtimeGetCoarseNs));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::TaiTimestamp => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::KtimeGetTaiNs));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::Jiffies => {
                self.instructions.push(EbpfInsn::call(BpfHelper::Jiffies64));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::FuncIp => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));
                self.instructions.push(EbpfInsn::call(BpfHelper::GetFuncIp));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::AttachCookie => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetAttachCookie));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::Cpu => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetSmpProcessorId));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::NumaNode => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetNumaNodeId));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::Random => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetPrandomU32));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::CgroupId => {
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCurrentCgroupId));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::PerfSamplePeriod => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::PerfAddr => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::PerfCounter => {
                self.compile_perf_event_value_field(dst, 0)?;
            }
            CtxField::PerfEnabled => {
                self.compile_perf_event_value_field(dst, 8)?;
            }
            CtxField::PerfRunning => {
                self.compile_perf_event_value_field(dst, 16)?;
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
            CtxField::CgroupClassid => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetCgroupClassid));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::RouteRealm => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetRouteRealm));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::CsumLevel => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));
                self.instructions
                    .push(EbpfInsn::mov64_imm(EbpfReg::R2, BPF_CSUM_LEVEL_QUERY));
                self.instructions.push(EbpfInsn::call(BpfHelper::CsumLevel));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::HashRecalc => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetHashRecalc));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::SkbCgroupId => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::SkbCgroupId));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::XdpBuffLen => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::XdpGetBuffLen));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::PacketLen => match self.packet_context_kind()? {
                PacketContextKind::XdpMd => {
                    let data_end_load = self.ctx_field_direct_load(&CtxField::DataEnd)?;
                    self.emit_ctx_direct_load(dst, data_end_load);
                    let data_load = self.ctx_field_direct_load(&CtxField::Data)?;
                    self.emit_ctx_direct_load(EbpfReg::R0, data_load);
                    self.instructions
                        .push(EbpfInsn::sub64_reg(dst, EbpfReg::R0));
                }
                _ => {
                    let load = self.ctx_field_direct_load(field)?;
                    self.emit_ctx_direct_load(dst, load);
                }
            },
            CtxField::PktType => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::QueueMapping => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::EthProtocol => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
                self.instructions.push(EbpfInsn::end16_to_be(dst));
            }
            CtxField::VlanPresent => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::VlanTci => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::VlanProto => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
                self.instructions.push(EbpfInsn::end16_to_be(dst));
            }
            CtxField::SkbCb => {
                self.compile_ctx_array_field_to_stack(dst, field, slot, "ctx.cb")?;
            }
            CtxField::TcClassid => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::NapiId => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::WireLen => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::GsoSegs => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::GsoSize => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::Tstamp => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::TstampType => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::Hwtstamp => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::Data => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::DataMeta => match self.data_meta_context_kind()? {
                PacketContextKind::XdpMd | PacketContextKind::SkBuff => {
                    let load = self.ctx_field_direct_load(field)?;
                    self.emit_ctx_direct_load(dst, load);
                }
                _ => unreachable!("data_meta context kind must be xdp or skb"),
            },
            CtxField::DataEnd => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::IngressIfindex => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::Ifindex => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::RxQueueIndex => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::EgressIfindex => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::TcIndex => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SkbHash => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::UserFamily => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::UserIp4 => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::UserIp6 => {
                self.compile_ctx_array_field_to_stack(dst, field, slot, "ctx.user_ip6")?;
            }
            CtxField::UserPort => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::Family => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockType => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::Protocol => {
                let layout = self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.protocol_context_layout());
                match layout {
                    Some(
                        layout @ (SocketContextLayout::CgroupSock
                        | SocketContextLayout::SockAddr
                        | SocketContextLayout::SkLookup
                        | SocketContextLayout::SkBuff
                        | SocketContextLayout::SkReuseport),
                    ) => {
                        let load = self.ctx_field_direct_load(field)?;
                        self.emit_ctx_direct_load(dst, load);
                        if matches!(layout, SocketContextLayout::SkBuff) {
                            self.instructions.push(EbpfInsn::end16_to_be(dst));
                        }
                    }
                    Some(
                        SocketContextLayout::CgroupSockopt
                        | SocketContextLayout::SkMsg
                        | SocketContextLayout::SockOps,
                    )
                    | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.protocol is only available on skb-backed packet, cgroup_sock, cgroup_sock_addr, sk_lookup, and sk_reuseport programs".to_string(),
                        ));
                    }
                }
            }
            CtxField::Socket => {
                match self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.socket_ref_context_layout())
                {
                    Some(SocketContextLayout::CgroupSock) => {
                        self.instructions
                            .push(EbpfInsn::mov64_reg(dst, EbpfReg::R9));
                        return Ok(());
                    }
                    None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.sk is only available on socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sk_lookup, sk_reuseport, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs".to_string(),
                        ));
                    }
                    Some(_) => {
                        let load = self.ctx_field_direct_load(field)?;
                        self.emit_ctx_direct_load(dst, load);
                    }
                }
            }
            CtxField::FlowKeys => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::NetfilterState | CtxField::NetfilterSkb => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::NetfilterHook | CtxField::NetfilterProtocolFamily => {
                let load = self.ctx_field_nested_load(field)?;
                self.emit_ctx_nested_load(dst, load);
            }
            CtxField::BindInany => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::MigratingSocket => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::BoundDevIf => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockMark => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockPriority => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::MsgSrcIp4 => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::MsgSrcIp6 => {
                self.compile_ctx_array_field_to_stack(dst, field, slot, "ctx.msg_src_ip6")?;
            }
            CtxField::RemoteIp4 => {
                let layout = self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.socket_tuple_context_layout());
                match layout {
                    Some(SocketContextLayout::SockAddr) => {
                        let Some(alias_field) = self.cgroup_sock_addr_tuple_alias_field(field)
                        else {
                            return Err(CompileError::UnsupportedInstruction(
                                "ctx.remote_ip4 is only available on cgroup_sock_addr connect4/connect6, getpeername4/getpeername6, sendmsg4/sendmsg6, and recvmsg4/recvmsg6 hooks".to_string(),
                            ));
                        };
                        return self.compile_load_ctx_field(dst, &alias_field, slot);
                    }
                    Some(
                        SocketContextLayout::CgroupSock
                        | SocketContextLayout::SockOps
                        | SocketContextLayout::SkMsg
                        | SocketContextLayout::SkBuff
                        | SocketContextLayout::SkLookup,
                    ) => {
                        let load = self.ctx_field_direct_load(field)?;
                        self.emit_ctx_direct_load(dst, load);
                        self.instructions.push(EbpfInsn::end32_to_be(dst));
                    }
                    Some(SocketContextLayout::CgroupSockopt | SocketContextLayout::SkReuseport)
                    | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.remote_ip4 is only available on cgroup_sock, cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs".to_string(),
                        ));
                    }
                }
            }
            CtxField::RemoteIp6 => {
                match self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.socket_tuple_context_layout())
                {
                    Some(SocketContextLayout::SockAddr) => {
                        let Some(alias_field) = self.cgroup_sock_addr_tuple_alias_field(field)
                        else {
                            return Err(CompileError::UnsupportedInstruction(
                                "ctx.remote_ip6 is only available on cgroup_sock_addr connect4/connect6, getpeername4/getpeername6, sendmsg4/sendmsg6, and recvmsg4/recvmsg6 hooks".to_string(),
                            ));
                        };
                        return self.compile_load_ctx_field(dst, &alias_field, slot);
                    }
                    _ => {}
                }
                self.compile_ctx_array_field_to_stack(dst, field, slot, "ctx.remote_ip6")?;
            }
            CtxField::RemotePort => {
                let layout = self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.socket_tuple_context_layout());
                match layout {
                    Some(SocketContextLayout::SockAddr) => {
                        let Some(alias_field) = self.cgroup_sock_addr_tuple_alias_field(field)
                        else {
                            return Err(CompileError::UnsupportedInstruction(
                                "ctx.remote_port is only available on cgroup_sock_addr connect4/connect6, getpeername4/getpeername6, sendmsg4/sendmsg6, and recvmsg4/recvmsg6 hooks".to_string(),
                            ));
                        };
                        return self.compile_load_ctx_field(dst, &alias_field, slot);
                    }
                    Some(
                        layout @ (SocketContextLayout::CgroupSock
                        | SocketContextLayout::SockOps
                        | SocketContextLayout::SkMsg
                        | SocketContextLayout::SkBuff
                        | SocketContextLayout::SkLookup),
                    ) => {
                        let load = self.ctx_field_direct_load(field)?;
                        self.emit_ctx_direct_load(dst, load);
                        if matches!(
                            layout,
                            SocketContextLayout::SkMsg | SocketContextLayout::SkBuff
                        ) {
                            self.instructions.push(EbpfInsn::end32_to_be(dst));
                        } else {
                            self.instructions.push(EbpfInsn::end16_to_be(dst));
                        }
                    }
                    Some(SocketContextLayout::CgroupSockopt | SocketContextLayout::SkReuseport)
                    | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.remote_port is only available on cgroup_sock, cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs".to_string(),
                        ));
                    }
                }
            }
            CtxField::LocalIp4 => {
                let layout = self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.socket_tuple_context_layout());
                match layout {
                    Some(SocketContextLayout::SockAddr) => {
                        let Some(alias_field) = self.cgroup_sock_addr_tuple_alias_field(field)
                        else {
                            return Err(CompileError::UnsupportedInstruction(
                                "ctx.local_ip4 is only available on cgroup_sock_addr bind4/bind6, getsockname4/getsockname6, and sendmsg4/sendmsg6 hooks".to_string(),
                            ));
                        };
                        return self.compile_load_ctx_field(dst, &alias_field, slot);
                    }
                    Some(
                        SocketContextLayout::CgroupSock
                        | SocketContextLayout::SockOps
                        | SocketContextLayout::SkMsg
                        | SocketContextLayout::SkBuff
                        | SocketContextLayout::SkLookup,
                    ) => {
                        let load = self.ctx_field_direct_load(field)?;
                        self.emit_ctx_direct_load(dst, load);
                        self.instructions.push(EbpfInsn::end32_to_be(dst));
                    }
                    Some(SocketContextLayout::CgroupSockopt | SocketContextLayout::SkReuseport)
                    | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.local_ip4 is only available on cgroup_sock post_bind4, cgroup_skb, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs".to_string(),
                        ));
                    }
                }
            }
            CtxField::LocalIp6 => {
                match self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.socket_tuple_context_layout())
                {
                    Some(SocketContextLayout::SockAddr) => {
                        let Some(alias_field) = self.cgroup_sock_addr_tuple_alias_field(field)
                        else {
                            return Err(CompileError::UnsupportedInstruction(
                                "ctx.local_ip6 is only available on cgroup_sock_addr bind4/bind6, getsockname4/getsockname6, and sendmsg4/sendmsg6 hooks".to_string(),
                            ));
                        };
                        return self.compile_load_ctx_field(dst, &alias_field, slot);
                    }
                    _ => {}
                }
                self.compile_ctx_array_field_to_stack(dst, field, slot, "ctx.local_ip6")?;
            }
            CtxField::LocalPort => {
                let layout = self
                    .probe_ctx
                    .as_ref()
                    .and_then(|ctx| ctx.socket_tuple_context_layout());
                match layout {
                    Some(SocketContextLayout::SockAddr) => {
                        let Some(alias_field) = self.cgroup_sock_addr_tuple_alias_field(field)
                        else {
                            return Err(CompileError::UnsupportedInstruction(
                                "ctx.local_port is only available on cgroup_sock_addr bind4/bind6 and getsockname4/getsockname6 hooks".to_string(),
                            ));
                        };
                        return self.compile_load_ctx_field(dst, &alias_field, slot);
                    }
                    Some(
                        SocketContextLayout::CgroupSock
                        | SocketContextLayout::SockOps
                        | SocketContextLayout::SkMsg
                        | SocketContextLayout::SkBuff
                        | SocketContextLayout::SkLookup,
                    ) => {
                        let load = self.ctx_field_direct_load(field)?;
                        self.emit_ctx_direct_load(dst, load);
                    }
                    Some(SocketContextLayout::CgroupSockopt | SocketContextLayout::SkReuseport)
                    | None => {
                        return Err(CompileError::UnsupportedInstruction(
                            "ctx.local_port is only available on cgroup_sock post_bind4/post_bind6 hooks and socket tuple programs".to_string(),
                        ));
                    }
                }
            }
            CtxField::LookupCookie => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::LircSample => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::LircValue => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
                self.instructions
                    .push(EbpfInsn::and32_imm(dst, 0x00ff_ffff));
            }
            CtxField::LircMode => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
                self.instructions
                    .push(EbpfInsn::and32_imm(dst, 0xff00_0000u32 as i32));
            }
            CtxField::DeviceAccessType => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::DeviceAccess => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
                self.instructions.push(EbpfInsn::rsh64_imm(dst, 16));
            }
            CtxField::DeviceType => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
                self.instructions.push(EbpfInsn::and64_imm(dst, 0xffff));
            }
            CtxField::DeviceMajor => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::DeviceMinor => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOp => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsArgs => {
                self.compile_ctx_array_field_to_stack(dst, field, slot, "ctx.args")?;
            }
            CtxField::SockOpsReply => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsReplyLong => {
                self.compile_ctx_array_field_to_stack(dst, field, slot, "ctx.replylong")?;
            }
            CtxField::IsFullsock => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsSndCwnd => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsSrttUs => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsCbFlags => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockState => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockRxQueueMapping => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsRttMin => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsSndSsthresh => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsRcvNxt => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsSndNxt => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsSndUna => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsMssCache => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsEcnFlags => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsRateDelivered => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsRateIntervalUs => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsPacketsOut => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsRetransOut => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsTotalRetrans => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsSegsIn => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsDataSegsIn => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsSegsOut => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsDataSegsOut => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsLostOut => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsSackedOut => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsSkTxhash => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsBytesReceived => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsBytesAcked => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsSkbLen => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsSkbTcpFlags => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockOpsSkbHwtstamp => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SysctlWrite => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SysctlFilePos => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SysctlName
            | CtxField::SysctlBaseName
            | CtxField::SysctlCurrentValue
            | CtxField::SysctlNewValue => {
                let helper = match field {
                    CtxField::SysctlName | CtxField::SysctlBaseName => BpfHelper::SysctlGetName,
                    CtxField::SysctlCurrentValue => BpfHelper::SysctlGetCurrentValue,
                    CtxField::SysctlNewValue => BpfHelper::SysctlGetNewValue,
                    _ => unreachable!(),
                };
                let name_flags = match field {
                    CtxField::SysctlName => Some(0),
                    CtxField::SysctlBaseName => Some(BPF_F_SYSCTL_BASE_NAME),
                    _ => None,
                };
                let field_name = field.display_name();
                let buf_offset = if let Some(slot) = slot {
                    *self.slot_offsets.get(&slot).ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "{field_name} stack slot not found"
                        ))
                    })?
                } else {
                    self.check_stack_space(SYSCTL_STRING_FIELD_LEN as i16)?;
                    self.stack_offset -= SYSCTL_STRING_FIELD_LEN as i16;
                    self.stack_offset
                };

                self.emit_zero_bytes(
                    EbpfReg::R10,
                    buf_offset,
                    SYSCTL_STRING_FIELD_LEN,
                    EbpfReg::R0,
                )?;

                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(EbpfReg::R2, buf_offset as i32));
                self.instructions.push(EbpfInsn::mov64_imm(
                    EbpfReg::R3,
                    SYSCTL_STRING_FIELD_LEN as i32,
                ));
                if let Some(flags) = name_flags {
                    self.instructions
                        .push(EbpfInsn::mov64_imm(EbpfReg::R4, flags));
                }
                self.instructions.push(EbpfInsn::call(helper));

                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(dst, buf_offset as i32));
            }
            CtxField::SockoptLevel => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockoptOptname => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockoptOptlen => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockoptOptval => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockoptOptvalEnd => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
            }
            CtxField::SockoptRetval => {
                let load = self.ctx_field_direct_load(field)?;
                self.emit_ctx_direct_load(dst, load);
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
            CtxField::ArgCount => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));
                self.instructions
                    .push(EbpfInsn::call(BpfHelper::GetFuncArgCnt));
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));
            }
            CtxField::Arg(n) => {
                let n = *n as usize;
                match self.probe_ctx {
                    Some(ctx) if ctx.uses_btf_trampoline() => {
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
                    Some(ctx) if ctx.uses_raw_tracepoint_args() => {
                        let load = self.ctx_field_direct_load(field)?;
                        self.emit_ctx_direct_load(dst, load);
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
                        // R9 contains the saved pt_regs context pointer for pt_regs-backed paths.
                        self.instructions
                            .push(EbpfInsn::ldxdw(dst, EbpfReg::R9, offset));
                    }
                }
            }
            CtxField::RetVal => match self.probe_ctx {
                Some(ctx) if ctx.retval_access().is_trampoline() => {
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
                        && !ctx.supports_ctx_retval()
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
                let probe_ctx = self.probe_ctx.ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "Tracepoint field access requires probe context".into(),
                    )
                })?;
                let field_info = probe_ctx.tracepoint_field_info_or_error(name)?;

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
