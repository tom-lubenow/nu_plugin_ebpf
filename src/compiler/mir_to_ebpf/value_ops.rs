use super::*;

fn record_store_requires_pointer(ty: &MirType) -> bool {
    matches!(ty, MirType::Array { .. } | MirType::Struct { .. }) || ty.size() > 8
}

impl<'a> MirToEbpfCompiler<'a> {
    fn value_is_packet_ptr(&self, value: &MirValue) -> bool {
        match value {
            MirValue::VReg(vreg) => matches!(
                self.current_types.get(vreg),
                Some(MirType::Ptr {
                    address_space: crate::compiler::mir::AddressSpace::Packet,
                    ..
                })
            ),
            _ => false,
        }
    }

    pub(super) fn compile_copy(&mut self, dst: VReg, src: &MirValue) -> Result<(), CompileError> {
        let dst_reg = self.alloc_dst_reg(dst)?;
        match src {
            MirValue::VReg(v) => {
                let src_reg = self.ensure_reg(*v)?;
                if dst_reg != src_reg {
                    self.instructions
                        .push(EbpfInsn::mov64_reg(dst_reg, src_reg));
                }
            }
            MirValue::Const(c) => {
                if *c >= i32::MIN as i64 && *c <= i32::MAX as i64 {
                    self.instructions
                        .push(EbpfInsn::mov64_imm(dst_reg, *c as i32));
                } else {
                    // Large constant - split into two parts
                    let low = *c as i32;
                    let high = (*c >> 32) as i32;
                    self.instructions.push(EbpfInsn::mov64_imm(dst_reg, low));
                    if high != 0 {
                        self.instructions
                            .push(EbpfInsn::mov64_imm(EbpfReg::R0, high));
                        self.instructions.push(EbpfInsn::lsh64_imm(EbpfReg::R0, 32));
                        self.instructions
                            .push(EbpfInsn::or64_reg(dst_reg, EbpfReg::R0));
                    }
                }
            }
            MirValue::StackSlot(slot) => {
                let offset = self.slot_offsets.get(slot).copied().unwrap_or(0);
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst_reg, EbpfReg::R10));
                self.instructions
                    .push(EbpfInsn::add64_imm(dst_reg, offset as i32));
            }
        }
        Ok(())
    }

    pub(super) fn compile_load_inst(
        &mut self,
        dst: VReg,
        ptr: VReg,
        offset: i32,
        ty: &MirType,
    ) -> Result<(), CompileError> {
        let dst_reg = self.alloc_dst_reg(dst)?;
        let ptr_reg = self.ensure_reg(ptr)?;
        let size = ty.size();
        let offset = i16::try_from(offset).map_err(|_| {
            CompileError::UnsupportedInstruction(format!("load offset {} out of range", offset))
        })?;
        self.emit_load(dst_reg, ptr_reg, offset, size)?;
        Ok(())
    }

    pub(super) fn compile_store_inst(
        &mut self,
        ptr: VReg,
        offset: i32,
        val: &MirValue,
        ty: &MirType,
    ) -> Result<(), CompileError> {
        let ptr_reg = self.ensure_reg(ptr)?;
        let size = ty.size();
        let offset = i16::try_from(offset).map_err(|_| {
            CompileError::UnsupportedInstruction(format!("store offset {} out of range", offset))
        })?;
        let val_reg = self.value_to_reg(val)?;
        self.emit_store(ptr_reg, offset, val_reg, size)?;
        Ok(())
    }

    pub(super) fn compile_load_slot_inst(
        &mut self,
        dst: VReg,
        slot: StackSlotId,
        offset: i32,
        ty: &MirType,
    ) -> Result<(), CompileError> {
        let dst_reg = self.alloc_dst_reg(dst)?;
        let size = ty.size();
        let offset = self.slot_offset_i16(slot, offset)?;
        self.emit_load(dst_reg, EbpfReg::R10, offset, size)?;
        Ok(())
    }

    pub(super) fn compile_store_slot_inst(
        &mut self,
        slot: StackSlotId,
        offset: i32,
        val: &MirValue,
        ty: &MirType,
    ) -> Result<(), CompileError> {
        let size = ty.size();
        let offset = self.slot_offset_i16(slot, offset)?;
        let val_reg = self.value_to_reg(val)?;
        self.emit_store(EbpfReg::R10, offset, val_reg, size)?;
        Ok(())
    }

    pub(super) fn compile_record_store_inst(
        &mut self,
        buffer: StackSlotId,
        field_offset: usize,
        val: &MirValue,
        ty: &MirType,
    ) -> Result<(), CompileError> {
        let size = ty.size();
        if size == 0 {
            return Err(CompileError::UnsupportedInstruction(
                "record store size must be positive".into(),
            ));
        }

        let field_offset = i32::try_from(field_offset).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "record store field offset {} out of range",
                field_offset
            ))
        })?;
        let dst_offset = self.slot_offset_i16(buffer, field_offset)?;

        if record_store_requires_pointer(ty) {
            if matches!(val, MirValue::Const(_)) {
                return Err(CompileError::UnsupportedInstruction(
                    "record store expects stack/map pointer for aggregate field".into(),
                ));
            }
            let src_reg = self.value_to_reg(val)?;
            let copy_size = match val {
                MirValue::VReg(vreg) => {
                    self.vreg_stack_or_map_copy_size(*vreg, size)
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "record store expects stack/map pointer for aggregate field".into(),
                            )
                        })?
                }
                MirValue::StackSlot(_) => size,
                MirValue::Const(_) => unreachable!(),
            }
            .min(size);

            if copy_size > 0 {
                self.emit_copy_bytes(src_reg, 0, EbpfReg::R10, dst_offset, copy_size, EbpfReg::R0)?;
            }
            if copy_size < size {
                let pad_offset = self.add_i16_offset(dst_offset, copy_size)?;
                self.emit_zero_bytes(EbpfReg::R10, pad_offset, size - copy_size, EbpfReg::R0)?;
            }
        } else {
            let val_reg = self.value_to_reg(val)?;
            self.emit_store(EbpfReg::R10, dst_offset, val_reg, size)?;
        }
        Ok(())
    }

    pub(super) fn compile_strcmp_inst(
        &mut self,
        dst: VReg,
        lhs: StackSlotId,
        rhs: StackSlotId,
        len: usize,
    ) -> Result<(), CompileError> {
        let dst_reg = self.alloc_dst_reg(dst)?;
        let lhs_base = self.slot_offset_i16(lhs, 0)?;
        let rhs_base = self.slot_offset_i16(rhs, 0)?;

        self.instructions.push(EbpfInsn::mov64_imm(dst_reg, 1));
        for idx in 0..len {
            let lhs_offset = self.add_i16_offset(lhs_base, idx)?;
            let rhs_offset = self.add_i16_offset(rhs_base, idx)?;
            self.emit_load(EbpfReg::R1, EbpfReg::R10, lhs_offset, 1)?;
            self.emit_load(EbpfReg::R2, EbpfReg::R10, rhs_offset, 1)?;
            self.instructions
                .push(EbpfInsn::jeq_reg(EbpfReg::R1, EbpfReg::R2, 1));
            self.instructions.push(EbpfInsn::mov64_imm(dst_reg, 0));
        }
        Ok(())
    }

    pub(super) fn compile_binop(
        &mut self,
        dst: VReg,
        op: BinOpKind,
        lhs: &MirValue,
        rhs: &MirValue,
    ) -> Result<(), CompileError> {
        let dst_reg = self.alloc_dst_reg(dst)?;
        let unsigned_compare = matches!(
            op,
            BinOpKind::Lt | BinOpKind::Le | BinOpKind::Gt | BinOpKind::Ge
        ) && self.value_is_packet_ptr(lhs)
            && self.value_is_packet_ptr(rhs);
        let lhs_src_reg = match lhs {
            MirValue::VReg(v) => Some(self.ensure_reg(*v)?),
            _ => None,
        };
        let lhs_vreg = match lhs {
            MirValue::VReg(v) => Some(*v),
            _ => None,
        };
        let rhs_vreg = match rhs {
            MirValue::VReg(v) => Some(*v),
            _ => None,
        };
        let mut rhs_reg = match rhs {
            MirValue::VReg(v) => Some(self.ensure_reg(*v)?),
            _ => None,
        };
        let mut spilled_rhs: Option<(EbpfReg, i16)> = None;

        if let (Some(rhs_reg_value), Some(rhs_vreg)) = (rhs_reg, rhs_vreg) {
            if rhs_reg_value == dst_reg && lhs_vreg != Some(rhs_vreg) {
                if dst_reg != EbpfReg::R0 {
                    self.instructions
                        .push(EbpfInsn::mov64_reg(EbpfReg::R0, rhs_reg_value));
                    rhs_reg = Some(EbpfReg::R0);
                } else {
                    self.check_stack_space(8)?;
                    self.stack_offset -= 8;
                    let spill_offset = self.stack_offset;
                    self.emit_store(EbpfReg::R10, spill_offset, rhs_reg_value, 8)?;

                    let reload_reg = lhs_src_reg
                        .filter(|reg| *reg != dst_reg)
                        .or_else(|| {
                            self.available_regs
                                .iter()
                                .copied()
                                .find(|reg| *reg != dst_reg)
                        })
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "no temporary register available for binop rhs preservation".into(),
                            )
                        })?;

                    rhs_reg = Some(reload_reg);
                    spilled_rhs = Some((reload_reg, spill_offset));
                }
            }
        }

        // Load LHS into dst
        match lhs {
            MirValue::VReg(_v) => {
                let src = lhs_src_reg.expect("lhs vreg register should already be resolved");
                if dst_reg != src {
                    self.instructions.push(EbpfInsn::mov64_reg(dst_reg, src));
                }
            }
            MirValue::Const(c) => {
                self.instructions
                    .push(EbpfInsn::mov64_imm(dst_reg, *c as i32));
            }
            MirValue::StackSlot(_) => {
                return Err(CompileError::UnsupportedInstruction(
                    "Stack slot in binop LHS".into(),
                ));
            }
        }

        if let Some((reload_reg, spill_offset)) = spilled_rhs {
            self.emit_load(reload_reg, EbpfReg::R10, spill_offset, 8)?;
        }

        // Apply operation with RHS
        match rhs {
            MirValue::VReg(v) => {
                let rhs_reg = rhs_reg.unwrap_or(self.ensure_reg(*v)?);
                self.emit_binop_reg(dst_reg, op, rhs_reg, unsigned_compare)?;
            }
            MirValue::Const(c) => {
                self.emit_binop_imm(dst_reg, op, *c as i32, unsigned_compare)?;
            }
            MirValue::StackSlot(_) => {
                return Err(CompileError::UnsupportedInstruction(
                    "Stack slot in binop RHS".into(),
                ));
            }
        }

        if spilled_rhs.is_some() {
            self.stack_offset += 8;
        }

        Ok(())
    }

    pub(super) fn compile_unary(
        &mut self,
        dst: VReg,
        op: UnaryOpKind,
        src: &MirValue,
    ) -> Result<(), CompileError> {
        let dst_reg = self.alloc_dst_reg(dst)?;
        match src {
            MirValue::VReg(v) => {
                let src_reg = self.ensure_reg(*v)?;
                if dst_reg != src_reg {
                    self.instructions
                        .push(EbpfInsn::mov64_reg(dst_reg, src_reg));
                }
            }
            MirValue::Const(c) => {
                self.instructions
                    .push(EbpfInsn::mov64_imm(dst_reg, *c as i32));
            }
            MirValue::StackSlot(_) => {
                return Err(CompileError::UnsupportedInstruction(
                    "Stack slot in unary op".into(),
                ));
            }
        }

        match op {
            UnaryOpKind::Not => {
                // Logical not: 0 -> 1, non-zero -> 0.
                self.instructions.push(EbpfInsn::new(
                    opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_K,
                    dst_reg.as_u8(),
                    0,
                    2,
                    0,
                ));
                self.instructions.push(EbpfInsn::mov64_imm(dst_reg, 0));
                self.instructions.push(EbpfInsn::jump(1));
                self.instructions.push(EbpfInsn::mov64_imm(dst_reg, 1));
            }
            UnaryOpKind::BitNot => {
                self.instructions.push(EbpfInsn::xor64_imm(dst_reg, -1));
            }
            UnaryOpKind::Neg => {
                self.instructions.push(EbpfInsn::neg64(dst_reg));
            }
        }

        Ok(())
    }
}
