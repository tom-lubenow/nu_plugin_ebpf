use super::*;

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
        let mut preserved_rhs_spill: Option<(EbpfReg, i16)> = None;

        if let (Some(rhs_reg_value), Some(rhs_vreg)) = (rhs_reg, rhs_vreg) {
            if rhs_reg_value == dst_reg && lhs_vreg != Some(rhs_vreg) {
                let spill_reg = [
                    EbpfReg::R1,
                    EbpfReg::R2,
                    EbpfReg::R3,
                    EbpfReg::R4,
                    EbpfReg::R5,
                    EbpfReg::R6,
                    EbpfReg::R7,
                    EbpfReg::R8,
                    EbpfReg::R9,
                ]
                .into_iter()
                .find(|reg| *reg != dst_reg && Some(*reg) != lhs_src_reg)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "no temporary register available for binop rhs preservation".into(),
                    )
                })?;

                self.check_stack_space(8)?;
                self.stack_offset -= 8;
                let spill_offset = self.stack_offset;
                self.emit_store(EbpfReg::R10, spill_offset, spill_reg, 8)?;
                self.instructions
                    .push(EbpfInsn::mov64_reg(spill_reg, rhs_reg_value));
                rhs_reg = Some(spill_reg);
                preserved_rhs_spill = Some((spill_reg, spill_offset));
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

        if let Some((spill_reg, spill_offset)) = preserved_rhs_spill {
            self.emit_load(spill_reg, EbpfReg::R10, spill_offset, 8)?;
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
                // Logical not: 0 -> 1, non-zero -> 0
                self.instructions.push(EbpfInsn::xor64_imm(dst_reg, 1));
                self.instructions.push(EbpfInsn::and64_imm(dst_reg, 1));
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
