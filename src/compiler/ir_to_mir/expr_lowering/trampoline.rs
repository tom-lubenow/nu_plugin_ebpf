use super::*;

#[derive(Debug, Clone)]
pub(in crate::compiler::ir_to_mir) struct TypedProjectionStep {
    pub(in crate::compiler::ir_to_mir) offset: usize,
    pub(in crate::compiler::ir_to_mir) ty: MirType,
    pub(in crate::compiler::ir_to_mir) bitfield: Option<TrampolineBitfieldInfo>,
    pub(in crate::compiler::ir_to_mir) packet_big_endian: bool,
}

impl<'a> HirToMirLowering<'a> {
    pub(in crate::compiler::ir_to_mir) fn trampoline_field_selector(
        member: &PathMember,
    ) -> Result<TrampolineFieldSelector, CompileError> {
        match member {
            PathMember::String { val, .. } => Ok(TrampolineFieldSelector::Field(val.clone())),
            PathMember::Int { val, .. } => usize::try_from(*val)
                .map(TrampolineFieldSelector::Index)
                .map_err(|_| {
                    CompileError::UnsupportedInstruction(
                        "trampoline array indexing requires a non-negative integer".into(),
                    )
                }),
        }
    }

    pub(in crate::compiler::ir_to_mir) fn trampoline_field_path_desc(
        path: &[TrampolineFieldSelector],
    ) -> String {
        let mut out = String::new();
        for (idx, segment) in path.iter().enumerate() {
            if idx > 0 {
                out.push('.');
            }
            match segment {
                TrampolineFieldSelector::Field(name) => out.push_str(name),
                TrampolineFieldSelector::Index(index) => out.push_str(&index.to_string()),
            }
        }
        out
    }

    pub(in crate::compiler::ir_to_mir) fn trampoline_value_spec(
        &self,
        field: &CtxField,
    ) -> Result<Option<TrampolineValueSpec>, CompileError> {
        match (self.probe_ctx, field) {
            (Some(ctx), CtxField::Arg(idx)) if ctx.probe_type.uses_btf_trampoline() => {
                let spec = ctx
                    .btf_arg_spec(*idx as usize)
                    .map_err(CompileError::UnsupportedInstruction)?
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            ctx.btf_arg_unavailable_error(*idx as usize),
                        )
                    })?;
                Ok(Some(spec))
            }
            (Some(ctx), CtxField::RetVal)
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
                Ok(Some(spec))
            }
            _ => Ok(None),
        }
    }

    pub(in crate::compiler::ir_to_mir) fn projected_trampoline_field_type(
        type_info: &TypeInfo,
    ) -> Option<MirType> {
        match type_info {
            TypeInfo::Int { size, signed } => Some(match (*size, *signed) {
                (1, false) => MirType::U8,
                (1, true) => MirType::I8,
                (2, false) => MirType::U16,
                (2, true) => MirType::I16,
                (4, false) => MirType::U32,
                (4, true) => MirType::I32,
                (8, false) => MirType::U64,
                (8, true) => MirType::I64,
                _ => return None,
            }),
            TypeInfo::Ptr {
                target, is_user, ..
            } => Some(MirType::Ptr {
                pointee: Box::new(
                    Self::projected_trampoline_field_type(target).unwrap_or(MirType::U8),
                ),
                address_space: if *is_user {
                    AddressSpace::User
                } else {
                    AddressSpace::Kernel
                },
            }),
            TypeInfo::Array { element, len } => {
                if *len == 0 {
                    return None;
                }
                let elem_ty = Self::projected_trampoline_field_type(element)?;
                Some(MirType::Array {
                    elem: Box::new(elem_ty),
                    len: *len,
                })
            }
            TypeInfo::Struct {
                name,
                btf_type_id,
                size,
                fields,
            } => {
                if *size == 0 {
                    return None;
                }
                if fields.is_empty() {
                    return Self::opaque_trampoline_struct_type(name, *size, *btf_type_id);
                }

                let mut mir_fields = Vec::with_capacity(fields.len() + 1);
                let mut cursor = 0usize;
                let mut pad_index = 0usize;
                for field in fields {
                    if field.size == 0 || field.offset >= *size {
                        continue;
                    }
                    if field.offset < cursor && field.bitfield.is_none() {
                        continue;
                    }
                    if field.offset > cursor {
                        mir_fields.push(Self::synthetic_padding_field(
                            cursor,
                            field.offset - cursor,
                            pad_index,
                        )?);
                        pad_index += 1;
                    }

                    let Some(field_ty) = Self::projected_trampoline_field_type(&field.type_info)
                        .or_else(|| Self::trampoline_byte_array_type(field.size))
                        .filter(|ty| ty.size() == field.size)
                        .or_else(|| Self::trampoline_byte_array_type(field.size))
                    else {
                        continue;
                    };
                    let Some(field_end) = field.offset.checked_add(field.size) else {
                        continue;
                    };
                    if field_end > *size {
                        continue;
                    }
                    mir_fields.push(crate::compiler::mir::StructField {
                        name: field.name.clone(),
                        ty: field_ty,
                        offset: field.offset,
                        synthetic: false,
                        bitfield: field.bitfield.map(|bitfield| {
                            crate::compiler::mir::BitfieldInfo {
                                bit_offset: bitfield.bit_offset,
                                bit_size: bitfield.bit_size,
                            }
                        }),
                    });
                    cursor = cursor.max(field_end);
                }
                if mir_fields.is_empty() {
                    return Self::opaque_trampoline_struct_type(name, *size, *btf_type_id);
                }
                if cursor < *size {
                    mir_fields.push(Self::synthetic_padding_field(
                        cursor,
                        *size - cursor,
                        pad_index,
                    )?);
                }

                Some(MirType::Struct {
                    name: Some(name.clone()),
                    kernel_btf_type_id: *btf_type_id,
                    fields: mir_fields,
                })
            }
            _ => None,
        }
    }

    pub(in crate::compiler::ir_to_mir) fn emit_bitfield_extract(
        &mut self,
        dst_vreg: VReg,
        loaded_vreg: VReg,
        projected_ty: &MirType,
        bitfield: TrampolineBitfieldInfo,
    ) -> Result<(), CompileError> {
        let storage_bits = u32::try_from(projected_ty.size().checked_mul(8).ok_or_else(|| {
            CompileError::UnsupportedInstruction("bitfield extraction size overflowed".to_string())
        })?)
        .map_err(|_| {
            CompileError::UnsupportedInstruction("bitfield extraction size overflowed".to_string())
        })?;
        if bitfield.bit_size == 0 || bitfield.bit_size > storage_bits {
            return Err(CompileError::UnsupportedInstruction(format!(
                "unsupported {}-bit bitfield extraction from {:?}",
                bitfield.bit_size, projected_ty
            )));
        }
        let bitfield_end = bitfield
            .bit_offset
            .checked_add(bitfield.bit_size)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction("bitfield extraction overflowed".to_string())
            })?;
        if bitfield_end > storage_bits {
            return Err(CompileError::UnsupportedInstruction(format!(
                "bitfield extraction exceeds {:?} storage width",
                projected_ty
            )));
        }

        let mut current_vreg = loaded_vreg;
        if bitfield.bit_offset > 0 {
            let shifted_vreg = self.func.alloc_vreg();
            self.vreg_type_hints
                .insert(shifted_vreg, projected_ty.clone());
            let shift_amount =
                self.large_const_operand(projected_ty, i64::from(bitfield.bit_offset));
            self.emit(MirInst::BinOp {
                dst: shifted_vreg,
                op: BinOpKind::Shr,
                lhs: MirValue::VReg(current_vreg),
                rhs: shift_amount,
            });
            current_vreg = shifted_vreg;
        }

        if bitfield.bit_size < storage_bits {
            let masked_vreg = self.func.alloc_vreg();
            self.vreg_type_hints
                .insert(masked_vreg, projected_ty.clone());
            let mask = ((1u128 << bitfield.bit_size) - 1) as i64;
            let mask_value = self.large_const_operand(projected_ty, mask);
            self.emit(MirInst::BinOp {
                dst: masked_vreg,
                op: BinOpKind::And,
                lhs: MirValue::VReg(current_vreg),
                rhs: mask_value,
            });
            current_vreg = masked_vreg;
        }

        if Self::mir_type_is_signed(projected_ty) && bitfield.bit_size < storage_bits {
            let sign_bit = 1i64.checked_shl(bitfield.bit_size - 1).ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "bitfield sign extension overflowed".to_string(),
                )
            })?;
            let xor_vreg = self.func.alloc_vreg();
            self.vreg_type_hints.insert(xor_vreg, projected_ty.clone());
            let sign_bit_value = self.large_const_operand(projected_ty, sign_bit);
            self.emit(MirInst::BinOp {
                dst: xor_vreg,
                op: BinOpKind::Xor,
                lhs: MirValue::VReg(current_vreg),
                rhs: sign_bit_value,
            });

            let signed_vreg = self.func.alloc_vreg();
            self.vreg_type_hints
                .insert(signed_vreg, projected_ty.clone());
            let sign_bit_value = self.large_const_operand(projected_ty, sign_bit);
            self.emit(MirInst::BinOp {
                dst: signed_vreg,
                op: BinOpKind::Sub,
                lhs: MirValue::VReg(xor_vreg),
                rhs: sign_bit_value,
            });
            current_vreg = signed_vreg;
        }

        self.vreg_type_hints.insert(dst_vreg, projected_ty.clone());
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::VReg(current_vreg),
        });
        Ok(())
    }

    pub(in crate::compiler::ir_to_mir) fn trampoline_root_type_info(
        &self,
        field: &CtxField,
    ) -> Result<Option<TypeInfo>, CompileError> {
        match field {
            CtxField::Arg(_) | CtxField::RetVal => self.probe_ctx.map_or(Ok(None), |ctx| {
                ctx.ctx_field_type_info(field)
                    .map_err(CompileError::UnsupportedInstruction)
            }),
            _ => Ok(None),
        }
    }

    pub(in crate::compiler::ir_to_mir) fn root_trampoline_value_types(
        type_info: &TypeInfo,
        kind: TrampolineValueKind,
    ) -> Option<(MirType, MirType)> {
        match kind {
            TrampolineValueKind::Scalar => {
                let ty = Self::projected_trampoline_field_type(type_info).unwrap_or(MirType::I64);
                Some((ty.clone(), ty))
            }
            TrampolineValueKind::Pointer { user_space } => {
                let address_space = if user_space {
                    AddressSpace::User
                } else {
                    AddressSpace::Kernel
                };
                let runtime_ty = Self::projected_trampoline_field_type(type_info)
                    .unwrap_or_else(|| Self::trampoline_pointer_type(address_space));
                Some((runtime_ty.clone(), runtime_ty))
            }
            TrampolineValueKind::Aggregate { size_bytes } => {
                let semantic_ty = Self::projected_trampoline_field_type(type_info)
                    .or_else(|| Self::trampoline_byte_array_type(size_bytes))?;
                let runtime_ty = MirType::Ptr {
                    pointee: Box::new(semantic_ty.clone()),
                    address_space: AddressSpace::Stack,
                };
                Some((semantic_ty, runtime_ty))
            }
        }
    }

    fn trampoline_byte_array_type(size: usize) -> Option<MirType> {
        if size == 0 {
            return None;
        }
        Some(MirType::Array {
            elem: Box::new(MirType::U8),
            len: size,
        })
    }

    fn opaque_trampoline_struct_type(
        name: &str,
        size: usize,
        kernel_btf_type_id: Option<u32>,
    ) -> Option<MirType> {
        Some(MirType::Struct {
            name: Some(name.to_string()),
            kernel_btf_type_id,
            fields: vec![crate::compiler::mir::StructField {
                name: "__opaque".to_string(),
                ty: Self::trampoline_byte_array_type(size)?,
                offset: 0,
                synthetic: false,
                bitfield: None,
            }],
        })
    }

    fn synthetic_padding_field(
        offset: usize,
        size: usize,
        pad_index: usize,
    ) -> Option<crate::compiler::mir::StructField> {
        Some(crate::compiler::mir::StructField {
            name: format!("__layout_pad{}", pad_index),
            ty: Self::trampoline_byte_array_type(size)?,
            offset,
            synthetic: true,
            bitfield: None,
        })
    }

    pub(in crate::compiler::ir_to_mir) fn trampoline_pointer_type(
        address_space: AddressSpace,
    ) -> MirType {
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space,
        }
    }

    fn scalar_mir_type_for_size(size: usize) -> Result<MirType, CompileError> {
        Ok(match size {
            1 => MirType::U8,
            2 => MirType::U16,
            4 => MirType::U32,
            8 => MirType::U64,
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "unsupported stack scalar width {}",
                    size
                )));
            }
        })
    }

    fn largest_aligned_stack_chunk(remaining: usize, offsets: &[usize]) -> usize {
        for chunk in [8usize, 4, 2, 1] {
            if remaining >= chunk && offsets.iter().all(|offset| offset % chunk == 0) {
                return chunk;
            }
        }
        1
    }

    fn emit_zero_stack_slot_bytes(
        &mut self,
        slot: StackSlotId,
        size: usize,
    ) -> Result<(), CompileError> {
        let mut written = 0usize;
        while written < size {
            let chunk = Self::largest_aligned_stack_chunk(size - written, &[written]);
            let ty = Self::scalar_mir_type_for_size(chunk)?;
            let offset = i32::try_from(written).map_err(|_| {
                CompileError::UnsupportedInstruction(format!(
                    "stack slot zero offset {} is too large",
                    written
                ))
            })?;
            self.emit(MirInst::StoreSlot {
                slot,
                offset,
                val: MirValue::Const(0),
                ty,
            });
            written += chunk;
        }
        Ok(())
    }

    pub(in crate::compiler::ir_to_mir) fn trampoline_projection_offset_i32(
        offset_bytes: usize,
        path_desc: &str,
    ) -> Result<i32, CompileError> {
        i32::try_from(offset_bytes).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "projected trampoline field '{}' offset is too large",
                path_desc
            ))
        })
    }

    pub(in crate::compiler::ir_to_mir) fn emit_trampoline_probe_read_to_slot(
        &mut self,
        ptr_vreg: VReg,
        address_space: AddressSpace,
        read_offset_bytes: usize,
        slot: StackSlotId,
        slot_ty: &MirType,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        let helper = match address_space {
            AddressSpace::Kernel => BpfHelper::ProbeReadKernel as u32,
            AddressSpace::User => BpfHelper::ProbeReadUser as u32,
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "unsupported trampoline pointer address space for '{}': {:?}",
                    path_desc, address_space
                )));
            }
        };

        self.emit_zero_stack_slot_bytes(slot, slot_ty.size())?;

        let cond_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: cond_vreg,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(ptr_vreg),
            rhs: MirValue::Const(0),
        });

        let read_block = self.func.alloc_block();
        let join_block = self.func.alloc_block();
        self.terminate(MirInst::Branch {
            cond: cond_vreg,
            if_true: read_block,
            if_false: join_block,
        });

        self.current_block = read_block;
        let src_ptr_vreg = if read_offset_bytes == 0 {
            ptr_vreg
        } else {
            let ptr_ty = self
                .vreg_type_hints
                .get(&ptr_vreg)
                .cloned()
                .unwrap_or_else(|| Self::trampoline_pointer_type(address_space));
            let field_ptr_vreg = self.func.alloc_vreg();
            self.vreg_type_hints.insert(field_ptr_vreg, ptr_ty.clone());
            let field_offset = i64::from(Self::trampoline_projection_offset_i32(
                read_offset_bytes,
                path_desc,
            )?);
            self.emit(MirInst::BinOp {
                dst: field_ptr_vreg,
                op: BinOpKind::Add,
                lhs: MirValue::VReg(ptr_vreg),
                rhs: MirValue::Const(field_offset),
            });
            field_ptr_vreg
        };

        let read_status_vreg = self.func.alloc_vreg();
        self.emit(MirInst::CallHelper {
            dst: read_status_vreg,
            helper,
            args: vec![
                MirValue::StackSlot(slot),
                MirValue::Const(slot_ty.size() as i64),
                MirValue::VReg(src_ptr_vreg),
            ],
        });
        self.terminate(MirInst::Jump { target: join_block });
        self.current_block = join_block;

        Ok(())
    }
}
