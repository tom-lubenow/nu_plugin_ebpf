use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::ctx_field_schema::synthetic_bpf_flow_keys_type;
use crate::compiler::elf::CtxWriteTarget;
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::AddressSpace;
use crate::kernel_btf::TrampolineBitfieldInfo;

impl<'a> HirToMirLowering<'a> {
    pub(super) fn ctx_path_member_name(member: &PathMember) -> Result<String, CompileError> {
        match member {
            PathMember::String { val, .. } => Ok(val.clone()),
            PathMember::Int { val, .. } => Ok(format!("arg{}", val)),
        }
    }

    pub(super) fn resolve_ctx_field_from_path(
        &self,
        path: &CellPath,
    ) -> Result<(CtxField, usize), CompileError> {
        let field_name = Self::ctx_path_member_name(&path.members[0])?;
        if field_name == "arg" {
            let Some(arg_member) = path.members.get(1) else {
                return Err(CompileError::UnsupportedInstruction(
                    "ctx.arg.<name> requires a named BTF parameter".into(),
                ));
            };
            let PathMember::String { val: arg_name, .. } = arg_member else {
                return Err(CompileError::UnsupportedInstruction(
                    "ctx.arg.<name> requires a named BTF parameter".into(),
                ));
            };
            let Some(ctx) = self.probe_ctx else {
                return Err(CompileError::UnsupportedInstruction(
                    "ctx.arg.<name> is only available on kernel-BTF-backed contexts".into(),
                ));
            };
            let field = ctx
                .resolve_named_ctx_arg(arg_name)
                .map_err(CompileError::UnsupportedInstruction)?;
            return Ok((field, 2));
        }

        let field = match self.probe_ctx {
            Some(ctx) => ctx.resolve_ctx_field_name(&field_name),
            None => EbpfProgramType::resolve_untyped_ctx_field_name(&field_name),
        }
        .map_err(CompileError::UnsupportedInstruction)?;

        Ok((field, 1))
    }

    fn resolve_ctx_write_target_from_path(
        &self,
        path: &CellPath,
    ) -> Result<(CtxWriteTarget, Option<CtxField>), CompileError> {
        let path_desc = Self::typed_value_path_desc(&path.members);
        let Some(ctx) = self.probe_ctx else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires probe context",
                path_desc
            )));
        };
        let (field_name, index) = match path.members.as_slice() {
            [member] => (Self::ctx_path_member_name(member)?, None),
            [member, PathMember::Int { val: index, .. }] => {
                (Self::ctx_path_member_name(member)?, Some(*index))
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "context cell path update '.{} = ...' only supports a direct writable field or a fixed integer index",
                    path_desc
                )));
            }
        };

        ctx.resolve_ctx_write_target_with_context_field(&field_name, index)
            .map_err(CompileError::UnsupportedInstruction)
    }

    fn packet_ctx_store_root_from_path(
        &self,
        path: &CellPath,
    ) -> Result<Option<(CtxField, usize)>, CompileError> {
        let (field, index) = self.resolve_ctx_field_from_path(path)?;
        Ok(matches!(field, CtxField::Data | CtxField::DataMeta).then_some((field, index)))
    }

    fn flow_keys_ctx_store_root_from_path(
        &self,
        path: &CellPath,
    ) -> Result<Option<usize>, CompileError> {
        let (field, index) = self.resolve_ctx_field_from_path(path)?;
        Ok(matches!(field, CtxField::FlowKeys).then_some(index))
    }

    fn materialize_scalar_assignment_value(
        &mut self,
        new_value: RegId,
        target_ty: &MirType,
        path_desc: &str,
    ) -> Result<VReg, CompileError> {
        let new_value_vreg = self.get_vreg(new_value);
        let new_value_runtime_ty = self
            .typed_value_runtime_type(new_value, new_value_vreg)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "context cell path update '.{} = ...' requires type information for the new value",
                    path_desc
                ))
            })?;
        match new_value_runtime_ty {
            MirType::Bool
            | MirType::I8
            | MirType::U8
            | MirType::I16
            | MirType::U16
            | MirType::I32
            | MirType::U32
            | MirType::I64
            | MirType::U64 => {
                let widened = self.func.alloc_vreg();
                self.vreg_type_hints.insert(widened, target_ty.clone());
                self.emit(MirInst::Copy {
                    dst: widened,
                    src: MirValue::VReg(new_value_vreg),
                });
                Ok(widened)
            }
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires an integer-compatible scalar value",
                path_desc
            ))),
        }
    }

    fn resolve_packet_store_target(
        &mut self,
        base_vreg: VReg,
        path_members: &[PathMember],
        path_desc: &str,
    ) -> Result<(VReg, usize, MirType, bool, Option<TrampolineBitfieldInfo>), CompileError> {
        enum PacketStoreCursor {
            Pointer {
                base_vreg: VReg,
                base_offset: usize,
                target_ty: MirType,
                direct: bool,
            },
            Scalar {
                base_vreg: VReg,
                base_offset: usize,
                element_ty: MirType,
                element_size: usize,
                big_endian: bool,
            },
        }

        let mut cursor = PacketStoreCursor::Pointer {
            base_vreg,
            base_offset: 0,
            target_ty: MirType::U8,
            direct: true,
        };

        for (segment_idx, member) in path_members.iter().enumerate() {
            let is_last = segment_idx + 1 == path_members.len();

            if let PacketStoreCursor::Scalar {
                base_vreg,
                base_offset,
                element_ty,
                element_size,
                big_endian,
            } = &cursor
            {
                let packet_offset = match member {
                    PathMember::Int { val, .. } => {
                        let index = usize::try_from(*val).map_err(|_| {
                            CompileError::UnsupportedInstruction(format!(
                                "context cell path update '.{} = ...' requires a non-negative packet scalar index",
                                path_desc
                            ))
                        })?;
                        base_offset
                            .checked_add(index.checked_mul(*element_size).ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "context cell path update '.{} = ...' packet scalar index overflowed",
                                    path_desc
                                ))
                            })?)
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "context cell path update '.{} = ...' offset overflowed",
                                    path_desc
                                ))
                            })?
                    }
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "context cell path update '.{} = ...' expects a numeric index after a packet scalar view",
                            path_desc
                        )));
                    }
                };

                if !is_last {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "context cell path update '.{} = ...' does not support nested projection after a packet scalar index",
                        path_desc
                    )));
                }

                return Ok((
                    *base_vreg,
                    packet_offset,
                    element_ty.clone(),
                    *big_endian,
                    None,
                ));
            }

            let PacketStoreCursor::Pointer {
                base_vreg,
                base_offset,
                target_ty,
                direct,
            } = &cursor
            else {
                unreachable!();
            };

            if let Some(kind) = Self::packet_payload_step_kind(target_ty, member) {
                let payload_ptr_vreg =
                    self.emit_packet_payload_ptr_step(*base_vreg, *base_offset, kind, path_desc)?;
                if is_last {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "context cell path update '.{} = ...' requires a scalar packet field, not a payload pointer",
                        path_desc
                    )));
                }
                cursor = PacketStoreCursor::Pointer {
                    base_vreg: payload_ptr_vreg,
                    base_offset: 0,
                    target_ty: MirType::U8,
                    direct: true,
                };
                continue;
            }

            if let Some((payload_kind, view_ty)) =
                Self::packet_protocol_header_view_spec(target_ty, member)
            {
                let view_ptr_vreg = self.emit_packet_payload_ptr_step(
                    *base_vreg,
                    *base_offset,
                    payload_kind,
                    path_desc,
                )?;
                if is_last {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "context cell path update '.{} = ...' requires a scalar packet field, not a header view",
                        path_desc
                    )));
                }
                cursor = PacketStoreCursor::Pointer {
                    base_vreg: view_ptr_vreg,
                    base_offset: 0,
                    target_ty: view_ty,
                    direct: false,
                };
                continue;
            }

            if let Some(view) = Self::packet_header_view_spec(target_ty, member) {
                let view_offset = view.offset;
                let view_ty = view.ty;
                let field_offset = base_offset.checked_add(view_offset).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "context cell path update '.{} = ...' offset overflowed",
                        path_desc
                    ))
                })?;
                if is_last {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "context cell path update '.{} = ...' requires a scalar packet field, not a header view",
                        path_desc
                    )));
                }
                cursor = PacketStoreCursor::Pointer {
                    base_vreg: *base_vreg,
                    base_offset: field_offset,
                    target_ty: view_ty,
                    direct: false,
                };
                continue;
            }

            if matches!(target_ty, MirType::U8)
                && let Some((element_ty, element_size, big_endian)) =
                    Self::packet_scalar_view_spec(member)
            {
                if is_last {
                    return Ok((*base_vreg, *base_offset, element_ty, big_endian, None));
                }
                cursor = PacketStoreCursor::Scalar {
                    base_vreg: *base_vreg,
                    base_offset: *base_offset,
                    element_ty,
                    element_size,
                    big_endian,
                };
                continue;
            }

            let step = match (direct, member) {
                (true, PathMember::Int { val, .. })
                    if !matches!(target_ty, MirType::Array { .. }) =>
                {
                    Self::resolve_pointer_sequence_index_step(target_ty, *val, path_desc)?
                }
                _ => Self::resolve_typed_value_projection_step(target_ty, member, path_desc)?,
            };

            if step.bitfield.is_some() && !is_last {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "context cell path update '.{} = ...' cannot traverse through a packet bitfield",
                    path_desc
                )));
            }

            let field_offset = base_offset.checked_add(step.offset).ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "context cell path update '.{} = ...' offset overflowed",
                    path_desc
                ))
            })?;

            if is_last {
                if matches!(step.ty, MirType::Array { .. } | MirType::Struct { .. }) {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "context cell path update '.{} = ...' requires a scalar packet field, not {:?}",
                        path_desc, step.ty
                    )));
                }
                return Ok((
                    *base_vreg,
                    field_offset,
                    step.ty,
                    step.packet_big_endian,
                    step.bitfield,
                ));
            }

            cursor = PacketStoreCursor::Pointer {
                base_vreg: *base_vreg,
                base_offset: field_offset,
                target_ty: step.ty,
                direct: false,
            };
        }

        Err(CompileError::UnsupportedInstruction(format!(
            "context cell path update '.{} = ...' cannot target an empty packet path",
            path_desc
        )))
    }

    fn bitfield_store_masks(
        store_ty: &MirType,
        bitfield: TrampolineBitfieldInfo,
    ) -> Result<(u128, u128), CompileError> {
        let storage_bits = u32::try_from(store_ty.size().checked_mul(8).ok_or_else(|| {
            CompileError::UnsupportedInstruction("bitfield store size overflowed".to_string())
        })?)
        .map_err(|_| {
            CompileError::UnsupportedInstruction("bitfield store size overflowed".to_string())
        })?;
        if bitfield.bit_size == 0 || bitfield.bit_size > storage_bits {
            return Err(CompileError::UnsupportedInstruction(format!(
                "unsupported {}-bit bitfield store into {:?}",
                bitfield.bit_size, store_ty
            )));
        }
        let bitfield_end = bitfield
            .bit_offset
            .checked_add(bitfield.bit_size)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction("bitfield store overflowed".to_string())
            })?;
        if bitfield_end > storage_bits {
            return Err(CompileError::UnsupportedInstruction(format!(
                "bitfield store exceeds {:?} storage width",
                store_ty
            )));
        }

        let field_mask = 1u128
            .checked_shl(bitfield.bit_size)
            .and_then(|value| value.checked_sub(1))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction("bitfield store mask overflowed".to_string())
            })?;
        let shifted_field_mask = field_mask.checked_shl(bitfield.bit_offset).ok_or_else(|| {
            CompileError::UnsupportedInstruction("bitfield store mask overflowed".to_string())
        })?;
        let storage_mask = 1u128
            .checked_shl(storage_bits)
            .and_then(|value| value.checked_sub(1))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction("bitfield store mask overflowed".to_string())
            })?;
        let clear_mask = storage_mask ^ shifted_field_mask;
        Ok((field_mask, clear_mask))
    }

    fn emit_bitfield_merge_value(
        &mut self,
        current_vreg: VReg,
        new_value_vreg: VReg,
        store_ty: &MirType,
        bitfield: TrampolineBitfieldInfo,
    ) -> Result<VReg, CompileError> {
        let (field_mask, clear_mask) = Self::bitfield_store_masks(store_ty, bitfield)?;
        let masked_value_vreg = self.func.alloc_vreg();
        self.vreg_type_hints
            .insert(masked_value_vreg, store_ty.clone());
        let field_mask_value = self.large_const_operand(store_ty, field_mask as i64);
        self.emit(MirInst::BinOp {
            dst: masked_value_vreg,
            op: BinOpKind::And,
            lhs: MirValue::VReg(new_value_vreg),
            rhs: field_mask_value,
        });

        let shifted_value_vreg = if bitfield.bit_offset == 0 {
            masked_value_vreg
        } else {
            let shifted = self.func.alloc_vreg();
            self.vreg_type_hints.insert(shifted, store_ty.clone());
            let shift = self.large_const_operand(store_ty, i64::from(bitfield.bit_offset));
            self.emit(MirInst::BinOp {
                dst: shifted,
                op: BinOpKind::Shl,
                lhs: MirValue::VReg(masked_value_vreg),
                rhs: shift,
            });
            shifted
        };

        let cleared_current_vreg = self.func.alloc_vreg();
        self.vreg_type_hints
            .insert(cleared_current_vreg, store_ty.clone());
        let clear_mask_value = self.large_const_operand(store_ty, clear_mask as i64);
        self.emit(MirInst::BinOp {
            dst: cleared_current_vreg,
            op: BinOpKind::And,
            lhs: MirValue::VReg(current_vreg),
            rhs: clear_mask_value,
        });

        let merged_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(merged_vreg, store_ty.clone());
        self.emit(MirInst::BinOp {
            dst: merged_vreg,
            op: BinOpKind::Or,
            lhs: MirValue::VReg(cleared_current_vreg),
            rhs: MirValue::VReg(shifted_value_vreg),
        });

        Ok(merged_vreg)
    }

    fn emit_packet_bitfield_store_value(
        &mut self,
        packet_store_vreg: VReg,
        new_value_vreg: VReg,
        store_ty: &MirType,
        bitfield: TrampolineBitfieldInfo,
        packet_big_endian: bool,
        end_field: CtxField,
        path_desc: &str,
    ) -> Result<VReg, CompileError> {
        let current_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(current_vreg, store_ty.clone());
        self.emit_packet_guarded_load(
            current_vreg,
            packet_store_vreg,
            store_ty,
            end_field,
            path_desc,
        )?;
        if packet_big_endian {
            self.emit_packet_big_endian_scalar_normalize(current_vreg, store_ty)?;
        }

        let merged_vreg =
            self.emit_bitfield_merge_value(current_vreg, new_value_vreg, store_ty, bitfield)?;
        if packet_big_endian {
            self.emit_packet_big_endian_scalar_normalize(merged_vreg, store_ty)?;
        }

        Ok(merged_vreg)
    }

    pub(super) fn emit_scalar_bitfield_store(
        &mut self,
        base_vreg: VReg,
        offset: usize,
        store_ty: &MirType,
        bitfield: TrampolineBitfieldInfo,
        new_value_vreg: VReg,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        let offset = Self::trampoline_projection_offset_i32(offset, path_desc)?;

        let current_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(current_vreg, store_ty.clone());
        self.emit(MirInst::Load {
            dst: current_vreg,
            ptr: base_vreg,
            offset,
            ty: store_ty.clone(),
        });

        let merged_vreg =
            self.emit_bitfield_merge_value(current_vreg, new_value_vreg, store_ty, bitfield)?;
        self.emit(MirInst::Store {
            ptr: base_vreg,
            offset,
            val: MirValue::VReg(merged_vreg),
            ty: store_ty.clone(),
        });

        Ok(())
    }

    pub(super) fn lower_context_pointer_scalar_update(
        &mut self,
        base_vreg: VReg,
        pointee_ty: &MirType,
        path_members: &[PathMember],
        new_value: RegId,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        if path_members.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires a scalar field, not the root context pointer",
                path_desc
            )));
        }

        let projection =
            Self::resolve_typed_value_projection_path(pointee_ty, path_members, path_desc)?;
        if matches!(
            projection.ty,
            MirType::Array { .. } | MirType::Struct { .. }
        ) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires a scalar field, not {:?}",
                path_desc, projection.ty
            )));
        }

        let stored_vreg =
            self.materialize_scalar_assignment_value(new_value, &projection.ty, path_desc)?;
        if let Some(bitfield) = projection.bitfield {
            return self.emit_scalar_bitfield_store(
                base_vreg,
                projection.offset,
                &projection.ty,
                bitfield,
                stored_vreg,
                path_desc,
            );
        }
        self.emit(MirInst::Store {
            ptr: base_vreg,
            offset: Self::trampoline_projection_offset_i32(projection.offset, path_desc)?,
            val: MirValue::VReg(stored_vreg),
            ty: projection.ty,
        });
        Ok(())
    }

    fn lower_flow_keys_ctx_update(
        &mut self,
        src_dst: RegId,
        path_members: &[PathMember],
        new_value: RegId,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        let Some(ctx) = self.probe_ctx else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires probe context",
                path_desc
            )));
        };
        ctx.validate_load_ctx_field(&CtxField::FlowKeys)?;

        let flow_keys_ty = synthetic_bpf_flow_keys_type();
        let base_ty = MirType::Ptr {
            pointee: Box::new(flow_keys_ty.clone()),
            address_space: AddressSpace::Context,
        };
        let base_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(base_vreg, base_ty);
        self.emit(MirInst::LoadCtxField {
            dst: base_vreg,
            field: CtxField::FlowKeys,
            slot: None,
        });
        self.lower_context_pointer_scalar_update(
            base_vreg,
            &flow_keys_ty,
            path_members,
            new_value,
            path_desc,
        )?;

        self.implied_ctx_fields.insert(CtxField::FlowKeys);
        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = true;
        Ok(())
    }

    fn lower_packet_ctx_update(
        &mut self,
        src_dst: RegId,
        root_field: CtxField,
        path_members: &[PathMember],
        new_value: RegId,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        if path_members.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires a scalar packet field, not the root packet pointer",
                path_desc
            )));
        }

        let Some(ctx) = self.probe_ctx else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires probe context",
                path_desc
            )));
        };

        if !ctx.supports_direct_packet_writes() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' direct packet writes are not supported on {} programs",
                path_desc,
                ctx.canonical_prefix()
            )));
        }

        ctx.validate_load_ctx_field(&root_field)?;
        let end_field = Self::packet_guard_end_field(Some(&root_field));
        ctx.validate_load_ctx_field(&end_field)?;

        let packet_ptr_ty = MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        };
        let packet_root_vreg = self.func.alloc_vreg();
        self.vreg_type_hints
            .insert(packet_root_vreg, packet_ptr_ty.clone());
        self.emit(MirInst::LoadCtxField {
            dst: packet_root_vreg,
            field: root_field.clone(),
            slot: None,
        });

        self.lower_packet_ctx_update_from_ptr(
            packet_root_vreg,
            root_field,
            path_members,
            new_value,
            path_desc,
        )?;

        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = true;
        Ok(())
    }

    pub(super) fn lower_packet_ctx_update_from_ptr(
        &mut self,
        packet_root_vreg: VReg,
        root_field: CtxField,
        path_members: &[PathMember],
        new_value: RegId,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        if path_members.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires a scalar packet field, not the root packet pointer",
                path_desc
            )));
        }

        let Some(ctx) = self.probe_ctx else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires probe context",
                path_desc
            )));
        };

        if !ctx.supports_direct_packet_writes() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' direct packet writes are not supported on {} programs",
                path_desc,
                ctx.canonical_prefix()
            )));
        }

        ctx.validate_load_ctx_field(&root_field)?;
        let end_field = Self::packet_guard_end_field(Some(&root_field));
        ctx.validate_load_ctx_field(&end_field)?;

        let packet_ptr_ty = MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        };
        let (packet_base_vreg, packet_offset, store_ty, packet_big_endian, bitfield) =
            self.resolve_packet_store_target(packet_root_vreg, path_members, path_desc)?;
        let mut stored_vreg =
            self.materialize_scalar_assignment_value(new_value, &store_ty, path_desc)?;
        if packet_big_endian && bitfield.is_none() {
            let normalized_vreg = self.func.alloc_vreg();
            self.vreg_type_hints
                .insert(normalized_vreg, store_ty.clone());
            self.emit(MirInst::Copy {
                dst: normalized_vreg,
                src: MirValue::VReg(stored_vreg),
            });
            self.emit_packet_big_endian_scalar_normalize(normalized_vreg, &store_ty)?;
            stored_vreg = normalized_vreg;
        }

        let packet_store_vreg = if packet_offset == 0 {
            packet_base_vreg
        } else {
            let packet_store_vreg = self.func.alloc_vreg();
            self.vreg_type_hints
                .insert(packet_store_vreg, packet_ptr_ty.clone());
            self.emit(MirInst::BinOp {
                dst: packet_store_vreg,
                op: BinOpKind::Add,
                lhs: MirValue::VReg(packet_base_vreg),
                rhs: MirValue::Const(i64::from(Self::trampoline_projection_offset_i32(
                    packet_offset,
                    path_desc,
                )?)),
            });
            packet_store_vreg
        };

        if let Some(bitfield) = bitfield {
            stored_vreg = self.emit_packet_bitfield_store_value(
                packet_store_vreg,
                stored_vreg,
                &store_ty,
                bitfield,
                packet_big_endian,
                end_field.clone(),
                path_desc,
            )?;
        }

        self.emit_packet_guarded_store(
            packet_store_vreg,
            stored_vreg,
            &store_ty,
            end_field,
            path_desc,
        )?;
        Ok(())
    }

    pub(super) fn lower_context_upsert_cell_path(
        &mut self,
        src_dst: RegId,
        path: &CellPath,
        new_value: RegId,
    ) -> Result<(), CompileError> {
        let path_desc = Self::typed_value_path_desc(&path.members);
        if let Some((root_field, index)) = self.packet_ctx_store_root_from_path(path)? {
            return self.lower_packet_ctx_update(
                src_dst,
                root_field,
                &path.members[index..],
                new_value,
                &path_desc,
            );
        }
        if let Some(index) = self.flow_keys_ctx_store_root_from_path(path)? {
            return self.lower_flow_keys_ctx_update(
                src_dst,
                &path.members[index..],
                new_value,
                &path_desc,
            );
        }
        let (target, context_field) = self.resolve_ctx_write_target_from_path(path)?;
        if let Some(field) = context_field {
            self.implied_ctx_fields.insert(field);
        }
        match target {
            CtxWriteTarget::StoreField(target) => {
                let target_ty = target.value_type();
                let stored_vreg =
                    self.materialize_scalar_assignment_value(new_value, &target_ty, &path_desc)?;
                self.emit(MirInst::StoreCtxField {
                    target,
                    val: MirValue::VReg(stored_vreg),
                    ty: target_ty,
                });
            }
            CtxWriteTarget::SysctlNewValue => {
                self.lower_cgroup_sysctl_new_value_update(src_dst, new_value, &path_desc)?;
                return Ok(());
            }
            CtxWriteTarget::SockoptOptvalByte(index) => {
                self.lower_cgroup_sockopt_optval_byte_update(
                    src_dst, index, new_value, &path_desc,
                )?;
                return Ok(());
            }
            CtxWriteTarget::AssignSocket => {
                self.lower_socket_assignment_update(new_value, &path_desc)?;
                return Ok(());
            }
            CtxWriteTarget::CgroupSockAddrSunPath => {
                self.lower_cgroup_sock_addr_sun_path_update(src_dst, new_value, &path_desc)?;
                return Ok(());
            }
            CtxWriteTarget::ContextPointerScalarField(field) => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "ctx.{} assignment requires a writable scalar subfield, e.g. $ctx.{}.FIELD = ...",
                    field.display_name(),
                    field.display_name()
                )));
            }
        }
        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = true;
        Ok(())
    }

    fn lower_socket_assignment_update(
        &mut self,
        new_value: RegId,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        let Some(ctx) = self.probe_ctx else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires a known attached program context",
                path_desc
            )));
        };
        if let Some(message) = ctx.helper_call_error(BpfHelper::SkAssign) {
            return Err(CompileError::UnsupportedInstruction(message));
        }

        let sk_vreg = self.get_vreg(new_value);
        let ctx_vreg = self.materialize_context_pointer_arg();
        let status_vreg = self.func.alloc_vreg();
        self.emit(MirInst::CallHelper {
            dst: status_vreg,
            helper: BpfHelper::SkAssign as u32,
            args: vec![
                MirValue::VReg(ctx_vreg),
                MirValue::VReg(sk_vreg),
                MirValue::Const(0),
            ],
        });
        self.vreg_type_hints.insert(status_vreg, MirType::I64);
        Ok(())
    }

    fn materialize_value_arg_vreg(&mut self, value: MirValue, ty: MirType) -> VReg {
        match value {
            MirValue::VReg(vreg) => vreg,
            other => {
                let vreg = self.func.alloc_vreg();
                self.emit(MirInst::Copy {
                    dst: vreg,
                    src: other,
                });
                self.vreg_type_hints.insert(vreg, ty);
                vreg
            }
        }
    }

    fn sysctl_new_value_len_arg(
        &self,
        value_reg: RegId,
        buf_ty: &MirType,
        path_desc: &str,
    ) -> Result<MirValue, CompileError> {
        if let Some(meta) = self.get_metadata(value_reg) {
            if meta.literal_string.is_some()
                && let Some(bound) = meta.string_len_bound
            {
                return Ok(MirValue::Const(i64::try_from(bound).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "context cell path update '.{} = ...' string length is too large",
                        path_desc
                    ))
                })?));
            }
            if let Some(len_vreg) = meta.string_len_vreg {
                return Ok(MirValue::VReg(len_vreg));
            }
            if let Some(bound) = meta.string_len_bound {
                return Ok(MirValue::Const(i64::try_from(bound).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "context cell path update '.{} = ...' string length is too large",
                        path_desc
                    ))
                })?));
            }
        }

        let Some(len) = buf_ty.byte_array_len() else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires a string or byte-buffer value",
                path_desc
            )));
        };

        Ok(MirValue::Const(i64::try_from(len).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' byte-buffer length is too large",
                path_desc
            ))
        })?))
    }

    fn materialize_context_byte_buffer(
        &mut self,
        new_value: RegId,
        new_value_vreg: VReg,
        path_desc: &str,
        value_desc: &str,
    ) -> Result<(VReg, MirValue), CompileError> {
        let value_ty = self
            .typed_value_runtime_type(new_value, new_value_vreg)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "context cell path update '.{} = ...' requires type information for {}",
                    path_desc, value_desc
                ))
            })?;

        let (buf_vreg, buf_ty, ptr_hint) = match value_ty.clone() {
            MirType::Ptr {
                pointee,
                address_space: address_space @ (AddressSpace::Stack | AddressSpace::Map),
            } => (
                new_value_vreg,
                pointee.as_ref().clone(),
                Some(MirType::Ptr {
                    pointee,
                    address_space,
                }),
            ),
            MirType::Ptr { address_space, .. } => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "context cell path update '.{} = ...' requires a stack/map-backed string or byte-buffer value, got {address_space:?} pointer",
                    path_desc
                )));
            }
            value_ty @ MirType::Array { .. } => {
                let ptr_vreg =
                    self.materialized_metadata_aggregate_vreg(new_value, new_value_vreg)?;
                (
                    ptr_vreg,
                    value_ty.clone(),
                    Some(MirType::Ptr {
                        pointee: Box::new(value_ty),
                        address_space: AddressSpace::Stack,
                    }),
                )
            }
            other => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "context cell path update '.{} = ...' requires a string or binary byte-buffer value, got {:?}",
                    path_desc, other
                )));
            }
        };

        if buf_ty.byte_array_len().is_none() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires a string or binary byte-buffer value, got {:?}",
                path_desc, buf_ty
            )));
        }

        if let Some(ptr_hint) = ptr_hint {
            self.vreg_type_hints.entry(buf_vreg).or_insert(ptr_hint);
        }

        let len_arg = self.sysctl_new_value_len_arg(new_value, &buf_ty, path_desc)?;
        Ok((buf_vreg, len_arg))
    }

    fn lower_cgroup_sock_addr_sun_path_update(
        &mut self,
        src_dst: RegId,
        new_value: RegId,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        let Some(ctx) = self.probe_ctx else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires probe context",
                path_desc
            )));
        };
        if let Some(message) = ctx.kfunc_call_error("bpf_sock_addr_set_sun_path") {
            return Err(CompileError::UnsupportedInstruction(message));
        }

        let new_value_vreg = self.get_vreg(new_value);
        let (buf_vreg, len_arg) = self.materialize_context_byte_buffer(
            new_value,
            new_value_vreg,
            path_desc,
            "the new UNIX socket path",
        )?;
        if let MirValue::Const(len) = &len_arg {
            if *len <= 0 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "context cell path update '.{} = ...' requires a non-empty UNIX socket path",
                    path_desc
                )));
            }
            if *len > 108 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "context cell path update '.{} = ...' UNIX socket path is too long (max 108 bytes)",
                    path_desc
                )));
            }
        }

        let ctx_vreg = self.materialize_context_pointer_arg();
        let len_vreg = self.materialize_value_arg_vreg(len_arg, MirType::U32);
        let ret_vreg = self.func.alloc_vreg();
        self.emit(MirInst::CallKfunc {
            dst: ret_vreg,
            kfunc: "bpf_sock_addr_set_sun_path".to_string(),
            btf_id: None,
            args: vec![ctx_vreg, buf_vreg, len_vreg],
        });
        self.vreg_type_hints.insert(ret_vreg, MirType::I64);

        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = true;
        Ok(())
    }

    fn lower_cgroup_sysctl_new_value_update(
        &mut self,
        src_dst: RegId,
        new_value: RegId,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        let Some(ctx) = self.probe_ctx else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires probe context",
                path_desc
            )));
        };
        if let Some(message) = ctx.helper_call_error(BpfHelper::SysctlSetNewValue) {
            return Err(CompileError::UnsupportedInstruction(message));
        }

        let new_value_vreg = self.get_vreg(new_value);
        let (buf_vreg, len_arg) = self.materialize_context_byte_buffer(
            new_value,
            new_value_vreg,
            path_desc,
            "the new sysctl value",
        )?;
        let ctx_vreg = self.materialize_context_pointer_arg();
        let ret_vreg = self.func.alloc_vreg();
        self.emit(MirInst::CallHelper {
            dst: ret_vreg,
            helper: BpfHelper::SysctlSetNewValue as u32,
            args: vec![MirValue::VReg(ctx_vreg), MirValue::VReg(buf_vreg), len_arg],
        });
        self.vreg_type_hints.insert(ret_vreg, MirType::I64);

        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = true;
        Ok(())
    }

    fn lower_cgroup_sockopt_optval_byte_update(
        &mut self,
        src_dst: RegId,
        index: usize,
        new_value: RegId,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        let Some(ctx) = self.probe_ctx else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires probe context",
                path_desc
            )));
        };
        ctx.validate_load_ctx_field(&CtxField::SockoptOptval)?;
        ctx.validate_load_ctx_field(&CtxField::SockoptOptvalEnd)?;

        let ptr_ty = MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        };
        let optval_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(optval_vreg, ptr_ty.clone());
        self.emit(MirInst::LoadCtxField {
            dst: optval_vreg,
            field: CtxField::SockoptOptval,
            slot: None,
        });

        self.lower_cgroup_sockopt_optval_byte_update_from_ptr(
            optval_vreg,
            index,
            new_value,
            path_desc,
        )?;

        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = true;
        Ok(())
    }

    pub(super) fn lower_cgroup_sockopt_optval_byte_update_from_ptr(
        &mut self,
        optval_vreg: VReg,
        index: usize,
        new_value: RegId,
        path_desc: &str,
    ) -> Result<(), CompileError> {
        let Some(ctx) = self.probe_ctx else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' requires probe context",
                path_desc
            )));
        };
        ctx.validate_load_ctx_field(&CtxField::SockoptOptvalEnd)?;

        let stored_vreg =
            self.materialize_scalar_assignment_value(new_value, &MirType::U8, path_desc)?;

        let ptr_ty = MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        };
        let join_block = self.func.alloc_block();
        let guard_block = self.func.alloc_block();
        let store_block = self.func.alloc_block();

        let non_null_cond_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: non_null_cond_vreg,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(optval_vreg),
            rhs: MirValue::Const(0),
        });
        self.terminate(MirInst::Branch {
            cond: non_null_cond_vreg,
            if_true: guard_block,
            if_false: join_block,
        });

        self.current_block = guard_block;
        let byte_ptr_vreg = if index == 0 {
            optval_vreg
        } else {
            let byte_ptr_vreg = self.func.alloc_vreg();
            self.vreg_type_hints.insert(byte_ptr_vreg, ptr_ty.clone());
            self.emit(MirInst::BinOp {
                dst: byte_ptr_vreg,
                op: BinOpKind::Add,
                lhs: MirValue::VReg(optval_vreg),
                rhs: MirValue::Const(i64::try_from(index).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "context cell path update '.{} = ...' index is too large",
                        path_desc
                    ))
                })?),
            });
            byte_ptr_vreg
        };

        let optval_end_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(optval_end_vreg, ptr_ty.clone());
        self.emit(MirInst::LoadCtxField {
            dst: optval_end_vreg,
            field: CtxField::SockoptOptvalEnd,
            slot: None,
        });

        let access_end_vreg = self.func.alloc_vreg();
        self.vreg_type_hints.insert(access_end_vreg, ptr_ty);
        self.emit(MirInst::BinOp {
            dst: access_end_vreg,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(byte_ptr_vreg),
            rhs: MirValue::Const(1),
        });

        let cond_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: cond_vreg,
            op: BinOpKind::Le,
            lhs: MirValue::VReg(access_end_vreg),
            rhs: MirValue::VReg(optval_end_vreg),
        });
        self.terminate(MirInst::Branch {
            cond: cond_vreg,
            if_true: store_block,
            if_false: join_block,
        });

        self.current_block = store_block;
        self.emit(MirInst::Store {
            ptr: byte_ptr_vreg,
            offset: 0,
            val: MirValue::VReg(stored_vreg),
            ty: MirType::U8,
        });
        self.terminate(MirInst::Jump { target: join_block });

        self.current_block = join_block;
        Ok(())
    }
}
