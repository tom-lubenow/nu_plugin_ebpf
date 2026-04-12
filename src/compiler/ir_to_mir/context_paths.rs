use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::elf::CtxWriteTarget;
use crate::compiler::mir::AddressSpace;

impl<'a> HirToMirLowering<'a> {
    fn ctx_path_member_name(member: &PathMember) -> Result<String, CompileError> {
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
    ) -> Result<CtxWriteTarget, CompileError> {
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

        ctx.resolve_ctx_write_target(&field_name, index, &path_desc)
            .map_err(CompileError::UnsupportedInstruction)
    }

    fn packet_ctx_store_root_from_path(
        &self,
        path: &CellPath,
    ) -> Result<Option<(CtxField, usize)>, CompileError> {
        let (field, index) = self.resolve_ctx_field_from_path(path)?;
        Ok(matches!(field, CtxField::Data | CtxField::DataMeta).then_some((field, index)))
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
    ) -> Result<(VReg, usize, MirType, bool), CompileError> {
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

                return Ok((*base_vreg, packet_offset, element_ty.clone(), *big_endian));
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
                    return Ok((*base_vreg, *base_offset, element_ty, big_endian));
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

            if step.bitfield.is_some() {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "context cell path update '.{} = ...' does not support packet bitfield stores",
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
                return Ok((*base_vreg, field_offset, step.ty, step.packet_big_endian));
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

        if !ctx.probe_type.supports_direct_packet_writes() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "context cell path update '.{} = ...' direct packet writes are not supported on {} programs",
                path_desc,
                ctx.probe_type.canonical_prefix()
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
            field: root_field,
            slot: None,
        });

        let (packet_base_vreg, packet_offset, store_ty, packet_big_endian) =
            self.resolve_packet_store_target(packet_root_vreg, path_members, path_desc)?;
        let mut stored_vreg =
            self.materialize_scalar_assignment_value(new_value, &store_ty, path_desc)?;
        if packet_big_endian {
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

        self.emit_packet_guarded_store(
            packet_store_vreg,
            stored_vreg,
            &store_ty,
            end_field,
            path_desc,
        )?;

        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = true;
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
        match self.resolve_ctx_write_target_from_path(path)? {
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
            CtxWriteTarget::SockoptOptvalByte(index) => {
                self.lower_cgroup_sockopt_optval_byte_update(
                    src_dst, index, new_value, &path_desc,
                )?;
                return Ok(());
            }
        }
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

        let stored_vreg =
            self.materialize_scalar_assignment_value(new_value, &MirType::U8, &path_desc)?;

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
        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = true;
        Ok(())
    }
}
