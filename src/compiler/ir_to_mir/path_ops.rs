use super::*;
use crate::compiler::mir::AddressSpace;
use crate::kernel_btf::{TrampolineFieldSelector, TrampolineValueKind, TypeInfo};

impl<'a> HirToMirLowering<'a> {
    fn tracepoint_root_field_types(
        &self,
        name: &str,
    ) -> Result<Option<(MirType, MirType)>, CompileError> {
        let Some(ctx) = self.probe_ctx else {
            return Ok(None);
        };
        let Some(type_info) = ctx
            .ctx_field_type_info(&CtxField::TracepointField(name.to_string()))
            .ok()
            .flatten()
        else {
            return Ok(None);
        };

        let types = match &type_info {
            TypeInfo::Struct { .. } | TypeInfo::Array { .. } => {
                let Some(semantic_ty) =
                    Self::projected_trampoline_field_type(&type_info).or_else(|| {
                        (type_info.size() > 0).then(|| MirType::Array {
                            elem: Box::new(MirType::U8),
                            len: type_info.size(),
                        })
                    })
                else {
                    return Ok(None);
                };
                let runtime_ty = MirType::Ptr {
                    pointee: Box::new(semantic_ty.clone()),
                    address_space: AddressSpace::Stack,
                };
                Some((semantic_ty, runtime_ty))
            }
            _ => {
                let ty = Self::projected_trampoline_field_type(&type_info).unwrap_or(MirType::I64);
                Some((ty.clone(), ty))
            }
        };
        Ok(types)
    }

    pub(super) fn lower_dynamic_typed_numeric_get(
        &mut self,
        dst_reg: RegId,
        base_vreg: VReg,
        base_runtime_ty: &MirType,
        idx: MirValue,
        root_ctx_field: Option<&CtxField>,
    ) -> Result<MirType, CompileError> {
        let dst_vreg = self.get_vreg(dst_reg);
        let path_desc = match &idx {
            MirValue::Const(value) => format!("get {}", value),
            _ => "get <dynamic-index>".to_string(),
        };

        let MirType::Ptr {
            pointee,
            address_space,
        } = base_runtime_ty
        else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "numeric get requires a typed pointer value, got {:?}",
                base_runtime_ty
            )));
        };

        let (element_ty, element_size) = match pointee.as_ref() {
            MirType::Array { elem, .. } => (elem.as_ref().clone(), elem.size()),
            other => (other.clone(), other.size()),
        };

        let base_copy = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: base_copy,
            src: MirValue::VReg(base_vreg),
        });
        self.vreg_type_hints
            .insert(base_copy, base_runtime_ty.clone());

        let scaled_idx = if element_size == 1 {
            idx.clone()
        } else {
            match idx {
                MirValue::Const(value) => {
                    let scaled = value
                        .checked_mul(i64::try_from(element_size).map_err(|_| {
                            CompileError::UnsupportedInstruction(format!(
                                "numeric get element size {} is too large",
                                element_size
                            ))
                        })?)
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "numeric get index overflowed".into(),
                            )
                        })?;
                    MirValue::Const(scaled)
                }
                MirValue::VReg(idx_vreg) => {
                    let scaled_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::BinOp {
                        dst: scaled_vreg,
                        op: BinOpKind::Mul,
                        lhs: MirValue::VReg(idx_vreg),
                        rhs: MirValue::Const(i64::try_from(element_size).map_err(|_| {
                            CompileError::UnsupportedInstruction(format!(
                                "numeric get element size {} is too large",
                                element_size
                            ))
                        })?),
                    });
                    MirValue::VReg(scaled_vreg)
                }
                MirValue::StackSlot(_) => {
                    return Err(CompileError::UnsupportedInstruction(
                        "numeric get does not support stack-slot indices".into(),
                    ));
                }
            }
        };

        let element_ptr_vreg = self.func.alloc_vreg();
        let element_ptr_ty = MirType::Ptr {
            pointee: Box::new(element_ty.clone()),
            address_space: *address_space,
        };
        self.vreg_type_hints
            .insert(element_ptr_vreg, element_ptr_ty.clone());
        self.emit(MirInst::BinOp {
            dst: element_ptr_vreg,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(base_copy),
            rhs: scaled_idx,
        });

        match address_space {
            AddressSpace::Kernel | AddressSpace::User => {
                if *address_space == AddressSpace::Kernel
                    && let Some(end_field) = root_ctx_field.and_then(CtxField::bounded_end_field)
                {
                    if matches!(element_ty, MirType::Array { .. } | MirType::Struct { .. }) {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "numeric get on bounded context buffers currently supports only scalar elements, got {:?}",
                            element_ty
                        )));
                    }
                    self.emit_context_buffer_guarded_load(
                        dst_vreg,
                        element_ptr_vreg,
                        0,
                        &element_ty,
                        end_field,
                        &path_desc,
                    )?;
                } else if matches!(element_ty, MirType::Array { .. } | MirType::Struct { .. }) {
                    let projected_slot = self.func.alloc_stack_slot(
                        align_to_eight(element_ty.size()),
                        8,
                        StackSlotKind::Local,
                    );
                    self.record_stack_slot_type(projected_slot, element_ty.clone());
                    self.emit_trampoline_probe_read_to_slot(
                        element_ptr_vreg,
                        *address_space,
                        0,
                        projected_slot,
                        &element_ty,
                        &path_desc,
                    )?;
                    self.vreg_type_hints.insert(
                        dst_vreg,
                        MirType::Ptr {
                            pointee: Box::new(element_ty.clone()),
                            address_space: AddressSpace::Stack,
                        },
                    );
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::StackSlot(projected_slot),
                    });
                } else {
                    let projected_slot = self.func.alloc_stack_slot(
                        align_to_eight(element_ty.size()),
                        8,
                        StackSlotKind::Local,
                    );
                    self.record_stack_slot_type(projected_slot, element_ty.clone());
                    self.emit_trampoline_probe_read_to_slot(
                        element_ptr_vreg,
                        *address_space,
                        0,
                        projected_slot,
                        &element_ty,
                        &path_desc,
                    )?;
                    self.vreg_type_hints.insert(dst_vreg, element_ty.clone());
                    self.emit(MirInst::LoadSlot {
                        dst: dst_vreg,
                        slot: projected_slot,
                        offset: 0,
                        ty: element_ty.clone(),
                    });
                }
            }
            AddressSpace::Packet => {
                if matches!(element_ty, MirType::Array { .. } | MirType::Struct { .. }) {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "numeric get on xdp packet data currently supports only scalar elements, got {:?}",
                        element_ty
                    )));
                }
                self.emit_packet_guarded_load(
                    dst_vreg,
                    element_ptr_vreg,
                    &element_ty,
                    root_ctx_field
                        .and_then(CtxField::bounded_end_field)
                        .unwrap_or(CtxField::DataEnd),
                    &path_desc,
                )?;
            }
            AddressSpace::Stack | AddressSpace::Map => {
                if matches!(element_ty, MirType::Array { .. } | MirType::Struct { .. }) {
                    self.vreg_type_hints.insert(
                        dst_vreg,
                        MirType::Ptr {
                            pointee: Box::new(element_ty.clone()),
                            address_space: *address_space,
                        },
                    );
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(element_ptr_vreg),
                    });
                } else {
                    self.vreg_type_hints.insert(dst_vreg, element_ty.clone());
                    self.emit(MirInst::Load {
                        dst: dst_vreg,
                        ptr: element_ptr_vreg,
                        offset: 0,
                        ty: element_ty.clone(),
                    });
                }
            }
        }

        let meta = self.get_or_create_metadata(dst_reg);
        meta.is_context = false;
        meta.field_type = Some(element_ty.clone());
        meta.root_ctx_field = root_ctx_field.cloned();

        Ok(element_ty)
    }

    /// Lower FollowCellPath instruction (context field access like $ctx.pid)
    pub(super) fn lower_follow_cell_path(
        &mut self,
        src_dst: RegId,
        path_reg: RegId,
    ) -> Result<(), CompileError> {
        let path = self
            .get_metadata(path_reg)
            .and_then(|m| m.cell_path.clone())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction("Cell path literal not found".into())
            })?;
        if path.members.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "Empty cell path is not supported".into(),
            ));
        }

        let dst_vreg = self.get_vreg(src_dst);

        if !self.is_context_reg(src_dst) {
            let path_desc = Self::typed_value_path_desc(&path.members);
            let base_runtime_ty = self
                .typed_value_runtime_type(src_dst, dst_vreg)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "typed field path '{}' requires type information for the base value",
                        path_desc
                    ))
                })?;
            let base_vreg = self.func.alloc_vreg();
            self.emit(MirInst::Copy {
                dst: base_vreg,
                src: MirValue::VReg(dst_vreg),
            });
            let projected_semantics = self
                .get_metadata(src_dst)
                .and_then(|m| m.annotated_semantics.clone())
                .and_then(|semantics| {
                    Self::project_annotated_value_semantics(&semantics, &path.members)
                });
            self.vreg_type_hints.insert(
                base_vreg,
                self.vreg_type_hints
                    .get(&dst_vreg)
                    .cloned()
                    .unwrap_or_else(|| base_runtime_ty.clone()),
            );
            let projected_ty = self.lower_typed_value_projection(
                src_dst,
                dst_vreg,
                base_vreg,
                &base_runtime_ty,
                &path.members,
                &path_desc,
                None,
                projected_semantics.as_ref(),
            )?;
            let meta = self.get_or_create_metadata(src_dst);
            meta.is_context = false;
            meta.field_type = Some(projected_ty);
            meta.root_ctx_field = None;
            meta.annotated_semantics = projected_semantics;
            meta.source_var = None;
            return Ok(());
        }

        let (ctx_field, root_members_consumed) = self.resolve_ctx_field_from_path(&path)?;
        let remaining_members = &path.members[root_members_consumed..];
        if let Some(ctx) = self.probe_ctx {
            ctx.validate_ctx_field_access(&ctx_field)?;
        }
        let trampoline_value_spec = self.trampoline_value_spec(&ctx_field)?;
        let ctx_projection_spec =
            ProbeContext::resolve_ctx_field_projection_spec(self.probe_ctx, &ctx_field);

        if !remaining_members.is_empty() {
            if let Some(spec) = ctx_projection_spec.as_ref() {
                if spec.validate_socket_projection {
                    if let (Some(ctx), Some(PathMember::String { val, .. })) =
                        (self.probe_ctx, remaining_members.first())
                    {
                        if let Some(message) = ctx.socket_projection_access_error(val) {
                            return Err(CompileError::UnsupportedInstruction(message));
                        }
                    }
                }
                let slot = spec.stack_slot_ty.as_ref().map(|stack_slot_ty| {
                    let slot = self.func.alloc_stack_slot(
                        align_to_eight(stack_slot_ty.size()),
                        8,
                        StackSlotKind::Local,
                    );
                    self.record_stack_slot_type(slot, stack_slot_ty.clone());
                    slot
                });
                let base_ty = spec.runtime_ty.clone();
                let base_vreg = self.func.alloc_vreg();
                self.vreg_type_hints.insert(base_vreg, base_ty.clone());
                self.emit(MirInst::LoadCtxField {
                    dst: base_vreg,
                    field: ctx_field.clone(),
                    slot,
                });
                if spec.normalize_u32_words_host_order {
                    self.normalize_host_order_u32_array_slot(base_vreg)?;
                }
                let projected_ty = self.lower_typed_value_projection(
                    src_dst,
                    dst_vreg,
                    base_vreg,
                    &base_ty,
                    remaining_members,
                    &Self::typed_value_path_desc(&path.members),
                    Some(&ctx_field),
                    None,
                )?;
                let meta = self.get_or_create_metadata(src_dst);
                meta.is_context = false;
                meta.field_type = Some(projected_ty);
                meta.root_ctx_field = Some(ctx_field.clone());
                meta.source_var = None;
                return Ok(());
            }

            if let CtxField::TracepointField(name) = &ctx_field
                && let Some((root_semantic_ty, root_runtime_ty @ MirType::Ptr { .. })) =
                    self.tracepoint_root_field_types(name)?
            {
                let slot = if matches!(
                    root_runtime_ty,
                    MirType::Ptr {
                        address_space: AddressSpace::Stack,
                        ..
                    }
                ) {
                    let slot = self.func.alloc_stack_slot(
                        align_to_eight(root_semantic_ty.size()),
                        8,
                        StackSlotKind::Local,
                    );
                    self.record_stack_slot_type(slot, root_semantic_ty.clone());
                    Some(slot)
                } else {
                    None
                };
                let base_vreg = self.func.alloc_vreg();
                self.vreg_type_hints
                    .insert(base_vreg, root_runtime_ty.clone());
                self.emit(MirInst::LoadCtxField {
                    dst: base_vreg,
                    field: ctx_field.clone(),
                    slot,
                });
                let projected_ty = self.lower_typed_value_projection(
                    src_dst,
                    dst_vreg,
                    base_vreg,
                    &root_runtime_ty,
                    remaining_members,
                    &Self::typed_value_path_desc(&path.members),
                    Some(&ctx_field),
                    None,
                )?;
                let meta = self.get_or_create_metadata(src_dst);
                meta.is_context = false;
                meta.field_type = Some(projected_ty);
                meta.root_ctx_field = Some(ctx_field.clone());
                meta.source_var = None;
                return Ok(());
            }

            let ctx = self.probe_ctx.ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "nested ctx field access requires probe context".into(),
                )
            })?;
            let nested_segments: Vec<TrampolineFieldSelector> = remaining_members
                .iter()
                .map(Self::trampoline_field_selector)
                .collect::<Result<_, _>>()?;
            let path_desc = Self::trampoline_field_path_desc(&nested_segments);
            let Some(spec) = trampoline_value_spec else {
                return Err(CompileError::UnsupportedInstruction(
                    "nested ctx field access is only supported for BTF-backed trampoline args and returns"
                        .into(),
                ));
            };
            if matches!(spec.kind, TrampolineValueKind::Scalar) {
                return Err(CompileError::UnsupportedInstruction(
                    "nested ctx field access requires a struct/union trampoline value or pointer to one"
                        .into(),
                ));
            }
            let projection = match &ctx_field {
                CtxField::Arg(idx) => ctx
                    .btf_arg_field_projection(*idx as usize, &nested_segments, &path_desc)
                    .map_err(CompileError::UnsupportedInstruction)?
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            ctx.btf_arg_unavailable_error(*idx as usize),
                        )
                    })?,
                CtxField::RetVal => ctx
                    .btf_ret_field_projection(&nested_segments, &path_desc)
                    .map_err(CompileError::UnsupportedInstruction)?
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(ctx.btf_ret_unavailable_error())
                    })?,
                _ => {
                    return Err(CompileError::UnsupportedInstruction(
                        "nested ctx field access is only supported for trampoline args and retval"
                            .into(),
                    ));
                }
            };
            let projected_ty =
                Self::projected_trampoline_field_type(&projection.type_info).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "projected trampoline field '{}' has unsupported type {:?}; only scalar, pointer, and terminal aggregate/array fields are supported",
                        path_desc,
                        projection.type_info
                    ))
                })?;
            let root_runtime_ty = self
                .trampoline_root_type_info(&ctx_field)?
                .and_then(|type_info| Self::root_trampoline_value_types(&type_info, spec.kind))
                .map(|(_, runtime_ty)| runtime_ty)
                .unwrap_or_else(|| match spec.kind {
                    TrampolineValueKind::Aggregate { size_bytes } => MirType::Ptr {
                        pointee: Box::new(MirType::Array {
                            elem: Box::new(MirType::U8),
                            len: size_bytes,
                        }),
                        address_space: AddressSpace::Stack,
                    },
                    TrampolineValueKind::Pointer { user_space } => {
                        Self::trampoline_pointer_type(if user_space {
                            AddressSpace::User
                        } else {
                            AddressSpace::Kernel
                        })
                    }
                    TrampolineValueKind::Scalar => MirType::I64,
                });
            self.lower_trampoline_field_projection(
                dst_vreg,
                &ctx_field,
                spec,
                &projection,
                &root_runtime_ty,
                &projected_ty,
                &path_desc,
            )?;

            let projected_ty = projected_ty.clone();
            let meta = self.get_or_create_metadata(src_dst);
            meta.is_context = false;
            meta.field_type = Some(projected_ty);
            meta.root_ctx_field = Some(ctx_field.clone());
            meta.source_var = None;
            return Ok(());
        }

        let tracepoint_root_types = match &ctx_field {
            CtxField::TracepointField(name) => self.tracepoint_root_field_types(name)?,
            _ => None,
        };
        let slot = trampoline_value_spec
            .and_then(|spec| match spec.kind {
                TrampolineValueKind::Aggregate { size_bytes } => Some(self.func.alloc_stack_slot(
                    align_to_eight(size_bytes),
                    8,
                    StackSlotKind::Local,
                )),
                _ => None,
            })
            .or_else(|| match tracepoint_root_types.as_ref() {
                Some((
                    semantic_ty,
                    MirType::Ptr {
                        address_space: AddressSpace::Stack,
                        ..
                    },
                )) => Some(self.func.alloc_stack_slot(
                    align_to_eight(semantic_ty.size()),
                    8,
                    StackSlotKind::Local,
                )),
                _ => None,
            })
            .or_else(|| self.get_metadata(src_dst).and_then(|m| m.string_slot))
            .or_else(|| {
                ctx_projection_spec
                    .as_ref()
                    .and_then(|spec| spec.stack_slot_ty.as_ref())
                    .map(|stack_slot_ty| {
                        self.func.alloc_stack_slot(
                            align_to_eight(stack_slot_ty.size()),
                            8,
                            StackSlotKind::Local,
                        )
                    })
            });
        let precise_trampoline_types = trampoline_value_spec
            .zip(self.trampoline_root_type_info(&ctx_field)?)
            .and_then(|(spec, type_info)| Self::root_trampoline_value_types(&type_info, spec.kind));
        if let (
            Some(slot),
            Some((
                _,
                MirType::Ptr {
                    pointee,
                    address_space,
                },
            )),
        ) = (slot, precise_trampoline_types.as_ref())
            && *address_space == AddressSpace::Stack
        {
            self.record_stack_slot_type(slot, pointee.as_ref().clone());
        }
        if let (Some(slot), Some(stack_slot_ty)) = (
            slot,
            ctx_projection_spec
                .as_ref()
                .and_then(|spec| spec.stack_slot_ty.as_ref()),
        ) {
            self.record_stack_slot_type(slot, stack_slot_ty.clone());
        }
        if let (
            Some(slot),
            Some((
                semantic_ty,
                MirType::Ptr {
                    address_space: AddressSpace::Stack,
                    ..
                },
            )),
        ) = (slot, tracepoint_root_types.as_ref())
        {
            self.record_stack_slot_type(slot, semantic_ty.clone());
        }
        self.emit(MirInst::LoadCtxField {
            dst: dst_vreg,
            field: ctx_field.clone(),
            slot,
        });

        let ctx_field_types = ProbeContext::resolve_ctx_field_type_spec(self.probe_ctx, &ctx_field);
        let (field_type, runtime_type_hint) = match &ctx_field {
            CtxField::Arg(_)
                if self
                    .probe_ctx
                    .is_some_and(|ctx| ctx.uses_raw_tracepoint_args()) =>
            {
                (MirType::U64, Some(MirType::U64))
            }
            CtxField::TracepointField(_) => tracepoint_root_types
                .map(|(semantic_ty, runtime_ty)| (semantic_ty, Some(runtime_ty)))
                .unwrap_or((MirType::I64, None)),
            _ if ctx_field_types.is_some() => {
                let spec = ctx_field_types.unwrap();
                (spec.semantic_ty, Some(spec.runtime_ty))
            }
            _ => precise_trampoline_types
                .map(|(semantic_ty, runtime_ty)| (semantic_ty, Some(runtime_ty)))
                .unwrap_or_else(|| match trampoline_value_spec.map(|spec| spec.kind) {
                    Some(TrampolineValueKind::Aggregate { size_bytes }) => (
                        MirType::Array {
                            elem: Box::new(MirType::U8),
                            len: size_bytes,
                        },
                        None,
                    ),
                    _ => (MirType::I64, None),
                }),
        };
        if let Some(runtime_ty) = runtime_type_hint {
            self.vreg_type_hints.insert(dst_vreg, runtime_ty);
        }

        if matches!(
            ctx_field,
            CtxField::UserIp4 | CtxField::UserPort | CtxField::MsgSrcIp4
        ) {
            self.emit_packet_big_endian_scalar_normalize(dst_vreg, &MirType::U32)?;
            if matches!(ctx_field, CtxField::UserPort) {
                let shift_16 = self.large_const_operand(&MirType::U32, 16);
                self.emit(MirInst::BinOp {
                    dst: dst_vreg,
                    op: BinOpKind::Shr,
                    lhs: MirValue::VReg(dst_vreg),
                    rhs: shift_16,
                });
            }
        }
        if ctx_projection_spec
            .as_ref()
            .is_some_and(|spec| spec.normalize_u32_words_host_order)
        {
            self.normalize_host_order_u32_array_slot(dst_vreg)?;
        }

        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = false;
        meta.field_type = Some(field_type);
        meta.root_ctx_field = Some(ctx_field);
        meta.source_var = None;

        Ok(())
    }

    pub(super) fn lower_upsert_cell_path(
        &mut self,
        src_dst: RegId,
        path_reg: RegId,
        new_value: RegId,
    ) -> Result<(), CompileError> {
        let path = self
            .get_metadata(path_reg)
            .and_then(|m| m.cell_path.clone())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction("Cell path literal not found".into())
            })?;
        if path.members.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "Empty cell path is not supported".into(),
            ));
        }

        if self.is_context_reg(src_dst) {
            return self.lower_context_upsert_cell_path(src_dst, &path, new_value);
        }

        let path_desc = Self::typed_value_path_desc(&path.members);

        let base_vreg = self.get_vreg(src_dst);
        let base_runtime_ty = self
            .typed_value_runtime_type(src_dst, base_vreg)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' requires type information for the base value",
                    path_desc
                ))
            })?;
        let MirType::Ptr {
            pointee,
            address_space: AddressSpace::Stack | AddressSpace::Map,
        } = base_runtime_ty
        else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' requires a materialized stack/map aggregate pointer value",
                path_desc
            )));
        };

        let projection =
            Self::resolve_typed_value_projection_path(pointee.as_ref(), &path.members, &path_desc)?;
        let projected_semantics = self
            .get_metadata(src_dst)
            .and_then(|m| m.annotated_semantics.clone())
            .and_then(|semantics| {
                Self::project_annotated_value_semantics(&semantics, &path.members)
            });
        if projection.bitfield.is_some() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' does not support bitfield fields",
                path_desc
            )));
        }

        let new_value_vreg = self.get_vreg(new_value);
        let new_value_runtime_ty = self.typed_value_runtime_type(new_value, new_value_vreg);

        match &projection.ty {
            MirType::Array { .. } | MirType::Struct { .. } => {
                if let Some(AnnotatedValueSemantics::String {
                    slot_len,
                    content_cap,
                }) = projected_semantics.as_ref()
                {
                    let src_meta = self.get_metadata(new_value).cloned().ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "cell path update '.{} = ...' requires a materialized string value with tracked length",
                            path_desc
                        ))
                    })?;
                    let slot = src_meta.string_slot.ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "cell path update '.{} = ...' requires a materialized string value with tracked length",
                            path_desc
                        ))
                    })?;
                    let len_vreg = src_meta.string_len_vreg.ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "cell path update '.{} = ...' requires a tracked string length",
                            path_desc
                        ))
                    })?;
                    let src_slot_size = self.stack_slot_size(slot).ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "string slot not found during cell path update".into(),
                        )
                    })?;
                    if src_slot_size > *slot_len {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "cell path update '.{} = ...' cannot store string buffer of size {} into field capacity {}",
                            path_desc, src_slot_size, slot_len
                        )));
                    }
                    let src_max_len = src_meta
                        .string_len_bound
                        .unwrap_or(src_slot_size.saturating_sub(1));
                    if src_max_len > *content_cap {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "cell path update '.{} = ...' cannot store string value with capacity {} into field content capacity {}",
                            path_desc, src_max_len, content_cap
                        )));
                    }

                    self.emit(MirInst::Store {
                        ptr: base_vreg,
                        offset: projection.offset as i32,
                        val: MirValue::VReg(len_vreg),
                        ty: MirType::U64,
                    });

                    let src_ptr = self.func.alloc_vreg();
                    self.emit(MirInst::Copy {
                        dst: src_ptr,
                        src: MirValue::StackSlot(slot),
                    });
                    self.vreg_type_hints.insert(
                        src_ptr,
                        MirType::Ptr {
                            pointee: Box::new(MirType::Array {
                                elem: Box::new(MirType::U8),
                                len: src_slot_size,
                            }),
                            address_space: AddressSpace::Stack,
                        },
                    );
                    self.emit_ptr_copy_with_offsets(
                        base_vreg,
                        projection.offset + 8,
                        src_ptr,
                        0,
                        src_slot_size,
                    )?;
                    if src_slot_size < *slot_len {
                        self.emit_ptr_zero(
                            base_vreg,
                            projection.offset + 8 + src_slot_size,
                            slot_len - src_slot_size,
                        )?;
                    }
                    return Ok(());
                }

                let aggregate_new_value_vreg =
                    self.materialized_metadata_aggregate_vreg(new_value, new_value_vreg)?;
                let aggregate_new_value_runtime_ty = self
                    .vreg_type_hints
                    .get(&aggregate_new_value_vreg)
                    .cloned()
                    .or_else(|| new_value_runtime_ty.clone())
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "cell path update '.{} = ...' requires type information for the new value",
                            path_desc
                        ))
                    })?;

                let MirType::Ptr {
                    pointee: new_value_pointee,
                    address_space: AddressSpace::Stack | AddressSpace::Map,
                } = aggregate_new_value_runtime_ty
                else {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "cell path update '.{} = ...' requires a materialized aggregate pointer value for field {:?}",
                        path_desc, projection.ty
                    )));
                };

                if new_value_pointee.as_ref() != &projection.ty {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "cell path update '.{} = ...' cannot store type {:?} into field of type {:?}",
                        path_desc, new_value_pointee, projection.ty
                    )));
                }

                self.emit_ptr_copy_with_offsets(
                    base_vreg,
                    projection.offset,
                    aggregate_new_value_vreg,
                    0,
                    projection.ty.size(),
                )?;
            }
            _ => {
                let new_value_runtime_ty = new_value_runtime_ty.ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "cell path update '.{} = ...' requires type information for the new value",
                        path_desc
                    ))
                })?;
                let Some(stored_vreg) = self.coerce_scalar_assignment_value(
                    new_value_vreg,
                    &new_value_runtime_ty,
                    &projection.ty,
                ) else {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "cell path update '.{} = ...' cannot store type {:?} into field of type {:?}",
                        path_desc, new_value_runtime_ty, projection.ty
                    )));
                };

                self.emit(MirInst::Store {
                    ptr: base_vreg,
                    offset: projection.offset as i32,
                    val: MirValue::VReg(stored_vreg),
                    ty: projection.ty.clone(),
                });
            }
        }

        let meta = self.get_or_create_metadata(src_dst);
        meta.field_type = Some(pointee.as_ref().clone());
        Ok(())
    }
}
