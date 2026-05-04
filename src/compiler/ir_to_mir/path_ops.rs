use super::*;
use crate::compiler::ctx_field_schema::ContextFieldTypeSpec;
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::AddressSpace;
use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector, TrampolineValueKind, TypeInfo};

impl<'a> HirToMirLowering<'a> {
    fn ctx_field_kernel_btf_root_runtime_type(
        &self,
        field: &CtxField,
        type_spec: &ContextFieldTypeSpec,
    ) -> Result<Option<MirType>, CompileError> {
        let Some(type_name) = type_spec.kernel_btf_runtime_type_name else {
            return Ok(None);
        };
        self.kernel_btf_root_runtime_type(field, type_name)
    }

    fn kernel_btf_root_runtime_type(
        &self,
        field: &CtxField,
        type_name: &str,
    ) -> Result<Option<MirType>, CompileError> {
        let type_info = KernelBtf::get()
            .kernel_named_type_info(type_name)
            .map_err(|err| {
                CompileError::UnsupportedInstruction(format!(
                    "failed to resolve ctx.{} {} layout from kernel BTF: {err}",
                    field.display_name(),
                    type_name
                ))
            })?;
        let TypeInfo::Struct {
            name,
            btf_type_id,
            size,
            ..
        } = type_info
        else {
            return Ok(None);
        };
        if size == 0 {
            return Ok(None);
        }

        let root_ty = MirType::Struct {
            name: Some(name),
            kernel_btf_type_id: btf_type_id,
            fields: vec![crate::compiler::mir::StructField {
                name: "__opaque".to_string(),
                ty: MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: size,
                },
                offset: 0,
                synthetic: false,
                bitfield: None,
            }],
        };
        Ok(Some(MirType::Ptr {
            pointee: Box::new(root_ty),
            address_space: AddressSpace::Kernel,
        }))
    }

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

    fn validate_ctx_field_access_with_source_name(
        &self,
        ctx_field: &CtxField,
        source_ctx_field_name: &str,
    ) -> Result<(), CompileError> {
        if let Some(ctx) = self.probe_ctx
            && let Some(message) = ctx.ctx_field_access_error(ctx_field)
        {
            let canonical = format!("ctx.{}", ctx_field.display_name());
            let source = format!("ctx.{source_ctx_field_name}");
            let message = if source_ctx_field_name != "arg" && source != canonical {
                message.replace(&canonical, &source)
            } else {
                message
            };
            return Err(CompileError::UnsupportedInstruction(message));
        }
        Ok(())
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
            AddressSpace::Stack | AddressSpace::Map | AddressSpace::Context => {
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
        meta.trusted_btf = false;

        Ok(element_ty)
    }

    fn lower_context_helper_backed_cgroup_id_projection(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        path: &CellPath,
    ) -> Result<bool, CompileError> {
        let Some(PathMember::String { val: root, .. }) = path.members.first() else {
            return Ok(false);
        };
        let helper = match root.as_str() {
            "ancestor_cgroup_id" => BpfHelper::GetCurrentAncestorCgroupId,
            "skb_ancestor_cgroup_id" => BpfHelper::SkbAncestorCgroupId,
            _ => return Ok(false),
        };
        let uses_ctx_arg = matches!(helper, BpfHelper::SkbAncestorCgroupId);
        let projection_name = root.as_str();

        let [_, level_member] = path.members.as_slice() else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "ctx.{projection_name} requires a constant numeric ancestor level, e.g. $ctx.{projection_name}.0"
            )));
        };
        let PathMember::Int { val: level, .. } = level_member else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "ctx.{projection_name} requires a constant numeric ancestor level, e.g. $ctx.{projection_name}.0"
            )));
        };
        let Ok(level_i32) = i32::try_from(*level) else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "ctx.{projection_name} requires ancestor level 0..{}, got {}",
                i32::MAX,
                level
            )));
        };
        if !uses_ctx_arg {
            self.validate_ctx_field_access_with_source_name(&CtxField::CgroupId, projection_name)?;
        }
        if let Some(message) = self.probe_ctx.and_then(|ctx| ctx.helper_call_error(helper)) {
            return Err(CompileError::UnsupportedInstruction(message));
        }

        let mut args = Vec::new();
        if uses_ctx_arg {
            let ctx_vreg = self.func.alloc_vreg();
            self.vreg_type_hints.insert(
                ctx_vreg,
                MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Kernel,
                },
            );
            self.emit(MirInst::LoadCtxField {
                dst: ctx_vreg,
                field: CtxField::Context,
                slot: None,
            });
            args.push(MirValue::VReg(ctx_vreg));
        }
        args.push(MirValue::Const(i64::from(level_i32)));

        self.emit(MirInst::CallHelper {
            dst: dst_vreg,
            helper: helper as u32,
            args,
        });
        self.vreg_type_hints.insert(dst_vreg, MirType::U64);
        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = false;
        meta.field_type = Some(MirType::U64);
        meta.root_ctx_field = None;
        meta.trusted_btf = false;
        meta.source_var = None;
        Ok(true)
    }

    fn lower_current_cgroup_btf_pointer_projection(
        &mut self,
        dst_vreg: VReg,
        task_vreg: VReg,
        alias_name: &str,
    ) -> Result<MirType, CompileError> {
        let projection_path = [
            TrampolineFieldSelector::Field("cgroups".to_string()),
            TrampolineFieldSelector::Field("dfl_cgrp".to_string()),
        ];
        let path_desc = format!("ctx.{alias_name}");
        let projection = KernelBtf::get()
            .kernel_named_type_field_projection("task_struct", &projection_path)
            .map_err(|err| {
                CompileError::UnsupportedInstruction(format!(
                    "{path_desc} requires kernel BTF for task_struct.cgroups.dfl_cgrp: {err}"
                ))
            })?;

        let mut base_vreg = task_vreg;
        let mut projected_ty = None;
        for (idx, segment) in projection.path.iter().enumerate() {
            if segment.bitfield.is_some() {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{path_desc} does not support bitfield segments"
                )));
            }
            let segment_ty =
                Self::projected_trampoline_field_type(&segment.type_info).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "{path_desc} has unsupported kernel BTF field type {:?}",
                        segment.type_info
                    ))
                })?;
            let segment_vreg = if idx + 1 == projection.path.len() {
                dst_vreg
            } else {
                self.func.alloc_vreg()
            };
            self.vreg_type_hints
                .insert(segment_vreg, segment_ty.clone());
            self.emit(MirInst::Load {
                dst: segment_vreg,
                ptr: base_vreg,
                offset: Self::trampoline_projection_offset_i32(segment.offset_bytes, &path_desc)?,
                ty: segment_ty.clone(),
            });
            base_vreg = segment_vreg;
            projected_ty = Some(segment_ty);
        }

        let projected_ty = projected_ty.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{path_desc} requires a non-empty kernel BTF projection"
            ))
        })?;
        if !projected_ty.is_cgroup_ptr() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{path_desc} resolved to {:?}, expected cgroup pointer",
                projected_ty
            )));
        }
        Ok(projected_ty)
    }

    fn lower_current_cgroup_context_field(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        path: &CellPath,
        source_ctx_field_name: &str,
        root_members_consumed: usize,
    ) -> Result<(), CompileError> {
        let task_field = CtxField::Task;
        self.implied_ctx_fields.insert(CtxField::Cgroup);
        let task_type_spec = ProbeContext::resolve_ctx_field_type_spec(self.probe_ctx, &task_field)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "ctx.{source_ctx_field_name} requires typed ctx.task support"
                ))
            })?;
        let task_runtime_ty = self
            .ctx_field_kernel_btf_root_runtime_type(&task_field, &task_type_spec)?
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "ctx.{source_ctx_field_name} requires kernel BTF for task_struct"
                ))
            })?;

        let task_vreg = self.func.alloc_vreg();
        self.vreg_type_hints
            .insert(task_vreg, task_runtime_ty.clone());
        self.emit(MirInst::LoadCtxField {
            dst: task_vreg,
            field: task_field.clone(),
            slot: None,
        });

        let path_desc = Self::typed_value_path_desc(&path.members);
        let remaining_members: Vec<PathMember> = path
            .members
            .iter()
            .skip(root_members_consumed)
            .cloned()
            .collect();
        let projected_ty = if remaining_members.is_empty() {
            self.lower_current_cgroup_btf_pointer_projection(
                dst_vreg,
                task_vreg,
                source_ctx_field_name,
            )?
        } else {
            let cgroup_vreg = self.func.alloc_vreg();
            let cgroup_ty = self.lower_current_cgroup_btf_pointer_projection(
                cgroup_vreg,
                task_vreg,
                source_ctx_field_name,
            )?;
            let projected_ty = self.lower_typed_value_projection(
                src_dst,
                dst_vreg,
                cgroup_vreg,
                &cgroup_ty,
                &remaining_members,
                &path_desc,
                Some(&task_field),
                true,
                None,
            )?;
            projected_ty
        };
        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = false;
        meta.field_type = Some(projected_ty);
        meta.root_ctx_field = Some(task_field);
        meta.trusted_btf = matches!(
            meta.field_type.as_ref(),
            Some(MirType::Ptr {
                address_space: AddressSpace::Kernel,
                ..
            })
        );
        meta.source_var = None;
        Ok(())
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
            let constant_value = self
                .get_metadata(src_dst)
                .and_then(|meta| meta.constant_value.as_ref())
                .and_then(|value| Self::constant_follow_cell_path(value, &path));
            let path_desc = Self::typed_value_path_desc(&path.members);
            let mut source_vreg = dst_vreg;
            let mut base_runtime_ty = self
                .typed_value_runtime_type(src_dst, source_vreg)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "typed field path '{}' requires type information for the base value",
                        path_desc
                    ))
                })?;
            if !matches!(base_runtime_ty, MirType::Ptr { .. })
                && Self::aggregate_call_value_type(&base_runtime_ty).is_some()
            {
                source_vreg = self.materialized_metadata_aggregate_vreg(src_dst, source_vreg)?;
                base_runtime_ty = self
                    .typed_value_runtime_type(src_dst, source_vreg)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "typed field path '{}' requires type information for the base value",
                            path_desc
                        ))
                    })?;
            }
            let base_vreg = self.func.alloc_vreg();
            self.emit(MirInst::Copy {
                dst: base_vreg,
                src: MirValue::VReg(source_vreg),
            });
            let projected_semantics = self
                .get_metadata(src_dst)
                .and_then(|m| m.annotated_semantics.clone())
                .and_then(|semantics| {
                    Self::project_annotated_value_semantics(&semantics, &path.members)
                });
            let root_ctx_field = self
                .get_metadata(src_dst)
                .and_then(|meta| meta.root_ctx_field.clone());
            let map_value_origin = self
                .get_metadata(src_dst)
                .and_then(|meta| meta.map_value_origin.clone());
            let base_trusted_btf = self
                .get_metadata(src_dst)
                .is_some_and(|meta| meta.trusted_btf);
            self.vreg_type_hints.insert(
                base_vreg,
                self.vreg_type_hints
                    .get(&source_vreg)
                    .cloned()
                    .unwrap_or_else(|| base_runtime_ty.clone()),
            );
            let projected_ty = self.lower_typed_value_projection(
                src_dst,
                source_vreg,
                base_vreg,
                &base_runtime_ty,
                &path.members,
                &path_desc,
                root_ctx_field.as_ref(),
                base_trusted_btf,
                projected_semantics.as_ref(),
            )?;
            let preserves_map_value_origin = matches!(
                self.vreg_type_hints.get(&dst_vreg),
                Some(MirType::Ptr {
                    address_space: AddressSpace::Map,
                    ..
                })
            );
            let meta = self.get_or_create_metadata(src_dst);
            meta.is_context = false;
            meta.field_type = Some(projected_ty);
            meta.root_ctx_field = root_ctx_field;
            meta.map_value_origin = map_value_origin.filter(|_| preserves_map_value_origin);
            meta.trusted_btf = base_trusted_btf
                && matches!(
                    meta.field_type.as_ref(),
                    Some(MirType::Ptr {
                        address_space: AddressSpace::Kernel,
                        ..
                    })
                );
            meta.annotated_semantics = projected_semantics;
            meta.source_var = None;
            self.set_reg_constant_value(src_dst, constant_value);
            return Ok(());
        }

        if self.lower_context_helper_backed_cgroup_id_projection(src_dst, dst_vreg, &path)? {
            return Ok(());
        }

        let source_ctx_field_name = Self::ctx_path_member_name(&path.members[0])?;
        let (ctx_field, root_members_consumed) = self.resolve_ctx_field_from_path(&path)?;
        let remaining_members = &path.members[root_members_consumed..];
        self.validate_ctx_field_access_with_source_name(&ctx_field, &source_ctx_field_name)?;
        if matches!(ctx_field, CtxField::Cgroup) {
            self.lower_current_cgroup_context_field(
                src_dst,
                dst_vreg,
                &path,
                &source_ctx_field_name,
                root_members_consumed,
            )?;
            return Ok(());
        }
        let trampoline_value_spec = self.trampoline_value_spec(&ctx_field)?;
        let ctx_projection_spec =
            ProbeContext::resolve_ctx_field_projection_spec(self.probe_ctx, &ctx_field);
        let ctx_field_types = ProbeContext::resolve_ctx_field_type_spec(self.probe_ctx, &ctx_field);

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
                let base_trusted_btf = slot.is_none()
                    && ProbeContext::resolve_ctx_field_is_trusted_btf_kernel_pointer(
                        self.probe_ctx,
                        &ctx_field,
                    );
                let projected_ty = self.lower_typed_value_projection(
                    src_dst,
                    dst_vreg,
                    base_vreg,
                    &base_ty,
                    remaining_members,
                    &Self::typed_value_path_desc(&path.members),
                    Some(&ctx_field),
                    base_trusted_btf,
                    None,
                )?;
                let meta = self.get_or_create_metadata(src_dst);
                meta.is_context = false;
                meta.field_type = Some(projected_ty);
                meta.root_ctx_field = Some(ctx_field.clone());
                meta.trusted_btf = base_trusted_btf
                    && matches!(
                        meta.field_type.as_ref(),
                        Some(MirType::Ptr {
                            address_space: AddressSpace::Kernel,
                            ..
                        })
                    );
                meta.source_var = None;
                return Ok(());
            }

            let ctx_projection_root_runtime_ty = match ctx_field_types.as_ref() {
                Some(type_spec) => {
                    self.ctx_field_kernel_btf_root_runtime_type(&ctx_field, type_spec)?
                }
                None => None,
            };
            if let Some(root_runtime_ty) = ctx_projection_root_runtime_ty {
                let base_vreg = self.func.alloc_vreg();
                self.vreg_type_hints
                    .insert(base_vreg, root_runtime_ty.clone());
                self.emit(MirInst::LoadCtxField {
                    dst: base_vreg,
                    field: ctx_field.clone(),
                    slot: None,
                });
                let base_trusted_btf =
                    ProbeContext::resolve_ctx_field_is_trusted_btf_kernel_pointer(
                        self.probe_ctx,
                        &ctx_field,
                    );
                let projected_ty = self.lower_typed_value_projection(
                    src_dst,
                    dst_vreg,
                    base_vreg,
                    &root_runtime_ty,
                    remaining_members,
                    &Self::typed_value_path_desc(&path.members),
                    Some(&ctx_field),
                    base_trusted_btf,
                    None,
                )?;
                let meta = self.get_or_create_metadata(src_dst);
                meta.is_context = false;
                meta.field_type = Some(projected_ty);
                meta.root_ctx_field = Some(ctx_field.clone());
                meta.trusted_btf = base_trusted_btf
                    && matches!(
                        meta.field_type.as_ref(),
                        Some(MirType::Ptr {
                            address_space: AddressSpace::Kernel,
                            ..
                        })
                    );
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
                    false,
                    None,
                )?;
                let meta = self.get_or_create_metadata(src_dst);
                meta.is_context = false;
                meta.field_type = Some(projected_ty);
                meta.root_ctx_field = Some(ctx_field.clone());
                meta.trusted_btf = false;
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
            meta.trusted_btf = matches!(
                spec.kind,
                TrampolineValueKind::Pointer { user_space: false }
            ) && matches!(
                meta.field_type.as_ref(),
                Some(MirType::Ptr {
                    address_space: AddressSpace::Kernel,
                    ..
                })
            );
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

        let ctx_field_btf_root_runtime_ty = ctx_field_types.as_ref().and_then(|type_spec| {
            self.ctx_field_kernel_btf_root_runtime_type(&ctx_field, type_spec)
                .ok()
                .flatten()
        });
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
            _ => {
                if let Some(spec) = ctx_field_types {
                    (
                        spec.semantic_ty,
                        Some(ctx_field_btf_root_runtime_ty.unwrap_or(spec.runtime_ty)),
                    )
                } else {
                    precise_trampoline_types
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
                        })
                }
            }
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

        let trusted_btf = slot.is_none()
            && ProbeContext::resolve_ctx_field_is_trusted_btf_kernel_pointer(
                self.probe_ctx,
                &ctx_field,
            );
        let meta = self.get_or_create_metadata(src_dst);
        meta.is_context = false;
        meta.field_type = Some(field_type);
        meta.root_ctx_field = Some(ctx_field);
        meta.trusted_btf = trusted_btf;
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
        let constant_value = self
            .get_metadata(src_dst)
            .and_then(|meta| meta.constant_value.as_ref())
            .zip(
                self.get_metadata(new_value)
                    .and_then(|meta| meta.constant_value.as_ref()),
            )
            .and_then(|(value, new_value)| {
                Self::constant_upsert_cell_path(value, &path, new_value.clone())
            });

        let mut base_vreg = self.get_vreg(src_dst);
        let mut base_runtime_ty = self
            .typed_value_runtime_type(src_dst, base_vreg)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' requires type information for the base value",
                    path_desc
                ))
            })?;
        if !matches!(base_runtime_ty, MirType::Ptr { .. })
            && Self::aggregate_call_value_type(&base_runtime_ty).is_some()
        {
            base_vreg = self.materialized_metadata_aggregate_vreg(src_dst, base_vreg)?;
            base_runtime_ty = self
                .typed_value_runtime_type(src_dst, base_vreg)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "cell path update '.{} = ...' requires type information for the base value",
                        path_desc
                    ))
                })?;
        }
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
                    self.clear_source_var(src_dst);
                    self.set_reg_constant_value(src_dst, constant_value.clone());
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
        meta.source_var = None;
        self.set_reg_constant_value(src_dst, constant_value);
        Ok(())
    }
}
