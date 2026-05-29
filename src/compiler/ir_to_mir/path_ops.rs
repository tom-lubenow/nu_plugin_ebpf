use super::*;
use crate::compiler::ctx_field_schema::ContextFieldTypeSpec;
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::AddressSpace;
use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector, TrampolineValueKind, TypeInfo};

mod numeric_lists;

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
        meta.kernel_btf_field_addr = None;

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
        meta.kernel_btf_field_addr = None;
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
        meta.kernel_btf_field_addr = None;
        meta.source_var = None;
        Ok(())
    }

    fn lower_record_field_projection_from_metadata(
        &mut self,
        src_dst: RegId,
        source_dst_vreg: VReg,
        had_source_vreg: bool,
        record_field: RecordField,
        remaining_members: &[PathMember],
        path_members: &[PathMember],
        constant_value: Option<Value>,
    ) -> Result<(), CompileError> {
        let path_desc = Self::typed_value_path_desc(path_members);
        let dst_vreg = if had_source_vreg {
            self.assign_fresh_vreg(src_dst)
        } else {
            source_dst_vreg
        };
        let mut source_vreg = record_field.value_vreg;
        let mut base_runtime_ty = self
            .vreg_type_hints
            .get(&source_vreg)
            .cloned()
            .unwrap_or_else(|| record_field.ty.clone());
        let source_meta = record_field
            .source_reg
            .and_then(|reg| self.get_metadata(reg).cloned());
        let base_trusted_btf = source_meta.as_ref().is_some_and(|meta| meta.trusted_btf);

        if remaining_members.is_empty() {
            self.emit(MirInst::Copy {
                dst: dst_vreg,
                src: MirValue::VReg(source_vreg),
            });
            self.vreg_type_hints
                .insert(dst_vreg, base_runtime_ty.clone());
            let meta = self.get_or_create_metadata(src_dst);
            *meta = RegMetadata::default();
            meta.is_context = record_field.is_context;
            meta.field_type = Some(base_runtime_ty);
            meta.root_ctx_field = record_field.root_ctx_field;
            meta.trusted_btf = base_trusted_btf;
            meta.kernel_btf_field_addr = source_meta.and_then(|meta| meta.kernel_btf_field_addr);
            meta.annotated_semantics = record_field.semantics;
            meta.source_var = None;
            self.set_reg_constant_value(src_dst, constant_value);
            return Ok(());
        }

        if let Some(AnnotatedValueSemantics::NumericList { max_len, .. }) = &record_field.semantics
            && let [PathMember::Int { val: index, .. }] = remaining_members
        {
            if *index >= *max_len {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' index {} is out of bounds for numeric list capacity {}",
                    path_desc, index, max_len
                )));
            }
            let list_vreg = match &base_runtime_ty {
                MirType::Ptr {
                    pointee,
                    address_space,
                } if pointee.as_ref() == &record_field.ty => match address_space {
                    AddressSpace::Stack => source_vreg,
                    AddressSpace::Map | AddressSpace::Context => {
                        let buffer_size = (max_len.saturating_add(1)) * std::mem::size_of::<i64>();
                        let slot =
                            self.func
                                .alloc_stack_slot(buffer_size, 8, StackSlotKind::ListBuffer);
                        self.record_list_buffer_slot_type(slot, *max_len);
                        let list_vreg = self.func.alloc_vreg();
                        self.emit(MirInst::ListNew {
                            dst: list_vreg,
                            buffer: slot,
                            max_len: *max_len,
                        });
                        self.vreg_type_hints.insert(
                            list_vreg,
                            MirType::Ptr {
                                pointee: Box::new(record_field.ty.clone()),
                                address_space: AddressSpace::Stack,
                            },
                        );
                        self.emit_ptr_to_slot_copy(
                            slot,
                            0,
                            source_vreg,
                            0,
                            record_field.ty.size(),
                        )?;
                        list_vreg
                    }
                    AddressSpace::Kernel | AddressSpace::User | AddressSpace::Packet => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "typed field path '{}' cannot index numeric list from {:?} memory",
                            path_desc, address_space
                        )));
                    }
                },
                _ => {
                    let mut parent_vreg = source_dst_vreg;
                    let mut parent_runtime_ty = self
                        .typed_value_runtime_type(src_dst, parent_vreg)
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(format!(
                                "typed field path '{}' requires type information for the parent record",
                                path_desc
                            ))
                        })?;
                    if !matches!(parent_runtime_ty, MirType::Ptr { .. })
                        && Self::aggregate_call_value_type(&parent_runtime_ty).is_some()
                    {
                        parent_vreg =
                            self.materialized_metadata_aggregate_vreg(src_dst, parent_vreg)?;
                        parent_runtime_ty = self
                            .typed_value_runtime_type(src_dst, parent_vreg)
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "typed field path '{}' requires type information for the materialized parent record",
                                    path_desc
                                ))
                            })?;
                    }

                    let list_vreg = self.func.alloc_vreg();
                    let parent_copy_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::Copy {
                        dst: parent_copy_vreg,
                        src: MirValue::VReg(parent_vreg),
                    });
                    self.vreg_type_hints
                        .insert(parent_copy_vreg, parent_runtime_ty.clone());
                    self.lower_typed_value_projection(
                        src_dst,
                        list_vreg,
                        parent_copy_vreg,
                        &parent_runtime_ty,
                        &path_members[..1],
                        &Self::typed_value_path_desc(&path_members[..1]),
                        record_field.root_ctx_field.as_ref(),
                        base_trusted_btf,
                        record_field.semantics.as_ref(),
                    )?;
                    list_vreg
                }
            };
            self.emit(MirInst::ListGet {
                dst: dst_vreg,
                list: list_vreg,
                idx: MirValue::Const(i64::try_from(*index).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "typed field path '{}' numeric list index {} is too large",
                        path_desc, index
                    ))
                })?),
            });
            self.vreg_type_hints.insert(dst_vreg, MirType::I64);
            let meta = self.get_or_create_metadata(src_dst);
            *meta = RegMetadata::default();
            meta.field_type = Some(MirType::I64);
            meta.source_var = None;
            self.set_reg_constant_value(src_dst, constant_value);
            return Ok(());
        }

        if !matches!(base_runtime_ty, MirType::Ptr { .. })
            && Self::aggregate_call_value_type(&base_runtime_ty).is_some()
        {
            let Some(source_reg) = record_field.source_reg else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' requires materializable metadata for record field '{}'",
                    path_desc, record_field.name
                )));
            };
            source_vreg = self.materialized_metadata_aggregate_vreg(source_reg, source_vreg)?;
            base_runtime_ty = self
                .typed_value_runtime_type(source_reg, source_vreg)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "typed field path '{}' requires type information for record field '{}'",
                        path_desc, record_field.name
                    ))
                })?;
        }

        let base_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: base_vreg,
            src: MirValue::VReg(source_vreg),
        });
        self.vreg_type_hints
            .insert(base_vreg, base_runtime_ty.clone());
        let projected_semantics = record_field.semantics.as_ref().and_then(|semantics| {
            Self::project_annotated_value_semantics(semantics, remaining_members)
        });
        let projected_ty = self.lower_typed_value_projection(
            src_dst,
            dst_vreg,
            base_vreg,
            &base_runtime_ty,
            remaining_members,
            &path_desc,
            record_field.root_ctx_field.as_ref(),
            base_trusted_btf,
            projected_semantics.as_ref(),
        )?;
        let meta = self.get_or_create_metadata(src_dst);
        *meta = RegMetadata::default();
        meta.is_context = false;
        meta.field_type = Some(projected_ty);
        meta.root_ctx_field = record_field.root_ctx_field;
        meta.trusted_btf = base_trusted_btf
            && matches!(
                meta.field_type.as_ref(),
                Some(MirType::Ptr {
                    address_space: AddressSpace::Kernel,
                    ..
                })
            );
        meta.annotated_semantics = projected_semantics;
        meta.kernel_btf_field_addr = None;
        meta.source_var = None;
        self.set_reg_constant_value(src_dst, constant_value);
        Ok(())
    }

    /// Lower FollowCellPath instruction (context field access like $ctx.pid)
    pub(super) fn lower_follow_cell_path(
        &mut self,
        src_dst: RegId,
        path_reg: RegId,
    ) -> Result<(), CompileError> {
        let mut path = self
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

        let had_source_vreg = self.reg_map.contains_key(&src_dst.get());
        let source_dst_vreg = self.get_vreg(src_dst);

        let record_context_remaining_path = if !self.is_context_reg(src_dst) {
            match path.members.first() {
                Some(PathMember::String { val, .. }) => {
                    self.get_metadata(src_dst).and_then(|meta| {
                        meta.record_fields
                            .iter()
                            .any(|field| field.name == *val && field.is_context)
                            .then(|| CellPath {
                                members: path.members.iter().skip(1).cloned().collect(),
                            })
                    })
                }
                _ => None,
            }
        } else {
            None
        };
        if let Some(remaining_path) = record_context_remaining_path {
            let meta = self.get_or_create_metadata(src_dst);
            *meta = RegMetadata::default();
            meta.is_context = true;
            path = remaining_path;
            if path.members.is_empty() {
                return Ok(());
            }
        }

        if !self.is_context_reg(src_dst) {
            let numeric_list_field_projection = match path.members.first() {
                Some(PathMember::String { val, .. })
                    if matches!(path.members.as_slice(), [_, PathMember::Int { .. }]) =>
                {
                    self.get_metadata(src_dst).and_then(|meta| {
                        meta.record_fields
                            .iter()
                            .find(|field| {
                                field.name == *val
                                    && matches!(
                                        field.semantics,
                                        Some(AnnotatedValueSemantics::NumericList { .. })
                                    )
                            })
                            .cloned()
                    })
                }
                _ => None,
            };
            if let Some(record_field) = numeric_list_field_projection {
                let constant_value = self
                    .get_metadata(src_dst)
                    .and_then(|meta| meta.constant_value.as_ref())
                    .and_then(|value| Self::constant_follow_cell_path(value, &path));
                let remaining_members: Vec<PathMember> =
                    path.members.iter().skip(1).cloned().collect();
                return self.lower_record_field_projection_from_metadata(
                    src_dst,
                    source_dst_vreg,
                    had_source_vreg,
                    record_field,
                    &remaining_members,
                    &path.members,
                    constant_value,
                );
            }

            // Context-derived record fields keep their own pointer provenance; projecting
            // through the materialized record would make helper aliases target the stack.
            let record_field_projection = match path.members.first() {
                Some(PathMember::String { val, .. }) => {
                    self.get_metadata(src_dst).and_then(|meta| {
                        meta.record_fields
                            .iter()
                            .find(|field| field.name == *val && field.root_ctx_field.is_some())
                            .cloned()
                    })
                }
                _ => None,
            };
            if let Some(record_field) = record_field_projection {
                let constant_value = self
                    .get_metadata(src_dst)
                    .and_then(|meta| meta.constant_value.as_ref())
                    .and_then(|value| Self::constant_follow_cell_path(value, &path));
                let remaining_members: Vec<PathMember> =
                    path.members.iter().skip(1).cloned().collect();
                return self.lower_record_field_projection_from_metadata(
                    src_dst,
                    source_dst_vreg,
                    had_source_vreg,
                    record_field,
                    &remaining_members,
                    &path.members,
                    constant_value,
                );
            }
        }

        if !self.is_context_reg(src_dst) {
            let constant_value = self
                .get_metadata(src_dst)
                .and_then(|meta| meta.constant_value.as_ref())
                .and_then(|value| Self::constant_follow_cell_path(value, &path));
            let path_desc = Self::typed_value_path_desc(&path.members);
            let mut source_vreg = source_dst_vreg;
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
            let dst_vreg = if had_source_vreg {
                self.assign_fresh_vreg(src_dst)
            } else {
                source_dst_vreg
            };
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
            let root_ctx_field = self.get_metadata(src_dst).and_then(|meta| {
                path.members
                    .first()
                    .and_then(|member| match member {
                        PathMember::String { val, .. } => meta
                            .record_fields
                            .iter()
                            .find(|field| field.name == *val)
                            .and_then(|field| field.root_ctx_field.clone()),
                        _ => None,
                    })
                    .or_else(|| meta.root_ctx_field.clone())
            });
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
            let base_semantics = self
                .get_metadata(src_dst)
                .and_then(|meta| meta.annotated_semantics.clone());
            if self.lower_metadata_numeric_list_path_projection(
                src_dst,
                dst_vreg,
                base_vreg,
                &base_runtime_ty,
                &path.members,
                &path_desc,
                constant_value.clone(),
                root_ctx_field.as_ref(),
                base_trusted_btf,
                base_semantics.as_ref(),
            )? {
                return Ok(());
            }
            let projected_ty = self.lower_typed_value_projection(
                src_dst,
                dst_vreg,
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
            meta.record_fields.clear();
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
            meta.kernel_btf_field_addr = None;
            meta.source_var = None;
            self.set_reg_constant_value(src_dst, constant_value);
            return Ok(());
        }

        let dst_vreg = source_dst_vreg;

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
                meta.kernel_btf_field_addr = None;
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
                meta.kernel_btf_field_addr = None;
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
                meta.kernel_btf_field_addr = None;
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
            let kernel_btf_field_addr = self.lower_trampoline_field_projection(
                dst_vreg,
                &ctx_field,
                spec,
                &projection,
                &root_runtime_ty,
                &projected_ty,
                &path_desc,
            )?;

            let projected_ty = projected_ty.clone();
            let root_trusted_btf = ProbeContext::resolve_ctx_field_is_trusted_btf_kernel_pointer(
                self.probe_ctx,
                &ctx_field,
            );
            let meta = self.get_or_create_metadata(src_dst);
            meta.is_context = false;
            meta.field_type = Some(projected_ty);
            meta.root_ctx_field = Some(ctx_field.clone());
            meta.trusted_btf = root_trusted_btf
                && matches!(
                    spec.kind,
                    TrampolineValueKind::Pointer { user_space: false }
                )
                && matches!(
                    meta.field_type.as_ref(),
                    Some(MirType::Ptr {
                        address_space: AddressSpace::Kernel,
                        ..
                    })
                );
            meta.kernel_btf_field_addr = kernel_btf_field_addr;
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
        meta.kernel_btf_field_addr = None;
        meta.source_var = None;

        Ok(())
    }

    fn record_numeric_list_field_from_terminal_index(
        &mut self,
        field_name: String,
        index: usize,
        new_value: RegId,
        path_desc: &str,
    ) -> Result<RecordField, CompileError> {
        if index != 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' can only create a missing list field at index 0",
                path_desc
            )));
        }

        let new_value_vreg = self.get_vreg(new_value);
        let new_value_runtime_ty = self
            .typed_value_runtime_type(new_value, new_value_vreg)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' requires type information for the new list value",
                    path_desc
                ))
            })?;
        let Some(item_vreg) = self.coerce_scalar_assignment_value(
            new_value_vreg,
            &new_value_runtime_ty,
            &MirType::I64,
        ) else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' cannot create a numeric list from value type {:?}",
                path_desc, new_value_runtime_ty
            )));
        };

        let max_len = 1;
        let list_ty = MirType::Array {
            elem: Box::new(MirType::I64),
            len: max_len + 1,
        };
        let slot = self
            .func
            .alloc_stack_slot(list_ty.size(), 8, StackSlotKind::ListBuffer);
        self.record_list_buffer_slot_type(slot, max_len);

        let list_vreg = self.func.alloc_vreg();
        self.emit(MirInst::ListNew {
            dst: list_vreg,
            buffer: slot,
            max_len,
        });
        self.vreg_type_hints.insert(
            list_vreg,
            MirType::Ptr {
                pointee: Box::new(list_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );
        self.emit(MirInst::ListPush {
            list: list_vreg,
            item: item_vreg,
        });

        Ok(RecordField {
            name: field_name,
            value_vreg: list_vreg,
            source_reg: None,
            stack_offset: None,
            ty: list_ty,
            semantics: Some(AnnotatedValueSemantics::NumericList {
                max_len,
                known_len: Some(1),
            }),
            is_context: false,
            root_ctx_field: None,
        })
    }

    fn materialized_record_array_element_value(
        &mut self,
        new_value: RegId,
        path_desc: &str,
    ) -> Result<Option<(VReg, MirType, Option<AnnotatedValueSemantics>)>, CompileError> {
        let new_value_vreg = self.get_vreg(new_value);
        let should_materialize_record = self
            .get_metadata(new_value)
            .and_then(Self::metadata_record_layout)
            .is_some()
            || matches!(
                self.typed_value_runtime_type(new_value, new_value_vreg),
                Some(MirType::Ptr {
                    pointee,
                    address_space: AddressSpace::Stack | AddressSpace::Map,
                }) if matches!(pointee.as_ref(), MirType::Struct { .. })
            );
        if !should_materialize_record {
            return Ok(None);
        }

        let element_vreg = self.materialized_metadata_aggregate_vreg(new_value, new_value_vreg)?;
        let element_runtime_ty = self
            .vreg_type_hints
            .get(&element_vreg)
            .cloned()
            .or_else(|| self.typed_value_runtime_type(new_value, element_vreg))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' requires type information for the record list element",
                    path_desc
                ))
            })?;
        let MirType::Ptr {
            pointee,
            address_space: AddressSpace::Stack | AddressSpace::Map,
        } = element_runtime_ty
        else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' requires a materialized record value for the list element",
                path_desc
            )));
        };
        if !matches!(pointee.as_ref(), MirType::Struct { .. }) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' can only synthesize fixed record arrays from record values, got {:?}",
                path_desc, pointee
            )));
        }

        let semantics = self
            .get_metadata(new_value)
            .and_then(|meta| meta.annotated_semantics.clone());
        Ok(Some((element_vreg, pointee.as_ref().clone(), semantics)))
    }

    fn record_list_field_from_terminal_index(
        &mut self,
        field_name: String,
        index: usize,
        new_value: RegId,
        path_desc: &str,
    ) -> Result<RecordField, CompileError> {
        if index != 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' can only create a missing list field at index 0",
                path_desc
            )));
        }

        let Some((element_vreg, element_ty, element_semantics)) =
            self.materialized_record_array_element_value(new_value, path_desc)?
        else {
            return self.record_numeric_list_field_from_terminal_index(
                field_name, index, new_value, path_desc,
            );
        };

        let array_ty = MirType::Array {
            elem: Box::new(element_ty.clone()),
            len: 1,
        };
        let slot =
            self.func
                .alloc_stack_slot(align_to_eight(array_ty.size()), 8, StackSlotKind::Local);
        self.record_stack_slot_type(slot, array_ty.clone());

        let array_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: array_vreg,
            src: MirValue::StackSlot(slot),
        });
        self.vreg_type_hints.insert(
            array_vreg,
            MirType::Ptr {
                pointee: Box::new(array_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );
        self.emit_ptr_copy_with_offsets(array_vreg, 0, element_vreg, 0, element_ty.size())?;

        Ok(RecordField {
            name: field_name,
            value_vreg: array_vreg,
            source_reg: None,
            stack_offset: None,
            ty: array_ty,
            semantics: element_semantics.map(|elem| AnnotatedValueSemantics::FixedArray {
                elem: Box::new(elem),
                len: 1,
            }),
            is_context: false,
            root_ctx_field: None,
        })
    }

    fn record_fixed_record_array_field_from_index_path(
        &mut self,
        field_name: String,
        index: usize,
        tail: &[PathMember],
        new_value: RegId,
        path_desc: &str,
    ) -> Result<RecordField, CompileError> {
        if index != 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' can only create a missing list field at index 0",
                path_desc
            )));
        }
        let Some((PathMember::String { val, .. }, element_tail)) = tail.split_first() else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' can only synthesize list-of-record fields when the index is followed by a record field",
                path_desc
            )));
        };

        let element_field =
            self.record_field_from_path_members(val.clone(), element_tail, new_value, path_desc)?;
        let mut element_meta = RegMetadata {
            record_fields: vec![element_field],
            ..Default::default()
        };
        let element_ty = Self::metadata_record_layout(&element_meta).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' could not infer synthesized list element layout",
                path_desc
            ))
        })?;
        element_meta.field_type = Some(element_ty.clone());
        element_meta.annotated_semantics = Self::metadata_record_semantics(&element_meta);
        let (element_vreg, materialized_element_meta) = self
            .materialize_metadata_record_value(&element_meta)?
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' could not materialize synthesized list element",
                    path_desc
                ))
            })?;

        let array_ty = MirType::Array {
            elem: Box::new(element_ty.clone()),
            len: 1,
        };
        let slot =
            self.func
                .alloc_stack_slot(align_to_eight(array_ty.size()), 8, StackSlotKind::Local);
        self.record_stack_slot_type(slot, array_ty.clone());

        let array_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: array_vreg,
            src: MirValue::StackSlot(slot),
        });
        self.vreg_type_hints.insert(
            array_vreg,
            MirType::Ptr {
                pointee: Box::new(array_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );
        self.emit_ptr_copy_with_offsets(array_vreg, 0, element_vreg, 0, element_ty.size())?;

        let semantics = materialized_element_meta.annotated_semantics.map(|elem| {
            AnnotatedValueSemantics::FixedArray {
                elem: Box::new(elem),
                len: 1,
            }
        });

        Ok(RecordField {
            name: field_name,
            value_vreg: array_vreg,
            source_reg: None,
            stack_offset: None,
            ty: array_ty,
            semantics,
            is_context: false,
            root_ctx_field: None,
        })
    }

    fn fixed_array_element_record_semantics(
        record_field: &RecordField,
    ) -> Vec<(String, AnnotatedValueSemantics)> {
        let Some(AnnotatedValueSemantics::FixedArray { elem, .. }) = record_field.semantics.clone()
        else {
            return Vec::new();
        };
        let AnnotatedValueSemantics::Record(fields) = *elem else {
            return Vec::new();
        };
        fields
    }

    fn record_field_from_existing_fixed_array_element_field(
        &mut self,
        array_vreg: VReg,
        element_offset: usize,
        layout_field: &StructField,
        element_semantics: &[(String, AnnotatedValueSemantics)],
        path_desc: &str,
    ) -> Result<RecordField, CompileError> {
        if layout_field.synthetic {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' cannot preserve synthetic fixed-array element field '{}'",
                path_desc, layout_field.name
            )));
        }
        if layout_field.bitfield.is_some() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' cannot preserve bitfield fixed-array element field '{}'",
                path_desc, layout_field.name
            )));
        }
        if !layout_field.ty.is_scalar_like() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' can only expand synthesized fixed record arrays with scalar existing fields; field '{}' has type {:?}",
                path_desc, layout_field.name, layout_field.ty
            )));
        }

        let value_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Load {
            dst: value_vreg,
            ptr: array_vreg,
            offset: (element_offset + layout_field.offset) as i32,
            ty: layout_field.ty.clone(),
        });
        self.vreg_type_hints
            .insert(value_vreg, layout_field.ty.clone());

        Ok(RecordField {
            name: layout_field.name.clone(),
            value_vreg,
            source_reg: None,
            stack_offset: None,
            ty: layout_field.ty.clone(),
            semantics: element_semantics.iter().find_map(|(name, semantics)| {
                (name == &layout_field.name).then_some(semantics.clone())
            }),
            is_context: false,
            root_ctx_field: None,
        })
    }

    fn replace_metadata_record_field(
        &mut self,
        src_dst: RegId,
        field_index: usize,
        updated_field: RecordField,
        constant_value: Option<Value>,
        path_desc: &str,
        base_is_materialized_aggregate: bool,
        action: &str,
    ) -> Result<(), CompileError> {
        let meta = self.get_or_create_metadata(src_dst);
        meta.record_fields[field_index] = updated_field;
        meta.field_type = Self::metadata_record_layout(meta);
        meta.annotated_semantics = Self::metadata_record_semantics(meta);
        meta.constant_value = constant_value.clone();
        meta.source_var = None;
        self.set_reg_constant_value(src_dst, constant_value);

        if base_is_materialized_aggregate {
            let updated_meta = self.get_metadata(src_dst).cloned().ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' lost {} record metadata",
                    path_desc, action
                ))
            })?;
            let (materialized_vreg, materialized_meta) = self
                .materialize_metadata_record_value(&updated_meta)?
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "cell path update '.{} = ...' could not materialize {} record",
                        path_desc, action
                    ))
                })?;
            self.reg_map.insert(src_dst.get(), materialized_vreg);
            self.reg_metadata.insert(src_dst.get(), materialized_meta);
        }

        Ok(())
    }

    fn replace_fixed_record_array_with_appended_element(
        &mut self,
        src_dst: RegId,
        field_index: usize,
        existing_field: RecordField,
        elem_ty: MirType,
        len: usize,
        element_vreg: VReg,
        element_semantics: Option<AnnotatedValueSemantics>,
        constant_value: Option<Value>,
        path_desc: &str,
        base_is_materialized_aggregate: bool,
    ) -> Result<bool, CompileError> {
        let new_len = len.checked_add(1).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' fixed-array length overflowed",
                path_desc
            ))
        })?;
        let array_ty = MirType::Array {
            elem: Box::new(elem_ty.clone()),
            len: new_len,
        };
        let slot =
            self.func
                .alloc_stack_slot(align_to_eight(array_ty.size()), 8, StackSlotKind::Local);
        self.record_stack_slot_type(slot, array_ty.clone());

        let array_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: array_vreg,
            src: MirValue::StackSlot(slot),
        });
        self.vreg_type_hints.insert(
            array_vreg,
            MirType::Ptr {
                pointee: Box::new(array_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );
        self.emit_ptr_copy_with_offsets(
            array_vreg,
            0,
            existing_field.value_vreg,
            0,
            existing_field.ty.size(),
        )?;
        self.emit_ptr_copy_with_offsets(
            array_vreg,
            len * elem_ty.size(),
            element_vreg,
            0,
            elem_ty.size(),
        )?;

        let semantics = match existing_field.semantics.clone() {
            Some(AnnotatedValueSemantics::FixedArray { elem, .. }) => {
                Some(AnnotatedValueSemantics::FixedArray { elem, len: new_len })
            }
            _ => element_semantics.map(|elem| AnnotatedValueSemantics::FixedArray {
                elem: Box::new(elem),
                len: new_len,
            }),
        };
        let updated_field = RecordField {
            name: existing_field.name,
            value_vreg: array_vreg,
            source_reg: None,
            stack_offset: existing_field.stack_offset,
            ty: array_ty,
            semantics,
            is_context: false,
            root_ctx_field: None,
        };

        self.replace_metadata_record_field(
            src_dst,
            field_index,
            updated_field,
            constant_value,
            path_desc,
            base_is_materialized_aggregate,
            "appended",
        )?;
        Ok(true)
    }

    fn lower_metadata_fixed_record_array_append_value(
        &mut self,
        src_dst: RegId,
        field_index: usize,
        existing_field: RecordField,
        elem_ty: MirType,
        len: usize,
        new_value: RegId,
        constant_value: Option<Value>,
        path_desc: &str,
        base_is_materialized_aggregate: bool,
    ) -> Result<bool, CompileError> {
        let Some((element_vreg, new_element_ty, element_semantics)) =
            self.materialized_record_array_element_value(new_value, path_desc)?
        else {
            return Ok(false);
        };

        if new_element_ty != elem_ty {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' can only append homogeneous fixed record array elements; appended element layout {:?} does not match existing layout {:?}",
                path_desc, new_element_ty, elem_ty
            )));
        }

        self.replace_fixed_record_array_with_appended_element(
            src_dst,
            field_index,
            existing_field,
            elem_ty,
            len,
            element_vreg,
            element_semantics,
            constant_value,
            path_desc,
            base_is_materialized_aggregate,
        )
    }

    fn lower_metadata_fixed_record_array_append_path(
        &mut self,
        src_dst: RegId,
        field_index: usize,
        existing_field: RecordField,
        elem_ty: MirType,
        len: usize,
        path_members: &[PathMember],
        new_value: RegId,
        constant_value: Option<Value>,
        path_desc: &str,
        base_is_materialized_aggregate: bool,
    ) -> Result<bool, CompileError> {
        let Some(PathMember::String {
            val: new_field_name,
            ..
        }) = path_members.get(2)
        else {
            return Ok(false);
        };

        let new_element_field = self.record_field_from_path_members(
            new_field_name.clone(),
            &path_members[3..],
            new_value,
            path_desc,
        )?;
        let mut element_meta = RegMetadata {
            record_fields: vec![new_element_field],
            ..Default::default()
        };
        let new_element_ty = Self::metadata_record_layout(&element_meta).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' could not infer appended fixed-array element layout",
                path_desc
            ))
        })?;

        if new_element_ty != elem_ty {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' can only append homogeneous fixed record array elements; appended element layout {:?} does not match existing layout {:?}",
                path_desc, new_element_ty, elem_ty
            )));
        }

        element_meta.field_type = Some(new_element_ty.clone());
        element_meta.annotated_semantics = Self::metadata_record_semantics(&element_meta);
        let (element_vreg, materialized_element_meta) = self
            .materialize_metadata_record_value(&element_meta)?
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' could not materialize appended fixed-array element",
                    path_desc
                ))
            })?;

        self.replace_fixed_record_array_with_appended_element(
            src_dst,
            field_index,
            existing_field,
            elem_ty,
            len,
            element_vreg,
            materialized_element_meta.annotated_semantics,
            constant_value,
            path_desc,
            base_is_materialized_aggregate,
        )
    }

    fn lower_metadata_existing_fixed_record_array_path_creation(
        &mut self,
        src_dst: RegId,
        field_index: usize,
        path_members: &[PathMember],
        new_value: RegId,
        constant_value: Option<Value>,
        path_desc: &str,
        base_is_materialized_aggregate: bool,
    ) -> Result<bool, CompileError> {
        let [
            PathMember::String { .. },
            PathMember::Int {
                val: element_index, ..
            },
            tail @ ..,
        ] = path_members
        else {
            return Ok(false);
        };

        let Some(existing_field) = self
            .get_metadata(src_dst)
            .and_then(|meta| meta.record_fields.get(field_index))
            .cloned()
        else {
            return Ok(false);
        };
        let MirType::Array { elem, len } = &existing_field.ty else {
            return Ok(false);
        };
        let elem_ty = elem.as_ref().clone();
        let len = *len;

        if *element_index == len {
            if tail.is_empty() {
                return self.lower_metadata_fixed_record_array_append_value(
                    src_dst,
                    field_index,
                    existing_field,
                    elem_ty,
                    len,
                    new_value,
                    constant_value,
                    path_desc,
                    base_is_materialized_aggregate,
                );
            }
            if matches!(tail.first(), Some(PathMember::String { .. })) {
                return self.lower_metadata_fixed_record_array_append_path(
                    src_dst,
                    field_index,
                    existing_field,
                    elem_ty,
                    len,
                    path_members,
                    new_value,
                    constant_value,
                    path_desc,
                    base_is_materialized_aggregate,
                );
            }
            return Ok(false);
        }

        let MirType::Struct { fields, .. } = &elem_ty else {
            return Ok(false);
        };

        let Some(PathMember::String {
            val: new_field_name,
            ..
        }) = tail.first()
        else {
            return Ok(false);
        };

        if len != 1 || *element_index != 0 {
            return Ok(false);
        }
        let new_field_exists = fields
            .iter()
            .any(|field| !field.synthetic && field.name == *new_field_name);
        if new_field_exists {
            return Ok(false);
        }

        let element_offset = elem.size() * *element_index;
        let element_semantics = Self::fixed_array_element_record_semantics(&existing_field);
        let mut element_fields = Vec::new();
        for layout_field in fields.iter().filter(|field| !field.synthetic) {
            element_fields.push(self.record_field_from_existing_fixed_array_element_field(
                existing_field.value_vreg,
                element_offset,
                layout_field,
                &element_semantics,
                path_desc,
            )?);
        }

        let new_field = self.record_field_from_path_members(
            new_field_name.clone(),
            &tail[1..],
            new_value,
            path_desc,
        )?;
        element_fields.push(new_field);

        let mut element_meta = RegMetadata {
            record_fields: element_fields,
            ..Default::default()
        };
        let element_ty = Self::metadata_record_layout(&element_meta).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' could not infer expanded fixed-array element layout",
                path_desc
            ))
        })?;
        element_meta.field_type = Some(element_ty.clone());
        element_meta.annotated_semantics = Self::metadata_record_semantics(&element_meta);
        let (element_vreg, materialized_element_meta) = self
            .materialize_metadata_record_value(&element_meta)?
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' could not materialize expanded fixed-array element",
                    path_desc
                ))
            })?;

        let array_ty = MirType::Array {
            elem: Box::new(element_ty.clone()),
            len,
        };
        let slot =
            self.func
                .alloc_stack_slot(align_to_eight(array_ty.size()), 8, StackSlotKind::Local);
        self.record_stack_slot_type(slot, array_ty.clone());
        let array_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: array_vreg,
            src: MirValue::StackSlot(slot),
        });
        self.vreg_type_hints.insert(
            array_vreg,
            MirType::Ptr {
                pointee: Box::new(array_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );
        self.emit_ptr_copy_with_offsets(array_vreg, 0, element_vreg, 0, element_ty.size())?;

        let semantics = materialized_element_meta.annotated_semantics.map(|elem| {
            AnnotatedValueSemantics::FixedArray {
                elem: Box::new(elem),
                len,
            }
        });
        let updated_field = RecordField {
            name: existing_field.name,
            value_vreg: array_vreg,
            source_reg: None,
            stack_offset: existing_field.stack_offset,
            ty: array_ty,
            semantics,
            is_context: false,
            root_ctx_field: None,
        };

        self.replace_metadata_record_field(
            src_dst,
            field_index,
            updated_field,
            constant_value,
            path_desc,
            base_is_materialized_aggregate,
            "expanded",
        )?;
        Ok(true)
    }

    fn record_field_from_path_members(
        &mut self,
        field_name: String,
        rest: &[PathMember],
        new_value: RegId,
        path_desc: &str,
    ) -> Result<RecordField, CompileError> {
        let Some((next_member, tail)) = rest.split_first() else {
            return self.record_field_from_value(field_name, new_value);
        };

        let PathMember::String {
            val: child_field_name,
            ..
        } = next_member
        else {
            return match next_member {
                PathMember::Int { val, .. } if tail.is_empty() => self
                    .record_list_field_from_terminal_index(field_name, *val, new_value, path_desc),
                PathMember::Int { val, .. } => self
                    .record_fixed_record_array_field_from_index_path(
                        field_name, *val, tail, new_value, path_desc,
                    ),
                PathMember::String { .. } => unreachable!(),
            };
        };

        let child_field = self.record_field_from_path_members(
            child_field_name.clone(),
            tail,
            new_value,
            path_desc,
        )?;

        let mut child_meta = RegMetadata {
            record_fields: vec![child_field],
            ..Default::default()
        };
        let child_ty = Self::metadata_record_layout(&child_meta).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' could not infer nested record layout",
                path_desc
            ))
        })?;
        child_meta.field_type = Some(child_ty.clone());
        child_meta.annotated_semantics = Self::metadata_record_semantics(&child_meta);
        let (child_vreg, materialized_meta) = self
            .materialize_metadata_record_value(&child_meta)?
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' could not materialize nested record",
                    path_desc
                ))
            })?;

        Ok(RecordField {
            name: field_name,
            value_vreg: child_vreg,
            source_reg: None,
            stack_offset: None,
            ty: child_ty,
            semantics: materialized_meta.annotated_semantics,
            is_context: false,
            root_ctx_field: None,
        })
    }

    fn lower_metadata_record_path_creation(
        &mut self,
        src_dst: RegId,
        path_members: &[PathMember],
        new_value: RegId,
        constant_value: Option<Value>,
    ) -> Result<bool, CompileError> {
        if path_members.len() < 2 {
            return Ok(false);
        }
        let Some(PathMember::String {
            val: first_field, ..
        }) = path_members.first()
        else {
            return Ok(false);
        };

        let Some(base_meta) = self.get_metadata(src_dst).cloned() else {
            return Ok(false);
        };
        if base_meta.record_fields.is_empty()
            && !matches!(
                base_meta.constant_value.as_ref(),
                Some(Value::Record { .. })
            )
        {
            return Ok(false);
        }

        let base_vreg = self.get_vreg(src_dst);
        let base_is_materialized_aggregate = matches!(
            self.typed_value_runtime_type(src_dst, base_vreg),
            Some(MirType::Ptr {
                address_space: AddressSpace::Stack | AddressSpace::Map,
                ..
            })
        );

        let existing_index = base_meta
            .record_fields
            .iter()
            .position(|field| field.name == *first_field);
        let first_field_missing = existing_index.is_none();
        let first_field_empty_record = existing_index.is_some()
            && Self::metadata_field_is_empty_record(&base_meta, first_field);
        if !first_field_missing && !first_field_empty_record {
            let path_desc = Self::typed_value_path_desc(path_members);
            if self.lower_metadata_existing_numeric_list_path_update(
                src_dst,
                existing_index.expect("existing index checked above"),
                path_members,
                new_value,
                constant_value.clone(),
                &path_desc,
                base_is_materialized_aggregate,
            )? {
                return Ok(true);
            }
            if self.lower_metadata_existing_fixed_record_array_path_creation(
                src_dst,
                existing_index.expect("existing index checked above"),
                path_members,
                new_value,
                constant_value,
                &path_desc,
                base_is_materialized_aggregate,
            )? {
                return Ok(true);
            }
            return Ok(false);
        }

        if base_is_materialized_aggregate {
            return Ok(false);
        }

        let path_desc = Self::typed_value_path_desc(path_members);
        let field = self.record_field_from_path_members(
            first_field.clone(),
            &path_members[1..],
            new_value,
            &path_desc,
        )?;
        let meta = self.get_or_create_metadata(src_dst);
        if let Some(index) = existing_index {
            meta.record_fields[index] = field;
        } else {
            meta.record_fields.push(field);
        }
        meta.field_type = Self::metadata_record_layout(meta);
        meta.annotated_semantics = Self::metadata_record_semantics(meta);
        meta.constant_value = constant_value.clone();
        meta.source_var = None;
        self.set_reg_constant_value(src_dst, constant_value);
        Ok(true)
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
        if let [
            PathMember::String {
                val: field_name, ..
            },
        ] = path.members.as_slice()
            && let Some(new_value_meta) = self.get_metadata(new_value).cloned()
            && (new_value_meta.is_context || new_value_meta.root_ctx_field.is_some())
        {
            let new_value_vreg = if new_value_meta.is_context && self.ctx_param.is_some() {
                self.materialize_context_pointer_arg()
            } else {
                self.get_vreg(new_value)
            };
            let Some(base_meta) = self.get_metadata(src_dst).cloned() else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' requires compiler-known record metadata for context-backed values",
                    path_desc
                )));
            };
            let existing_field = base_meta
                .record_fields
                .iter()
                .find(|field| field.name == *field_name)
                .cloned();
            let field_type = new_value_meta
                .field_type
                .clone()
                .or_else(|| Self::metadata_record_layout(&new_value_meta))
                .or_else(|| self.vreg_type_hints.get(&new_value_vreg).cloned())
                .or_else(|| existing_field.as_ref().map(|field| field.ty.clone()))
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "cell path update '.{} = ...' requires type information for the context-backed value",
                        path_desc
                    ))
                })?;

            let field = RecordField {
                name: field_name.clone(),
                value_vreg: new_value_vreg,
                source_reg: Some(new_value),
                stack_offset: existing_field.and_then(|field| field.stack_offset),
                ty: field_type,
                semantics: new_value_meta.annotated_semantics.clone(),
                is_context: new_value_meta.is_context,
                root_ctx_field: new_value_meta.root_ctx_field.clone(),
            };
            let meta = self.get_or_create_metadata(src_dst);
            if let Some(existing) = meta
                .record_fields
                .iter_mut()
                .find(|existing| existing.name == *field_name)
            {
                *existing = field;
            } else {
                meta.record_fields.push(field);
            }
            meta.field_type = Self::metadata_record_layout(meta);
            meta.annotated_semantics = Self::metadata_record_semantics(meta);
            meta.constant_value = None;
            meta.source_var = None;
            return Ok(());
        }

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

        if self.lower_metadata_record_path_creation(
            src_dst,
            &path.members,
            new_value,
            constant_value.clone(),
        )? {
            return Ok(());
        }

        if let [
            PathMember::String {
                val: field_name, ..
            },
        ] = path.members.as_slice()
            && let Some(base_meta) = self.get_metadata(src_dst).cloned()
            && (!base_meta.record_fields.is_empty()
                || matches!(
                    base_meta.constant_value.as_ref(),
                    Some(Value::Record { .. })
                ))
            && !base_meta
                .record_fields
                .iter()
                .any(|field| field.name == *field_name)
        {
            let base_vreg = self.get_vreg(src_dst);
            let base_is_materialized_aggregate = matches!(
                self.typed_value_runtime_type(src_dst, base_vreg),
                Some(MirType::Ptr {
                    address_space: AddressSpace::Stack | AddressSpace::Map,
                    ..
                })
            );
            if !base_is_materialized_aggregate {
                let field = self.record_field_from_value(field_name.clone(), new_value)?;
                let meta = self.get_or_create_metadata(src_dst);
                if let Some(existing) = meta
                    .record_fields
                    .iter_mut()
                    .find(|existing| existing.name == *field_name)
                {
                    *existing = field;
                } else {
                    meta.record_fields.push(field);
                }
                meta.field_type = Self::metadata_record_layout(meta);
                meta.annotated_semantics = Self::metadata_record_semantics(meta);
                meta.constant_value = constant_value.clone();
                meta.source_var = None;
                self.set_reg_constant_value(src_dst, constant_value);
                return Ok(());
            }
        }

        if let Some(record_field) = self.get_metadata(src_dst).and_then(|meta| {
            path.members.first().and_then(|member| match member {
                PathMember::String { val, .. } => meta
                    .record_fields
                    .iter()
                    .find(|field| field.name == *val && field.root_ctx_field.is_some())
                    .cloned(),
                _ => None,
            })
        }) {
            let tail: Vec<PathMember> = path.members.iter().skip(1).cloned().collect();
            match (&record_field.ty, record_field.root_ctx_field.clone()) {
                (
                    MirType::Ptr {
                        pointee,
                        address_space: AddressSpace::Context,
                    },
                    Some(CtxField::FlowKeys),
                ) => {
                    self.lower_context_pointer_scalar_update(
                        record_field.value_vreg,
                        pointee.as_ref(),
                        &tail,
                        new_value,
                        &path_desc,
                    )?;
                    self.set_reg_constant_value(src_dst, constant_value);
                    return Ok(());
                }
                (
                    MirType::Ptr {
                        address_space: AddressSpace::Packet,
                        ..
                    },
                    Some(root_field @ (CtxField::Data | CtxField::DataMeta)),
                ) => {
                    self.lower_packet_ctx_update_from_ptr(
                        record_field.value_vreg,
                        root_field,
                        &tail,
                        new_value,
                        &path_desc,
                    )?;
                    self.set_reg_constant_value(src_dst, constant_value);
                    return Ok(());
                }
                (
                    MirType::Ptr {
                        address_space: AddressSpace::Kernel,
                        ..
                    },
                    Some(CtxField::SockoptOptval),
                ) => {
                    let [PathMember::Int { val: index, .. }] = tail.as_slice() else {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "cell path update '.{} = ...' for a ctx.optval alias requires a fixed integer byte index, e.g. $ctx.optval.N = ...",
                            path_desc
                        )));
                    };
                    let index = usize::try_from(*index).map_err(|_| {
                        CompileError::UnsupportedInstruction(format!(
                            "cell path update '.{} = ...' requires a non-negative ctx.optval byte index",
                            path_desc
                        ))
                    })?;
                    self.lower_cgroup_sockopt_optval_byte_update_from_ptr(
                        record_field.value_vreg,
                        index,
                        new_value,
                        &path_desc,
                    )?;
                    self.set_reg_constant_value(src_dst, constant_value);
                    return Ok(());
                }
                _ => {}
            }
        }

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
        let root_ctx_field = self
            .get_metadata(src_dst)
            .and_then(|meta| meta.root_ctx_field.clone());
        if let MirType::Ptr {
            pointee,
            address_space: AddressSpace::Context,
        } = &base_runtime_ty
        {
            if root_ctx_field == Some(CtxField::FlowKeys) {
                self.lower_context_pointer_scalar_update(
                    base_vreg,
                    pointee.as_ref(),
                    &path.members,
                    new_value,
                    &path_desc,
                )?;
                let meta = self.get_or_create_metadata(src_dst);
                meta.field_type = Some(pointee.as_ref().clone());
                meta.kernel_btf_field_addr = None;
                meta.source_var = None;
                self.set_reg_constant_value(src_dst, constant_value);
                return Ok(());
            }

            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' only supports writable context pointers rooted at ctx.flow_keys",
                path_desc
            )));
        }
        if let MirType::Ptr {
            address_space: AddressSpace::Packet,
            ..
        } = &base_runtime_ty
        {
            let Some(root_field @ (CtxField::Data | CtxField::DataMeta)) = root_ctx_field else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' requires a packet pointer rooted at ctx.data or ctx.data_meta",
                    path_desc
                )));
            };
            self.lower_packet_ctx_update_from_ptr(
                base_vreg,
                root_field,
                &path.members,
                new_value,
                &path_desc,
            )?;
            self.set_reg_constant_value(src_dst, constant_value);
            return Ok(());
        }
        if let MirType::Ptr {
            address_space: AddressSpace::Kernel,
            ..
        } = &base_runtime_ty
            && root_ctx_field == Some(CtxField::SockoptOptval)
        {
            let [PathMember::Int { val: index, .. }] = path.members.as_slice() else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' for a ctx.optval alias requires a fixed integer byte index, e.g. $ctx.optval.N = ...",
                    path_desc
                )));
            };
            let index = usize::try_from(*index).map_err(|_| {
                CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' requires a non-negative ctx.optval byte index",
                    path_desc
                ))
            })?;
            self.lower_cgroup_sockopt_optval_byte_update_from_ptr(
                base_vreg, index, new_value, &path_desc,
            )?;
            self.set_reg_constant_value(src_dst, constant_value);
            return Ok(());
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

        if self.lower_materialized_numeric_list_path_update(
            src_dst,
            base_vreg,
            pointee.as_ref(),
            &path.members,
            new_value,
            constant_value.clone(),
            &path_desc,
        )? {
            return Ok(());
        }

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
        meta.kernel_btf_field_addr = None;
        meta.source_var = None;
        self.set_reg_constant_value(src_dst, constant_value);
        Ok(())
    }
}
