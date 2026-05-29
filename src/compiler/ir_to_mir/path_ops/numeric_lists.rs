use super::super::*;
use crate::compiler::mir::AddressSpace;

impl<'a> HirToMirLowering<'a> {
    fn metadata_record_numeric_list_len(meta: &RegMetadata, field_name: &str) -> Option<usize> {
        let Some(Value::Record { val: record, .. }) = meta.constant_value.as_ref() else {
            return None;
        };
        let Some(Value::List { vals, .. }) = record.get(field_name) else {
            return None;
        };
        Some(vals.len())
    }

    fn numeric_list_index_path(path_members: &[PathMember]) -> Option<(&[PathMember], usize)> {
        let (PathMember::Int { val: index, .. }, list_path) = path_members.split_last()? else {
            return None;
        };
        Some((list_path, *index))
    }

    fn numeric_list_semantics_at_path(
        semantics: Option<&AnnotatedValueSemantics>,
        list_path: &[PathMember],
    ) -> Option<(usize, Option<usize>)> {
        let AnnotatedValueSemantics::NumericList { max_len, known_len } =
            Self::project_annotated_value_semantics(semantics?, list_path)?
        else {
            return None;
        };
        Some((max_len, known_len))
    }

    fn constant_numeric_list_len_at_path(value: &Value, list_path: &[PathMember]) -> Option<usize> {
        let list_path = CellPath {
            members: list_path.to_vec(),
        };
        let Value::List { vals, .. } = Self::constant_follow_cell_path(value, &list_path)? else {
            return None;
        };
        Some(vals.len())
    }

    fn materialize_constant_record_stack_value(
        &mut self,
        dst_reg: RegId,
        record: &nu_protocol::Record,
        path_desc: &str,
    ) -> Result<
        (
            VReg,
            MirType,
            Vec<RecordField>,
            Option<AnnotatedValueSemantics>,
        ),
        CompileError,
    > {
        let (record_ty, data) = Self::constant_record_rodata_repr(record)?;
        let symbol = self.alloc_readonly_global_name();
        self.readonly_globals.push(ReadonlyGlobal {
            name: symbol.clone(),
            data,
        });

        let global_vreg = self.func.alloc_vreg();
        self.emit(MirInst::LoadGlobal {
            dst: global_vreg,
            symbol,
            ty: record_ty.clone(),
        });
        self.vreg_type_hints.insert(
            global_vreg,
            MirType::Ptr {
                pointee: Box::new(record_ty.clone()),
                address_space: AddressSpace::Map,
            },
        );

        let slot =
            self.func
                .alloc_stack_slot(align_to_eight(record_ty.size()), 8, StackSlotKind::Local);
        self.record_stack_slot_type(slot, record_ty.clone());
        let record_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: record_vreg,
            src: MirValue::StackSlot(slot),
        });
        let base_runtime_ty = MirType::Ptr {
            pointee: Box::new(record_ty.clone()),
            address_space: AddressSpace::Stack,
        };
        self.vreg_type_hints
            .insert(record_vreg, base_runtime_ty.clone());
        self.emit_ptr_to_slot_copy(slot, 0, global_vreg, 0, record_ty.size())?;

        let MirType::Struct { fields, .. } = &record_ty else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' rebuilt record constant did not produce a struct layout",
                path_desc
            )));
        };

        let mut record_fields = Vec::new();
        for layout_field in fields.iter().filter(|field| !field.synthetic) {
            let field_value = record.get(&layout_field.name).ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' rebuilt record is missing field '{}'",
                    path_desc, layout_field.name
                ))
            })?;
            let field_semantics = Self::mutable_global_value_semantics(field_value)?;
            let field_vreg = self.func.alloc_vreg();
            let path = vec![PathMember::string(
                layout_field.name.clone(),
                false,
                Casing::Sensitive,
                Span::unknown(),
            )];
            let field_ty = self.lower_typed_value_projection(
                dst_reg,
                field_vreg,
                record_vreg,
                &base_runtime_ty,
                &path,
                &layout_field.name,
                None,
                false,
                field_semantics.as_ref(),
            )?;
            record_fields.push(RecordField {
                name: layout_field.name.clone(),
                value_vreg: field_vreg,
                source_reg: None,
                stack_offset: None,
                ty: field_ty,
                semantics: field_semantics,
                is_context: false,
                root_ctx_field: None,
            });
        }

        let semantics =
            Self::mutable_global_value_semantics(&Value::record(record.clone(), Span::unknown()))?;
        Ok((record_vreg, record_ty, record_fields, semantics))
    }

    pub(super) fn lower_metadata_numeric_list_path_projection(
        &mut self,
        dst_reg: RegId,
        dst_vreg: VReg,
        base_vreg: VReg,
        base_runtime_ty: &MirType,
        path_members: &[PathMember],
        path_desc: &str,
        constant_value: Option<Value>,
        root_ctx_field: Option<&CtxField>,
        trusted_btf: bool,
        base_semantics: Option<&AnnotatedValueSemantics>,
    ) -> Result<bool, CompileError> {
        let Some((list_path, index)) = Self::numeric_list_index_path(path_members) else {
            return Ok(false);
        };
        let Some((max_len, known_len)) =
            Self::numeric_list_semantics_at_path(base_semantics, list_path)
        else {
            return Ok(false);
        };
        if index >= max_len {
            return Err(CompileError::UnsupportedInstruction(format!(
                "typed field path '{}' index {} is out of bounds for numeric list capacity {}",
                path_desc, index, max_len
            )));
        }

        let list_vreg = if list_path.is_empty() {
            let MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack,
            } = base_runtime_ty
            else {
                return Ok(false);
            };
            if !matches!(pointee.as_ref(), MirType::Array { .. }) {
                return Ok(false);
            }
            base_vreg
        } else {
            let list_vreg = self.func.alloc_vreg();
            let list_path_desc = Self::typed_value_path_desc(list_path);
            let list_semantics = AnnotatedValueSemantics::NumericList { max_len, known_len };
            self.lower_typed_value_projection(
                dst_reg,
                list_vreg,
                base_vreg,
                base_runtime_ty,
                list_path,
                &list_path_desc,
                root_ctx_field,
                trusted_btf,
                Some(&list_semantics),
            )?;
            list_vreg
        };
        self.emit(MirInst::ListGet {
            dst: dst_vreg,
            list: list_vreg,
            idx: MirValue::Const(i64::try_from(index).map_err(|_| {
                CompileError::UnsupportedInstruction(format!(
                    "typed field path '{}' numeric list index {} is too large",
                    path_desc, index
                ))
            })?),
        });
        self.vreg_type_hints.insert(dst_vreg, MirType::I64);
        let meta = self.get_or_create_metadata(dst_reg);
        *meta = RegMetadata::default();
        meta.field_type = Some(MirType::I64);
        meta.source_var = None;
        self.set_reg_constant_value(dst_reg, constant_value);
        Ok(true)
    }

    pub(super) fn lower_materialized_numeric_list_path_update(
        &mut self,
        src_dst: RegId,
        base_vreg: VReg,
        pointee_ty: &MirType,
        path_members: &[PathMember],
        new_value: RegId,
        constant_value: Option<Value>,
        path_desc: &str,
    ) -> Result<bool, CompileError> {
        let Some((list_path, index)) = Self::numeric_list_index_path(path_members) else {
            return Ok(false);
        };
        let Some(base_meta) = self.get_metadata(src_dst).cloned() else {
            return Ok(false);
        };
        let Some((max_len, known_len)) =
            Self::numeric_list_semantics_at_path(base_meta.annotated_semantics.as_ref(), list_path)
        else {
            return Ok(false);
        };
        let current_len = base_meta
            .constant_value
            .as_ref()
            .and_then(|value| Self::constant_numeric_list_len_at_path(value, list_path))
            .or(known_len)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' requires compile-time numeric list length metadata",
                    path_desc
                ))
            })?;
        if index > current_len {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' can only update an existing numeric list item or append at the next index",
                path_desc
            )));
        }

        if index == current_len && current_len == max_len {
            if list_path.is_empty() {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' cannot append beyond numeric list capacity {}",
                    path_desc, max_len
                )));
            }
            let Some(Value::Record { val: record, .. }) = constant_value.as_ref() else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' requires updated constant record metadata to grow a nested numeric list",
                    path_desc
                )));
            };
            let (record_vreg, record_ty, record_fields, semantics) =
                self.materialize_constant_record_stack_value(src_dst, record.as_ref(), path_desc)?;
            self.reg_map.insert(src_dst.get(), record_vreg);
            let meta = self.get_or_create_metadata(src_dst);
            meta.is_context = false;
            meta.record_fields = record_fields;
            meta.field_type = Some(record_ty);
            meta.annotated_semantics = semantics;
            meta.constant_value = constant_value.clone();
            meta.root_ctx_field = None;
            meta.direct_ctx_field = None;
            meta.kernel_btf_field_addr = None;
            meta.source_var = None;
            self.set_reg_constant_value(src_dst, constant_value);
            return Ok(true);
        }

        let (list_offset, list_ty) = if list_path.is_empty() {
            (0usize, pointee_ty.clone())
        } else {
            let projection = Self::resolve_typed_value_projection_path(
                pointee_ty,
                list_path,
                &Self::typed_value_path_desc(list_path),
            )?;
            if projection.bitfield.is_some() {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' does not support bitfield numeric list fields",
                    path_desc
                )));
            }
            (projection.offset, projection.ty)
        };
        if !matches!(list_ty, MirType::Array { .. }) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' expected numeric list field at {:?}, got {:?}",
                path_desc, list_path, list_ty
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
                "cell path update '.{} = ...' cannot store value type {:?} into numeric list field",
                path_desc, new_value_runtime_ty
            )));
        };

        let item_offset = index
            .checked_mul(8)
            .and_then(|offset| offset.checked_add(8))
            .and_then(|offset| list_offset.checked_add(offset))
            .and_then(|offset| i32::try_from(offset).ok())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' numeric list index offset overflowed",
                    path_desc
                ))
            })?;
        self.emit(MirInst::Store {
            ptr: base_vreg,
            offset: item_offset,
            val: MirValue::VReg(item_vreg),
            ty: MirType::I64,
        });

        if index == current_len {
            let len_offset = i32::try_from(list_offset).map_err(|_| {
                CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' numeric list length offset overflowed",
                    path_desc
                ))
            })?;
            self.emit(MirInst::Store {
                ptr: base_vreg,
                offset: len_offset,
                val: MirValue::Const(i64::try_from(current_len + 1).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "cell path update '.{} = ...' numeric list length overflowed",
                        path_desc
                    ))
                })?),
                ty: MirType::U64,
            });
        }

        let meta = self.get_or_create_metadata(src_dst);
        meta.field_type = Some(pointee_ty.clone());
        if list_path.is_empty() {
            meta.annotated_semantics = Some(AnnotatedValueSemantics::NumericList {
                max_len,
                known_len: Some(if index == current_len {
                    current_len + 1
                } else {
                    current_len
                }),
            });
        }
        meta.constant_value = constant_value.clone();
        meta.kernel_btf_field_addr = None;
        meta.source_var = None;
        self.set_reg_constant_value(src_dst, constant_value);
        Ok(true)
    }

    pub(super) fn lower_metadata_existing_numeric_list_path_update(
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
            PathMember::String {
                val: field_name, ..
            },
            PathMember::Int { val: index, .. },
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
        let Some(AnnotatedValueSemantics::NumericList { max_len, known_len }) =
            existing_field.semantics
        else {
            return Ok(false);
        };
        let current_len = self
            .get_metadata(src_dst)
            .and_then(|meta| Self::metadata_record_numeric_list_len(meta, field_name))
            .or(known_len)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "cell path update '.{} = ...' requires compile-time numeric list length metadata",
                    path_desc
                ))
            })?;
        if *index > current_len {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' can only update an existing numeric list item or append at the next index",
                path_desc
            )));
        }

        let list_runtime_ty = self
            .vreg_type_hints
            .get(&existing_field.value_vreg)
            .cloned()
            .unwrap_or_else(|| existing_field.ty.clone());
        let MirType::Ptr {
            pointee,
            address_space: AddressSpace::Stack,
        } = list_runtime_ty
        else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' requires a stack-backed numeric list field",
                path_desc
            )));
        };
        if pointee.as_ref() != &existing_field.ty {
            return Err(CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' numeric list field pointer type {:?} does not match field type {:?}",
                path_desc, pointee, existing_field.ty
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
                "cell path update '.{} = ...' cannot store value type {:?} into numeric list field",
                path_desc, new_value_runtime_ty
            )));
        };

        if *index < current_len {
            let item_offset = index
                .checked_mul(8)
                .and_then(|offset| offset.checked_add(8))
                .and_then(|offset| i32::try_from(offset).ok())
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "cell path update '.{} = ...' numeric list index offset overflowed",
                        path_desc
                    ))
                })?;
            self.emit(MirInst::Store {
                ptr: existing_field.value_vreg,
                offset: item_offset,
                val: MirValue::VReg(item_vreg),
                ty: MirType::I64,
            });
            self.replace_metadata_record_field(
                src_dst,
                field_index,
                existing_field,
                constant_value,
                path_desc,
                base_is_materialized_aggregate,
                "updated",
            )?;
            return Ok(true);
        }

        if current_len < max_len {
            let mut updated_field = existing_field;
            updated_field.semantics = Some(AnnotatedValueSemantics::NumericList {
                max_len,
                known_len: Some(current_len + 1),
            });
            self.emit(MirInst::ListPush {
                list: updated_field.value_vreg,
                item: item_vreg,
            });
            self.replace_metadata_record_field(
                src_dst,
                field_index,
                updated_field,
                constant_value,
                path_desc,
                base_is_materialized_aggregate,
                "updated",
            )?;
            return Ok(true);
        }

        let new_max_len = max_len.checked_add(1).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "cell path update '.{} = ...' numeric list capacity overflowed",
                path_desc
            ))
        })?;
        let list_ty = MirType::Array {
            elem: Box::new(MirType::I64),
            len: new_max_len + 1,
        };
        let slot = self
            .func
            .alloc_stack_slot(list_ty.size(), 8, StackSlotKind::ListBuffer);
        self.record_list_buffer_slot_type(slot, new_max_len);
        let list_vreg = self.func.alloc_vreg();
        self.emit(MirInst::ListNew {
            dst: list_vreg,
            buffer: slot,
            max_len: new_max_len,
        });
        self.vreg_type_hints.insert(
            list_vreg,
            MirType::Ptr {
                pointee: Box::new(list_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );
        for old_index in 0..current_len {
            let old_item = self.func.alloc_vreg();
            self.vreg_type_hints.insert(old_item, MirType::I64);
            self.emit(MirInst::ListGet {
                dst: old_item,
                list: existing_field.value_vreg,
                idx: MirValue::Const(i64::try_from(old_index).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "cell path update '.{} = ...' numeric list index {} is too large",
                        path_desc, old_index
                    ))
                })?),
            });
            self.emit(MirInst::ListPush {
                list: list_vreg,
                item: old_item,
            });
        }
        self.emit(MirInst::ListPush {
            list: list_vreg,
            item: item_vreg,
        });

        let updated_field = RecordField {
            name: existing_field.name,
            value_vreg: list_vreg,
            source_reg: None,
            stack_offset: existing_field.stack_offset,
            ty: list_ty,
            semantics: Some(AnnotatedValueSemantics::NumericList {
                max_len: new_max_len,
                known_len: Some(current_len + 1),
            }),
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
            "updated",
        )?;
        Ok(true)
    }
}
