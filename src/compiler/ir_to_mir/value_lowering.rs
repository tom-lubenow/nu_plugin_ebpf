use super::*;
use crate::compiler::hir::AnnotatedMutGlobal;
use crate::compiler::mir::{AddressSpace, StructField};

impl<'a> HirToMirLowering<'a> {
    pub(super) fn mutable_global_value_semantics(
        value: &Value,
    ) -> Result<Option<AnnotatedValueSemantics>, CompileError> {
        match value {
            Value::String { .. } | Value::Glob { .. } => {
                let Some((_ty, _data, slot_len)) = Self::mutable_string_global_repr(value) else {
                    return Ok(None);
                };
                Ok(Some(AnnotatedValueSemantics::String {
                    slot_len,
                    content_cap: slot_len.saturating_sub(1),
                }))
            }
            Value::List { vals, .. }
                if crate::compiler::hir::supports_numeric_constant_list(value) =>
            {
                Ok(Some(AnnotatedValueSemantics::NumericList {
                    max_len: vals.len(),
                }))
            }
            Value::Record { val, .. } => {
                let mut field_semantics = Vec::new();
                for (field_name, field_value) in val.iter() {
                    if let Some(field_semantics_value) =
                        Self::mutable_global_value_semantics(field_value)?
                    {
                        field_semantics.push((field_name.clone(), field_semantics_value));
                    }
                }

                if field_semantics.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(AnnotatedValueSemantics::Record(field_semantics)))
                }
            }
            _ => Ok(None),
        }
    }

    pub(super) fn project_annotated_value_semantics(
        semantics: &AnnotatedValueSemantics,
        path_members: &[PathMember],
    ) -> Option<AnnotatedValueSemantics> {
        let mut current = semantics.clone();
        for member in path_members {
            current = match (current, member) {
                (AnnotatedValueSemantics::Record(fields), PathMember::String { val, .. }) => fields
                    .into_iter()
                    .find_map(|(name, semantics)| (name == *val).then_some(semantics))?,
                _ => return None,
            };
        }
        Some(current)
    }

    pub(super) fn init_annotated_mut_globals(
        &mut self,
        annotated_mut_globals: &[AnnotatedMutGlobal],
    ) -> Result<(), CompileError> {
        for annotated in annotated_mut_globals {
            let Some((ty, data, list_max_len, string_slot_len)) = Self::typed_mutable_global_repr(
                &annotated.declared_type,
                &annotated.initial_value,
            )?
            else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "leading annotated mutable variable {} declared as {} is not yet supported; annotated mutable globals currently support scalar, string, binary, numeric list<int>, and record layouts composed of those supported field types",
                    annotated.var_id.get(),
                    annotated.declared_type
                )));
            };

            let symbol = format!("__nu_local_global_{}", annotated.var_id.get());
            if data.iter().all(|byte| *byte == 0) {
                self.bss_globals.push(BssGlobal {
                    name: symbol.clone(),
                    size: data.len(),
                });
            } else {
                self.data_globals.push(DataGlobal {
                    name: symbol.clone(),
                    data,
                });
            }
            self.annotated_mut_globals.insert(
                annotated.var_id,
                MutableCaptureGlobal {
                    symbol,
                    ty,
                    list_max_len,
                    string_slot_len,
                    string_content_cap: string_slot_len.map(|slot_len| slot_len.saturating_sub(1)),
                },
            );
            if let Some(semantics) = Self::annotated_mutable_global_semantics(
                &annotated.declared_type,
                &annotated.initial_value,
            )? {
                self.annotated_mut_global_semantics
                    .insert(annotated.var_id, semantics);
            }
            self.pending_annotated_mut_global_init_stores
                .insert(annotated.var_id);
        }

        Ok(())
    }

    fn lower_constant_list_value(
        &mut self,
        dst: RegId,
        values: &[Value],
    ) -> Result<(), CompileError> {
        self.lower_load_literal(
            dst,
            &HirLiteral::List {
                capacity: values.len(),
            },
        )?;

        let Some((slot, max_len)) = self.get_metadata(dst).and_then(|m| m.list_buffer) else {
            return Err(CompileError::UnsupportedInstruction(
                "constant list lowering did not allocate a list buffer".into(),
            ));
        };

        let truncated_values = &values[..values.len().min(max_len)];
        let (_array_ty, encoded_items) = Self::constant_numeric_list_rodata_repr(truncated_values)?;

        if !encoded_items.is_empty() {
            let symbol = self.alloc_readonly_global_name();
            self.readonly_globals.push(ReadonlyGlobal {
                name: symbol.clone(),
                data: encoded_items,
            });

            let rodata_vreg = self.func.alloc_vreg();
            self.emit(MirInst::LoadGlobal {
                dst: rodata_vreg,
                symbol,
                ty: MirType::Array {
                    elem: Box::new(MirType::I64),
                    len: truncated_values.len(),
                },
            });
            self.vreg_type_hints.insert(
                rodata_vreg,
                MirType::Ptr {
                    pointee: Box::new(MirType::Array {
                        elem: Box::new(MirType::I64),
                        len: truncated_values.len(),
                    }),
                    address_space: AddressSpace::Map,
                },
            );

            for index in 0..truncated_values.len() {
                let item_vreg = self.func.alloc_vreg();
                self.emit(MirInst::Load {
                    dst: item_vreg,
                    ptr: rodata_vreg,
                    offset: (index * std::mem::size_of::<i64>()) as i32,
                    ty: MirType::I64,
                });
                self.emit(MirInst::StoreSlot {
                    slot,
                    offset: (8 + index * std::mem::size_of::<i64>()) as i32,
                    val: MirValue::VReg(item_vreg),
                    ty: MirType::I64,
                });
            }
        }

        self.emit(MirInst::StoreSlot {
            slot,
            offset: 0,
            val: MirValue::Const(truncated_values.len() as i64),
            ty: MirType::U64,
        });

        Ok(())
    }

    pub(super) fn record_type_from_fields(fields: &[(String, MirType)]) -> MirType {
        let mut offset = 0usize;
        let struct_fields = fields
            .iter()
            .map(|(name, ty)| {
                let struct_field = StructField {
                    name: name.clone(),
                    ty: ty.clone(),
                    offset,
                    synthetic: false,
                    bitfield: None,
                };
                offset = offset.saturating_add(ty.size());
                struct_field
            })
            .collect();
        MirType::Struct {
            name: None,
            kernel_btf_type_id: None,
            fields: struct_fields,
        }
    }

    fn alloc_readonly_global_name(&mut self) -> String {
        let id = self.readonly_global_counter;
        self.readonly_global_counter = self.readonly_global_counter.saturating_add(1);
        format!("__nu_rodata_const_{}", id)
    }

    pub(super) fn scalar_constant_rodata_repr(value: &Value) -> Option<(MirType, Vec<u8>)> {
        let encoded = match value {
            Value::Bool { val, .. } => Some(if *val { 1i64 } else { 0 }),
            Value::Int { val, .. } => Some(*val),
            Value::Filesize { val, .. } => Some(val.get()),
            Value::Duration { val, .. } => Some(*val),
            Value::Nothing { .. } => Some(0),
            _ => None,
        }?;
        Some((MirType::I64, encoded.to_le_bytes().to_vec()))
    }

    fn string_constant_rodata_repr(value: &Value) -> Option<(MirType, Vec<u8>)> {
        let bytes = match value {
            Value::String { val, .. } => Some(val.as_bytes()),
            Value::Glob { val, .. } => Some(val.as_bytes()),
            _ => None,
        }?;

        let content_len = bytes.len().min(MAX_STRING_SIZE.saturating_sub(1));
        let aligned_len = align_to_eight(content_len + 1).min(MAX_STRING_SIZE).max(16);
        let mut data = vec![0u8; aligned_len];
        data[..content_len].copy_from_slice(&bytes[..content_len]);
        Some((
            MirType::Array {
                elem: Box::new(MirType::U8),
                len: aligned_len,
            },
            data,
        ))
    }

    fn constant_numeric_list_rodata_repr(
        values: &[Value],
    ) -> Result<(MirType, Vec<u8>), CompileError> {
        let mut data = Vec::with_capacity(values.len() * std::mem::size_of::<i64>());
        for value in values {
            let Some((_item_ty, item_data)) = Self::scalar_constant_rodata_repr(value) else {
                return Err(CompileError::UnsupportedInstruction(
                    "constant lists currently only support numeric scalar elements in eBPF lowering"
                        .into(),
                ));
            };
            data.extend_from_slice(&item_data);
        }
        Ok((
            MirType::Array {
                elem: Box::new(MirType::I64),
                len: values.len(),
            },
            data,
        ))
    }

    fn constant_value_rodata_repr(value: &Value) -> Result<(MirType, Vec<u8>), CompileError> {
        if let Some(repr) = Self::scalar_constant_rodata_repr(value) {
            return Ok(repr);
        }
        if let Some(repr) = Self::string_constant_rodata_repr(value) {
            return Ok(repr);
        }
        if let Value::Binary { val, .. } = value {
            return Self::binary_constant_rodata_repr(val);
        }
        if crate::compiler::hir::supports_numeric_constant_list(value)
            && let Value::List { vals, .. } = value
        {
            return Self::constant_numeric_list_rodata_repr(vals);
        }

        match value {
            Value::Record { val, .. } => Self::constant_record_rodata_repr(val.as_ref()),
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "LoadValue of type {} is not supported in eBPF lowering",
                value.get_type()
            ))),
        }
    }

    pub(super) fn constant_record_rodata_repr(
        record: &nu_protocol::Record,
    ) -> Result<(MirType, Vec<u8>), CompileError> {
        let mut field_layouts = Vec::with_capacity(record.len());
        let mut data = Vec::new();

        for (field_name, field_value) in record.iter() {
            let (field_ty, field_data) = Self::constant_value_rodata_repr(field_value)?;
            field_layouts.push((field_name.clone(), field_ty));
            data.extend_from_slice(&field_data);
        }

        Ok((Self::record_type_from_fields(&field_layouts), data))
    }

    fn lower_constant_record_value(
        &mut self,
        dst: RegId,
        record: &nu_protocol::Record,
    ) -> Result<(), CompileError> {
        let dst_vreg = if self.reg_map.contains_key(&dst.get()) {
            self.assign_fresh_vreg(dst)
        } else {
            self.get_vreg(dst)
        };
        self.reg_metadata.insert(dst.get(), RegMetadata::default());

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

        let base_runtime_ty = MirType::Ptr {
            pointee: Box::new(record_ty.clone()),
            address_space: AddressSpace::Map,
        };
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::VReg(global_vreg),
        });
        self.vreg_type_hints
            .insert(global_vreg, base_runtime_ty.clone());
        self.vreg_type_hints
            .insert(dst_vreg, base_runtime_ty.clone());

        let mut record_fields = Vec::new();
        let struct_fields = match &record_ty {
            MirType::Struct { fields, .. } => fields.clone(),
            _ => {
                return Err(CompileError::UnsupportedInstruction(
                    "constant record lowering did not produce a struct layout".into(),
                ));
            }
        };
        for field in struct_fields.into_iter().filter(|field| !field.synthetic) {
            let field_vreg = self.func.alloc_vreg();
            let path = vec![PathMember::string(
                field.name.clone(),
                false,
                Casing::Sensitive,
                Span::unknown(),
            )];
            let field_ty = self.lower_typed_value_projection(
                dst,
                field_vreg,
                dst_vreg,
                &base_runtime_ty,
                &path,
                &field.name,
                None,
                None,
            )?;
            let field_semantics = record
                .get(&field.name)
                .map(Self::mutable_global_value_semantics)
                .transpose()?
                .flatten();
            record_fields.push(RecordField {
                name: field.name,
                value_vreg: field_vreg,
                stack_offset: None,
                ty: field_ty,
                semantics: field_semantics,
            });
        }

        let meta = self.get_or_create_metadata(dst);
        meta.is_context = false;
        meta.record_fields = record_fields;
        meta.field_type = Some(record_ty);
        meta.annotated_semantics =
            Self::mutable_global_value_semantics(&Value::record(record.clone(), Span::unknown()))?;

        Ok(())
    }

    pub(super) fn lower_constant_value(
        &mut self,
        dst: RegId,
        value: &Value,
    ) -> Result<(), CompileError> {
        self.lower_constant_value_with_lists(dst, value, true)
    }

    fn lower_constant_value_with_lists(
        &mut self,
        dst: RegId,
        value: &Value,
        allow_top_level_list: bool,
    ) -> Result<(), CompileError> {
        if let Some(lit) = HirLiteral::from_constant_value(value) {
            self.lower_load_literal(dst, &lit)?;
        } else {
            match value {
                Value::Record { val, .. } => self.lower_constant_record_value(dst, val.as_ref())?,
                Value::List { vals, .. } if allow_top_level_list => {
                    self.lower_constant_list_value(dst, vals)?
                }
                Value::List { .. } => {
                    return Err(CompileError::UnsupportedInstruction(
                        "constant lists nested inside records are not yet supported in eBPF lowering"
                            .into(),
                    ));
                }
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "LoadValue of type {} is not supported in eBPF lowering",
                        value.get_type()
                    )));
                }
            }
        }

        self.get_or_create_metadata(dst).constant_value = Some(value.clone());
        Ok(())
    }

    fn lower_const_i64_literal(&mut self, dst: RegId, dst_vreg: VReg, value: i64) {
        self.vreg_type_hints.insert(dst_vreg, MirType::I64);
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::Const(value),
        });
        let meta = self.get_or_create_metadata(dst);
        meta.literal_int = Some(value);
        meta.field_type = Some(MirType::I64);
    }

    fn lower_string_like_literal(
        &mut self,
        dst: RegId,
        dst_vreg: VReg,
        bytes: &[u8],
    ) -> Result<(), CompileError> {
        // Warn if string exceeds eBPF limits
        let string_len = bytes.len();
        let max_content_len = MAX_STRING_SIZE.saturating_sub(1);
        if string_len > max_content_len {
            eprintln!(
                "Warning: string literal ({} bytes) exceeds eBPF limit of {} bytes and will be truncated",
                string_len, max_content_len
            );
        }
        let content_len = bytes.len().min(max_content_len);
        let aligned_len = align_to_eight(content_len + 1).min(MAX_STRING_SIZE).max(16);

        // Allocate stack slot for string buffer (aligned for emit)
        let slot = self
            .func
            .alloc_stack_slot(aligned_len, 8, StackSlotKind::StringBuffer);
        self.record_stack_slot_type(
            slot,
            MirType::Array {
                elem: Box::new(MirType::U8),
                len: aligned_len,
            },
        );

        // Build literal bytes with null terminator and zero padding
        let mut literal_bytes = vec![0u8; aligned_len];
        literal_bytes[..content_len].copy_from_slice(&bytes[..content_len]);
        // literal_bytes is zero-initialized, so null + padding are already zeroed.

        // Write literal bytes into the buffer at runtime
        let len_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: len_vreg,
            src: MirValue::Const(0),
        });
        self.emit(MirInst::StringAppend {
            dst_buffer: slot,
            dst_len: len_vreg,
            val: MirValue::Const(0),
            val_type: StringAppendType::Literal {
                bytes: literal_bytes,
            },
        });

        let string_value = std::str::from_utf8(&bytes[..content_len])
            .ok()
            .map(|s| s.to_string());

        // Record slot pointer in a vreg
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::StackSlot(slot),
        });
        // Track the string slot and value
        let meta = self.get_or_create_metadata(dst);
        meta.string_slot = Some(slot);
        meta.string_len_vreg = Some(len_vreg);
        meta.string_len_bound = Some(content_len);
        meta.field_type = Some(MirType::Array {
            elem: Box::new(MirType::U8),
            len: aligned_len,
        });
        // Also track the literal string value for record field names
        if let Some(s) = string_value {
            meta.literal_string = Some(s);
        }

        Ok(())
    }

    pub(super) fn lower_load_literal(
        &mut self,
        dst: RegId,
        lit: &HirLiteral,
    ) -> Result<(), CompileError> {
        let dst_vreg = if self.reg_map.contains_key(&dst.get()) {
            self.assign_fresh_vreg(dst)
        } else {
            self.get_vreg(dst)
        };
        self.reg_metadata.insert(dst.get(), RegMetadata::default());

        match lit {
            HirLiteral::Int(val) => {
                self.lower_const_i64_literal(dst, dst_vreg, *val);
            }

            HirLiteral::Bool(val) => {
                self.vreg_type_hints.insert(dst_vreg, MirType::Bool);
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(if *val { 1 } else { 0 }),
                });
                self.get_or_create_metadata(dst).field_type = Some(MirType::Bool);
            }

            HirLiteral::Filesize(val) => {
                self.lower_const_i64_literal(dst, dst_vreg, val.get());
            }

            HirLiteral::Duration(val) => {
                self.lower_const_i64_literal(dst, dst_vreg, *val);
            }

            HirLiteral::Nothing => {
                // `nothing` is used by Nushell IR for omitted range steps and
                // other optional parser slots. Lower it to a zero placeholder.
                self.vreg_type_hints.insert(dst_vreg, MirType::I64);
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
                self.get_or_create_metadata(dst).field_type = Some(MirType::I64);
            }

            HirLiteral::String(bytes)
            | HirLiteral::RawString(bytes)
            | HirLiteral::Filepath { val: bytes, .. }
            | HirLiteral::Directory { val: bytes, .. }
            | HirLiteral::GlobPattern { val: bytes, .. } => {
                self.lower_string_like_literal(dst, dst_vreg, bytes)?;
            }

            HirLiteral::Binary(bytes) => {
                let (array_ty, data) = Self::binary_constant_rodata_repr(bytes)?;
                let symbol = self.alloc_readonly_global_name();
                self.readonly_globals.push(ReadonlyGlobal {
                    name: symbol.clone(),
                    data,
                });

                let global_vreg = self.func.alloc_vreg();
                self.emit(MirInst::LoadGlobal {
                    dst: global_vreg,
                    symbol,
                    ty: array_ty.clone(),
                });

                let runtime_ty = MirType::Ptr {
                    pointee: Box::new(array_ty.clone()),
                    address_space: AddressSpace::Map,
                };
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::VReg(global_vreg),
                });
                self.vreg_type_hints.insert(global_vreg, runtime_ty.clone());
                self.vreg_type_hints.insert(dst_vreg, runtime_ty);

                let meta = self.get_or_create_metadata(dst);
                meta.field_type = Some(array_ty);
            }

            HirLiteral::CellPath(cell_path) => {
                // Cell paths are metadata-only - they guide field access compilation
                // They don't need a runtime value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0), // Dummy value
                });
                // Track the cell path for use in FollowCellPath
                let meta = self.get_or_create_metadata(dst);
                meta.cell_path = Some((**cell_path).clone());
            }

            HirLiteral::Record { capacity: _ } => {
                // Record allocation - just track that this is a record
                // Actual fields are added via RecordInsert
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0), // Placeholder
                });
                // Initialize empty record fields in metadata
                let meta = self.get_or_create_metadata(dst);
                meta.record_fields = Vec::new();
            }

            HirLiteral::Range {
                start,
                step,
                end,
                inclusion,
            } => {
                // For eBPF bounded loops, we need compile-time known bounds
                let start_val = self
                    .get_metadata(*start)
                    .and_then(|m| m.literal_int)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "Range start must be a compile-time known integer for eBPF loops"
                                .into(),
                        )
                    })?;

                // Step can be nothing (default 1) or an explicit integer
                let step_val = self
                    .get_metadata(*step)
                    .and_then(|m| m.literal_int)
                    .unwrap_or(1);

                let end_val = self
                    .get_metadata(*end)
                    .and_then(|m| m.literal_int)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "Range end must be a compile-time known integer for eBPF loops".into(),
                        )
                    })?;

                // Validate step is non-zero
                if step_val == 0 {
                    return Err(CompileError::UnsupportedInstruction(
                        "Range step cannot be zero".into(),
                    ));
                }

                // Store range info in metadata for use by Iterate
                let range = BoundedRange {
                    start: start_val,
                    step: step_val,
                    end: end_val,
                    inclusive: *inclusion == RangeInclusion::Inclusive,
                };

                // Set a placeholder value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(start_val), // Initial value
                });

                let meta = self.get_or_create_metadata(dst);
                meta.bounded_range = Some(range);
            }

            HirLiteral::List { capacity } => {
                // Allocate stack slot for list: [length: u64, elem0, elem1, ...]
                // Due to eBPF 512-byte stack limit, we cap capacity at 60 elements
                // (8 bytes per elem + 8 bytes for length = 488 bytes max)
                const MAX_LIST_CAPACITY: usize = 60;
                let max_len = (*capacity as usize).min(MAX_LIST_CAPACITY);
                let buffer_size = 8 + (max_len * 8); // length + elements
                let list_ty = MirType::Array {
                    elem: Box::new(MirType::I64),
                    len: max_len.saturating_add(1),
                };

                let slot = self
                    .func
                    .alloc_stack_slot(buffer_size, 8, StackSlotKind::ListBuffer);
                self.record_list_buffer_slot_type(slot, max_len);

                // Emit ListNew to initialize the list buffer
                self.emit(MirInst::ListNew {
                    dst: dst_vreg,
                    buffer: slot,
                    max_len,
                });
                self.vreg_type_hints.insert(
                    dst_vreg,
                    MirType::Ptr {
                        pointee: Box::new(list_ty.clone()),
                        address_space: AddressSpace::Stack,
                    },
                );

                // Track the list buffer in metadata
                let meta = self.get_or_create_metadata(dst);
                meta.field_type = Some(list_ty);
                meta.list_buffer = Some((slot, max_len));
            }

            HirLiteral::Closure(block_id) => {
                // Track the closure block ID for use in where/each
                // Closures as first-class values (stored in variables, passed around)
                // are not supported, but inline closures for where/each work.
                let meta = self.get_or_create_metadata(dst);
                meta.closure_block_id = Some(*block_id);
                // Store a placeholder value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            HirLiteral::Block(block_id) => {
                // Track block ID same as closure
                let meta = self.get_or_create_metadata(dst);
                meta.closure_block_id = Some(*block_id);
                // Store a placeholder value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            HirLiteral::RowCondition(block_id) => {
                // RowCondition is used by `where` command - same as Closure
                let meta = self.get_or_create_metadata(dst);
                meta.closure_block_id = Some(*block_id);
                // Store a placeholder value
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
            }

            _ => {
                return Err(CompileError::UnsupportedLiteral);
            }
        }
        if let Some(value) = lit.to_constant_value() {
            self.get_or_create_metadata(dst).constant_value = Some(value);
        }
        Ok(())
    }
}
