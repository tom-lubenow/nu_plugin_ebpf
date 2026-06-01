use super::*;
use crate::compiler::mir::AddressSpace;

const MAX_RECORD_COLUMNS_RESULTS: usize = 64;

impl<'a> HirToMirLowering<'a> {
    fn metadata_record_values_supported_field(meta: &RegMetadata, field: &RecordField) -> bool {
        let storage_is_integer = matches!(
            field.ty,
            MirType::I8
                | MirType::I16
                | MirType::I32
                | MirType::I64
                | MirType::U8
                | MirType::U16
                | MirType::U32
                | MirType::U64
        );
        if !storage_is_integer {
            return false;
        }

        let Some(nu_protocol::Value::Record { val, .. }) = meta.constant_value.as_ref() else {
            return true;
        };
        matches!(
            val.get(&field.name),
            Some(
                nu_protocol::Value::Int { .. }
                    | nu_protocol::Value::Filesize { .. }
                    | nu_protocol::Value::Duration { .. }
            )
        )
    }

    fn default_should_replace_value(value: &nu_protocol::Value, replace_empty: bool) -> bool {
        match value {
            nu_protocol::Value::Nothing { .. } => true,
            nu_protocol::Value::String { val, .. } => replace_empty && val.is_empty(),
            nu_protocol::Value::Binary { val, .. } => replace_empty && val.is_empty(),
            nu_protocol::Value::List { vals, .. } => replace_empty && vals.is_empty(),
            nu_protocol::Value::Record { val, .. } => replace_empty && val.is_empty(),
            _ => false,
        }
    }

    pub(super) fn emit_metadata_record_result(
        &mut self,
        src_dst: RegId,
        result_vreg: VReg,
        mut projected_meta: RegMetadata,
    ) -> Result<(), CompileError> {
        projected_meta.is_context = false;
        projected_meta.field_type = Self::metadata_record_layout(&projected_meta);
        projected_meta.annotated_semantics = Self::metadata_record_semantics(&projected_meta);
        projected_meta.source_var = None;

        let out_meta = if let Some((record_vreg, mut materialized_meta)) =
            self.materialize_metadata_record_value(&projected_meta)?
        {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::VReg(record_vreg),
            });
            if let Some(record_ty) = self.vreg_type_hints.get(&record_vreg).cloned() {
                self.vreg_type_hints.insert(result_vreg, record_ty);
            }
            materialized_meta.source_var = None;
            materialized_meta
        } else {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(0),
            });
            projected_meta
        };
        self.reg_metadata.insert(src_dst.get(), out_meta);

        Ok(())
    }

    pub(super) fn field_path_arg(
        &self,
        reg: RegId,
        context: &str,
    ) -> Result<Option<CellPath>, CompileError> {
        let Some(meta) = self.get_metadata(reg) else {
            return Ok(None);
        };

        let path = meta.cell_path.as_ref().or_else(|| {
            meta.constant_value.as_ref().and_then(|value| match value {
                nu_protocol::Value::CellPath { val, .. } => Some(val),
                _ => None,
            })
        });
        if let Some(path) = path {
            return match path.members.first() {
                Some(PathMember::String { .. }) => Ok(Some(path.clone())),
                Some(PathMember::Int { .. }) => Ok(None),
                None => Err(CompileError::UnsupportedInstruction(format!(
                    "{context} does not support empty cell paths in eBPF"
                ))),
            };
        }

        let name = meta
            .literal_string
            .clone()
            .or_else(|| match meta.constant_value.as_ref() {
                Some(nu_protocol::Value::String { val, .. }) => Some(val.clone()),
                _ => None,
            });
        Ok(name.map(|name| CellPath {
            members: vec![PathMember::string(
                name,
                false,
                Casing::Sensitive,
                Span::unknown(),
            )],
        }))
    }

    fn top_level_field_name_arg(&self, reg: RegId, context: &str) -> Result<String, CompileError> {
        let Some(meta) = self.get_metadata(reg) else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} requires compile-time field names in eBPF"
            )));
        };

        if let Some(name) = meta.literal_string.clone() {
            return Ok(name);
        }

        let path = meta.cell_path.as_ref().or_else(|| {
            meta.constant_value.as_ref().and_then(|value| match value {
                nu_protocol::Value::CellPath { val, .. } => Some(val),
                _ => None,
            })
        });
        if let Some(path) = path {
            match path.members.as_slice() {
                [PathMember::String { val, .. }] => return Ok(val.clone()),
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{context} supports only top-level record field names in eBPF"
                    )));
                }
            }
        }

        if let Some(nu_protocol::Value::String { val, .. }) = meta.constant_value.as_ref() {
            return Ok(val.clone());
        }

        Err(CompileError::UnsupportedInstruction(format!(
            "{context} requires compile-time field names in eBPF"
        )))
    }

    pub(super) fn lower_metadata_record_select_or_reject(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} does not accept named flags or arguments in eBPF"
            )));
        }
        if self.positional_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires at least one record field name in eBPF"
            )));
        }

        let mut names = Vec::new();
        for (_, reg) in &self.positional_args {
            let name = self.top_level_field_name_arg(*reg, cmd_name)?;
            if !names.contains(&name) {
                names.push(name);
            }
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires record input with compiler-known fields in eBPF"
                ))
            })?;
        if input_meta.record_fields.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires record input with compiler-known fields in eBPF"
            )));
        }

        for name in &names {
            if !input_meta
                .record_fields
                .iter()
                .any(|field| field.name == *name)
            {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} cannot find record field '{name}'"
                )));
            }
        }

        let selected_fields = if cmd_name == "select" {
            names
                .iter()
                .filter_map(|name| {
                    input_meta
                        .record_fields
                        .iter()
                        .find(|field| field.name == *name)
                        .cloned()
                })
                .collect::<Vec<_>>()
        } else {
            input_meta
                .record_fields
                .iter()
                .filter(|field| !names.contains(&field.name))
                .cloned()
                .collect::<Vec<_>>()
        };

        let constant_value = match input_meta.constant_value.clone() {
            Some(nu_protocol::Value::Record { val, .. }) => {
                let record = val.into_owned();
                let mut out = nu_protocol::Record::new();
                if cmd_name == "select" {
                    for name in &names {
                        let Some(value) = record.get(name) else {
                            continue;
                        };
                        out.push(name.clone(), value.clone());
                    }
                } else {
                    for (key, value) in record.iter() {
                        if !names.iter().any(|name| name == key) {
                            out.push(key, value.clone());
                        }
                    }
                }
                Some(nu_protocol::Value::record(out, Span::unknown()))
            }
            _ => None,
        };

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let projected_meta = RegMetadata {
            record_fields: selected_fields,
            constant_value,
            ..Default::default()
        };
        self.emit_metadata_record_result(src_dst, result_vreg, projected_meta)?;

        Ok(())
    }

    pub(super) fn lower_metadata_record_rename(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "rename --column and --block are not supported in eBPF".into(),
            ));
        }

        let mut new_names = Vec::new();
        for (_, reg) in &self.positional_args {
            let name = self.top_level_field_name_arg(*reg, "rename")?;
            new_names.push(name);
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "rename requires record input with compiler-known fields in eBPF".into(),
                )
            })?;
        if input_meta.record_fields.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "rename requires record input with compiler-known fields in eBPF".into(),
            ));
        }

        let mut renamed_fields = input_meta.record_fields.clone();
        for (field, name) in renamed_fields.iter_mut().zip(new_names.iter()) {
            field.name = name.clone();
        }

        let constant_value = match input_meta.constant_value.clone() {
            Some(nu_protocol::Value::Record { val, .. }) => {
                let mut out = nu_protocol::Record::new();
                for (idx, (key, value)) in val.iter().enumerate() {
                    let out_key = new_names.get(idx).unwrap_or(key).clone();
                    out.push(out_key, value.clone());
                }
                Some(nu_protocol::Value::record(out, Span::unknown()))
            }
            _ => None,
        };

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let projected_meta = RegMetadata {
            record_fields: renamed_fields,
            constant_value,
            ..Default::default()
        };
        self.emit_metadata_record_result(src_dst, result_vreg, projected_meta)
    }

    pub(super) fn lower_metadata_record_merge(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "merge does not accept named flags or arguments in eBPF".into(),
            ));
        }
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "merge requires exactly one record argument in eBPF".into(),
            ));
        }

        let (_, merge_reg) = self.positional_args[0];
        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "merge requires record input with compiler-known fields in eBPF".into(),
                )
            })?;
        let merge_meta = self.get_metadata(merge_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "merge requires a record argument with compiler-known fields in eBPF".into(),
            )
        })?;

        let input_is_known_empty_record = matches!(
            input_meta.constant_value.as_ref(),
            Some(nu_protocol::Value::Record { val, .. }) if val.is_empty()
        );
        if input_meta.record_fields.is_empty() && !input_is_known_empty_record {
            return Err(CompileError::UnsupportedInstruction(
                "merge requires record input with compiler-known fields in eBPF".into(),
            ));
        }

        let merge_is_known_empty_record = matches!(
            merge_meta.constant_value.as_ref(),
            Some(nu_protocol::Value::Record { val, .. }) if val.is_empty()
        );
        if merge_meta.record_fields.is_empty() && !merge_is_known_empty_record {
            return Err(CompileError::UnsupportedInstruction(
                "merge requires a record argument with compiler-known fields in eBPF".into(),
            ));
        }

        let mut fields = input_meta.record_fields.clone();
        for merge_field in &merge_meta.record_fields {
            if let Some(index) = fields
                .iter()
                .position(|field| field.name == merge_field.name)
            {
                fields[index] = merge_field.clone();
            } else {
                fields.push(merge_field.clone());
            }
        }

        let constant_value = match (
            input_meta.constant_value.clone(),
            merge_meta.constant_value.clone(),
        ) {
            (
                Some(nu_protocol::Value::Record { val: input, .. }),
                Some(nu_protocol::Value::Record { val: merge, .. }),
            ) => {
                let mut record = input.into_owned();
                for (key, value) in merge.iter() {
                    record.insert(key.clone(), value.clone());
                }
                Some(nu_protocol::Value::record(record, Span::unknown()))
            }
            _ => None,
        };

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let projected_meta = RegMetadata {
            record_fields: fields,
            constant_value,
            ..Default::default()
        };
        self.emit_metadata_record_result(src_dst, result_vreg, projected_meta)
    }

    pub(super) fn lower_metadata_record_values(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !self.named_flags.is_empty()
            || !self.named_args.is_empty()
            || !self.positional_args.is_empty()
        {
            return Err(CompileError::UnsupportedInstruction(
                "values does not accept arguments in eBPF".into(),
            ));
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "values requires record input with compiler-known fields in eBPF".into(),
                )
            })?;
        let input_is_known_empty_record = matches!(
            input_meta.constant_value.as_ref(),
            Some(nu_protocol::Value::Record { val, .. }) if val.is_empty()
        );
        if input_meta.record_fields.is_empty() && !input_is_known_empty_record {
            return Err(CompileError::UnsupportedInstruction(
                "values requires record input with compiler-known fields in eBPF".into(),
            ));
        }

        for field in &input_meta.record_fields {
            if !Self::metadata_record_values_supported_field(&input_meta, field) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "values supports only integer scalar record fields in eBPF; field '{}' has type {:?}",
                    field.name, field.ty
                )));
            }
        }

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let max_len = input_meta.record_fields.len();
        let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, max_len);

        for field in &input_meta.record_fields {
            self.emit(MirInst::ListPush {
                list: result_vreg,
                item: field.value_vreg,
            });
        }

        self.install_stack_numeric_list_result_metadata(
            src_dst,
            out_slot,
            out_ty,
            max_len,
            Some(max_len),
        );
        if let Some(nu_protocol::Value::Record { val, .. }) = input_meta.constant_value {
            let vals = val
                .iter()
                .map(|(_key, value)| value.clone())
                .collect::<Vec<_>>();
            self.get_or_create_metadata(src_dst).constant_value =
                Some(nu_protocol::Value::list(vals, Span::unknown()));
        }

        Ok(())
    }

    pub(super) fn lower_metadata_record_columns(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !self.named_flags.is_empty()
            || !self.named_args.is_empty()
            || !self.positional_args.is_empty()
        {
            return Err(CompileError::UnsupportedInstruction(
                "columns does not accept arguments in eBPF".into(),
            ));
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "columns requires record input with compiler-known fields in eBPF".into(),
                )
            })?;
        if input_meta.record_fields.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "columns requires non-empty record input with compiler-known fields in eBPF".into(),
            ));
        }
        if input_meta.record_fields.len() > MAX_RECORD_COLUMNS_RESULTS {
            return Err(CompileError::UnsupportedInstruction(format!(
                "columns supports at most {MAX_RECORD_COLUMNS_RESULTS} record fields in eBPF"
            )));
        }

        let mut columns = Vec::with_capacity(input_meta.record_fields.len());
        for field in &input_meta.record_fields {
            if field.name.len().saturating_add(1) > MAX_STRING_SIZE {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "columns field name '{}' exceeds the eBPF string capacity of {} bytes",
                    field.name,
                    MAX_STRING_SIZE - 1
                )));
            }
            columns.push(field.name.clone());
        }

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        self.lower_known_string_list_result(src_dst, result_vreg, columns)
    }

    pub(super) fn lower_metadata_record_get(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "get does not accept named flags or arguments in eBPF".into(),
            ));
        }
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "get requires exactly one record field name argument in eBPF".into(),
            ));
        }

        let (_, field_reg) = self.positional_args[0];
        let field_name = self.top_level_field_name_arg(field_reg, "get")?;
        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "get requires record input with compiler-known fields in eBPF".into(),
                )
            })?;
        if input_meta.record_fields.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "get requires record input with compiler-known fields in eBPF".into(),
            ));
        }

        let field = input_meta
            .record_fields
            .iter()
            .find(|field| field.name == field_name)
            .cloned()
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "get field '{field_name}' was not found in metadata-backed record in eBPF"
                ))
            })?;
        let field_constant = input_meta
            .constant_value
            .as_ref()
            .and_then(|value| match value {
                nu_protocol::Value::Record { val, .. } => val.get(&field_name).cloned(),
                _ => None,
            });
        let field_source_meta = field
            .source_reg
            .and_then(|reg| self.get_metadata(reg).cloned());

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        self.emit(MirInst::Copy {
            dst: result_vreg,
            src: MirValue::VReg(field.value_vreg),
        });
        self.vreg_type_hints.insert(result_vreg, field.ty.clone());

        let mut out_meta = field_source_meta.unwrap_or_default();
        out_meta.is_context = field.is_context;
        out_meta.field_type = Some(field.ty);
        out_meta.root_ctx_field = field.root_ctx_field;
        out_meta.trusted_btf = out_meta.trusted_btf
            && matches!(
                out_meta.field_type.as_ref(),
                Some(MirType::Ptr {
                    address_space: AddressSpace::Kernel,
                    ..
                })
            );
        out_meta.annotated_semantics = field.semantics;
        out_meta.source_var = None;
        out_meta.constant_value = field_constant;
        self.reg_metadata.insert(src_dst.get(), out_meta);

        Ok(())
    }

    pub(super) fn lower_default(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let replace_empty = match self.named_flags.as_slice() {
            [] => false,
            [flag] if flag == "empty" => true,
            _ => {
                return Err(CompileError::UnsupportedInstruction(
                    "default accepts only the --empty flag in eBPF".into(),
                ));
            }
        };
        self.require_only_named_args("default", &[])?;

        let (default_vreg, default_reg) =
            self.positional_args.first().copied().ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "default requires a default value positional argument in eBPF".into(),
                )
            })?;
        if self
            .get_metadata(default_reg)
            .is_some_and(|meta| meta.closure_block_id.is_some())
        {
            return Err(CompileError::UnsupportedInstruction(
                "default closure values are not supported in eBPF".into(),
            ));
        }

        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "default requires pipeline input in eBPF".into(),
                )
            })?;
        let input_meta = self.get_metadata(input_reg).cloned();

        let mut column_names = Vec::new();
        for (_, reg) in self.positional_args.iter().skip(1) {
            let name = self.top_level_field_name_arg(*reg, "default")?;
            if !column_names.contains(&name) {
                column_names.push(name);
            }
        }

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        if column_names.is_empty() {
            let should_replace = input_meta
                .as_ref()
                .and_then(|meta| meta.constant_value.as_ref())
                .is_some_and(|value| Self::default_should_replace_value(value, replace_empty));
            if replace_empty
                && input_meta
                    .as_ref()
                    .and_then(|meta| meta.constant_value.as_ref())
                    .is_none()
            {
                return Err(CompileError::UnsupportedInstruction(
                    "default --empty requires compiler-known empty state in eBPF".into(),
                ));
            }
            let selected_vreg = if should_replace {
                default_vreg
            } else {
                let input_ty = self.typed_value_runtime_type(input_reg, input_vreg);
                if matches!(
                    input_ty,
                    Some(MirType::Ptr {
                        address_space: AddressSpace::Map | AddressSpace::Kernel,
                        ..
                    })
                ) && input_meta
                    .as_ref()
                    .and_then(|meta| meta.constant_value.as_ref())
                    .is_none()
                {
                    return Err(CompileError::UnsupportedInstruction(
                        "default on runtime nullable pointer inputs requires an explicit null branch in eBPF"
                            .into(),
                    ));
                }
                input_vreg
            };
            let selected_reg = if should_replace {
                default_reg
            } else {
                input_reg
            };
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::VReg(selected_vreg),
            });
            self.propagate_passthrough_reg_metadata(
                src_dst,
                result_vreg,
                selected_reg,
                selected_vreg,
            );
            return Ok(());
        }

        let input_meta = input_meta.ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "default column fill requires record input with compiler-known fields in eBPF"
                    .into(),
            )
        })?;
        let input_is_known_empty_record = matches!(
            input_meta.constant_value.as_ref(),
            Some(nu_protocol::Value::Record { val, .. }) if val.is_empty()
        );
        if input_meta.record_fields.is_empty() && !input_is_known_empty_record {
            return Err(CompileError::UnsupportedInstruction(
                "default column fill requires record input with compiler-known fields in eBPF"
                    .into(),
            ));
        }

        let mut fields = input_meta.record_fields.clone();
        for name in &column_names {
            let existing_index = fields.iter().position(|field| field.name == *name);
            let replace_existing = input_meta
                .constant_value
                .as_ref()
                .and_then(|value| match value {
                    nu_protocol::Value::Record { val, .. } => val.get(name),
                    _ => None,
                })
                .is_some_and(|value| Self::default_should_replace_value(value, replace_empty));
            if let Some(index) = existing_index {
                if replace_existing {
                    fields[index] = self.record_field_from_value(name.clone(), default_reg)?;
                }
            } else {
                fields.push(self.record_field_from_value(name.clone(), default_reg)?);
            }
        }

        let default_constant = self
            .get_metadata(default_reg)
            .and_then(|meta| meta.constant_value.clone());
        let constant_value = match input_meta.constant_value.clone() {
            Some(nu_protocol::Value::Record { val, .. }) => {
                let mut record = val.into_owned();
                let mut fully_known = true;
                for name in &column_names {
                    let should_replace = record
                        .get(name)
                        .map(|value| Self::default_should_replace_value(value, replace_empty))
                        .unwrap_or(true);
                    if should_replace {
                        if let Some(value) = default_constant.clone() {
                            record.insert(name.clone(), value);
                        } else {
                            fully_known = false;
                        }
                    }
                }
                fully_known.then(|| nu_protocol::Value::record(record, Span::unknown()))
            }
            _ => None,
        };

        let projected_meta = RegMetadata {
            record_fields: fields,
            constant_value,
            ..Default::default()
        };
        self.emit_metadata_record_result(src_dst, result_vreg, projected_meta)
    }

    pub(super) fn lower_metadata_record_insert_update_or_upsert(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} does not accept named flags or arguments in eBPF"
            )));
        }
        if self.positional_args.len() != 2 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires exactly one field name and one replacement value in eBPF"
            )));
        }

        let (_, field_reg) = self.positional_args[0];
        let (_, value_reg) = self.positional_args[1];
        if self
            .get_metadata(value_reg)
            .is_some_and(|meta| meta.closure_block_id.is_some())
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} closure replacement values are not supported in eBPF"
            )));
        }
        let field_name = self.top_level_field_name_arg(field_reg, cmd_name)?;

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires record input with compiler-known fields in eBPF"
                ))
            })?;
        let input_is_known_empty_record = matches!(
            input_meta.constant_value.as_ref(),
            Some(nu_protocol::Value::Record { val, .. }) if val.is_empty()
        );
        if input_meta.record_fields.is_empty() && !input_is_known_empty_record {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires record input with compiler-known fields in eBPF"
            )));
        }

        let mut fields = input_meta.record_fields.clone();
        let existing_index = fields.iter().position(|field| field.name == field_name);
        match (cmd_name, existing_index) {
            ("insert", Some(_)) => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "insert cannot replace existing record field '{field_name}'"
                )));
            }
            ("update", None) => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "update cannot find record field '{field_name}'"
                )));
            }
            ("upsert", _) | ("insert", None) | ("update", Some(_)) => {}
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "unsupported metadata record command '{cmd_name}'"
                )));
            }
        }

        let replacement_field = self.record_field_from_value(field_name.clone(), value_reg)?;
        if let Some(index) = existing_index {
            fields[index] = replacement_field;
        } else {
            fields.push(replacement_field);
        }

        let replacement_constant = self
            .get_metadata(value_reg)
            .and_then(|meta| meta.constant_value.clone());
        let constant_value = match (input_meta.constant_value.clone(), replacement_constant) {
            (Some(nu_protocol::Value::Record { val, .. }), Some(value)) => {
                let mut record = val.into_owned();
                record.insert(field_name, value);
                Some(nu_protocol::Value::record(record, Span::unknown()))
            }
            _ => None,
        };

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let projected_meta = RegMetadata {
            record_fields: fields,
            constant_value,
            ..Default::default()
        };
        self.emit_metadata_record_result(src_dst, result_vreg, projected_meta)
    }
}
