use super::*;
use crate::compiler::mir::AddressSpace;

const MAX_RECORD_COLUMNS_RESULTS: usize = 64;

impl<'a> HirToMirLowering<'a> {
    fn metadata_record_values_supported_field(meta: &RegMetadata, field: &RecordField) -> bool {
        let storage_is_numeric_scalar = matches!(
            field.ty,
            MirType::I8
                | MirType::I16
                | MirType::I32
                | MirType::I64
                | MirType::U8
                | MirType::U16
                | MirType::U32
                | MirType::U64
                | MirType::Bool
        );
        if !storage_is_numeric_scalar {
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
                    | nu_protocol::Value::Bool { .. }
                    | nu_protocol::Value::Nothing { .. }
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

    fn rename_column_arg(&self) -> Option<(VReg, RegId)> {
        self.named_args
            .get("column")
            .or_else(|| self.named_args.get("c"))
            .copied()
    }

    fn rename_block_arg(&self) -> Result<Option<NuBlockId>, CompileError> {
        let mut block_id = None;
        if let Some((_, reg)) = self
            .named_args
            .get("block")
            .or_else(|| self.named_args.get("b"))
        {
            block_id = Some(
                self.get_metadata(*reg)
                    .and_then(|meta| meta.closure_block_id)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "rename --block requires a compile-time closure in eBPF".into(),
                        )
                    })?,
            );
        }

        for (name, expr) in &self.parser_info_args {
            if !matches!(name.as_str(), "block" | "b") {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "rename does not accept parser info --{name} in eBPF"
                )));
            }
            let parser_block_id = expr.as_block().ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "rename --block requires a compile-time closure in eBPF".into(),
                )
            })?;
            if let Some(existing) = block_id {
                if existing != parser_block_id {
                    return Err(CompileError::UnsupportedInstruction(
                        "rename --block accepts exactly one closure in eBPF".into(),
                    ));
                }
            } else {
                block_id = Some(parser_block_id);
            }
        }

        Ok(block_id)
    }

    fn rename_block_string_transform_commands(
        &self,
        block_id: NuBlockId,
    ) -> Result<Vec<String>, CompileError> {
        let hir = self.closure_irs.get(&block_id).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "rename --block closure block {} not found",
                block_id.get()
            ))
        })?;
        if hir.blocks.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "rename --block supports only a straight-line string transform closure in eBPF"
                    .into(),
            ));
        }

        let mut commands = Vec::new();
        for block in &hir.blocks {
            for stmt in &block.stmts {
                match stmt {
                    HirStmt::LoadVariable { .. }
                    | HirStmt::StoreVariable { .. }
                    | HirStmt::DropVariable { .. }
                    | HirStmt::Move { .. }
                    | HirStmt::Clone { .. }
                    | HirStmt::Collect { .. }
                    | HirStmt::Span { .. }
                    | HirStmt::Drop { .. }
                    | HirStmt::Drain { .. }
                    | HirStmt::DrainIfEnd { .. }
                    | HirStmt::RedirectOut { .. }
                    | HirStmt::RedirectErr { .. }
                    | HirStmt::CheckErrRedirected { .. } => {}
                    HirStmt::Call { decl_id, args, .. } => {
                        if !args.positional.is_empty()
                            || !args.rest.is_empty()
                            || !args.named.is_empty()
                            || !args.flags.is_empty()
                            || !args.parser_info.is_empty()
                        {
                            return Err(CompileError::UnsupportedInstruction(
                                "rename --block supports only no-argument string transform commands in eBPF"
                                    .into(),
                            ));
                        }
                        let command = self
                            .decl_names
                            .get(decl_id)
                            .map(String::as_str)
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "rename --block closure command {} is unknown",
                                    decl_id.get()
                                ))
                            })?;
                        if !matches!(
                            command,
                            "str downcase"
                                | "str upcase"
                                | "str reverse"
                                | "str capitalize"
                                | "str camel-case"
                                | "str kebab-case"
                                | "str pascal-case"
                                | "str screaming-snake-case"
                                | "str snake-case"
                                | "str title-case"
                        ) {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "rename --block supports only known string transform commands in eBPF, got '{command}'"
                            )));
                        }
                        commands.push(command.to_string());
                    }
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "rename --block supports only a straight-line string transform closure in eBPF"
                                .into(),
                        ));
                    }
                }
            }

            if !matches!(
                block.terminator,
                HirTerminator::Return { .. } | HirTerminator::ReturnEarly { .. }
            ) {
                return Err(CompileError::UnsupportedInstruction(
                    "rename --block supports only a straight-line string transform closure in eBPF"
                        .into(),
                ));
            }
        }

        if commands.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "rename --block requires at least one string transform command in eBPF".into(),
            ));
        }
        Ok(commands)
    }

    fn rename_block_field_names(
        &self,
        block_id: NuBlockId,
        fields: &[RecordField],
    ) -> Result<Vec<String>, CompileError> {
        let commands = self.rename_block_string_transform_commands(block_id)?;
        fields
            .iter()
            .map(|field| {
                commands
                    .iter()
                    .try_fold(field.name.clone(), |name, command| {
                        Self::known_string_transform(command, name)
                    })
            })
            .collect()
    }

    fn rename_column_target_name(value: &nu_protocol::Value) -> Result<String, CompileError> {
        match value {
            nu_protocol::Value::String { val, .. } => Ok(val.clone()),
            nu_protocol::Value::CellPath { val, .. } => match val.members.as_slice() {
                [PathMember::String { val, .. }] => Ok(val.clone()),
                _ => Err(CompileError::UnsupportedInstruction(
                    "rename --column supports only top-level replacement field names in eBPF"
                        .into(),
                )),
            },
            _ => Err(CompileError::UnsupportedInstruction(
                "rename --column requires compile-time string replacement field names in eBPF"
                    .into(),
            )),
        }
    }

    fn rename_column_pairs(&self, reg: RegId) -> Result<Vec<(String, String)>, CompileError> {
        let Some(meta) = self.get_metadata(reg) else {
            return Err(CompileError::UnsupportedInstruction(
                "rename --column requires a compile-time record mapping in eBPF".into(),
            ));
        };
        let Some(nu_protocol::Value::Record { val, .. }) = meta.constant_value.as_ref() else {
            return Err(CompileError::UnsupportedInstruction(
                "rename --column requires a compile-time record mapping in eBPF".into(),
            ));
        };
        if val.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "rename --column requires a non-empty record mapping in eBPF".into(),
            ));
        }

        let mut pairs = Vec::with_capacity(val.len());
        for (source, target) in val.iter() {
            pairs.push((source.to_string(), Self::rename_column_target_name(target)?));
        }
        Ok(pairs)
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

    pub(super) fn top_level_field_name_arg(
        &self,
        reg: RegId,
        context: &str,
    ) -> Result<String, CompileError> {
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

        if !self.named_flags.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "rename does not accept named flags in eBPF".into(),
            ));
        }

        let block_rename = self.rename_block_arg()?;
        for name in self.named_args.keys() {
            if !matches!(name.as_str(), "column" | "c" | "block" | "b") {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "rename does not accept named argument --{name} in eBPF"
                )));
            }
        }

        let column_arg = self.rename_column_arg();
        if block_rename.is_some() && column_arg.is_some() {
            return Err(CompileError::UnsupportedInstruction(
                "rename --block cannot be combined with --column in eBPF".into(),
            ));
        }
        if block_rename.is_some() && !self.positional_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "rename --block cannot be combined with positional field names in eBPF".into(),
            ));
        }

        let column_renames = if let Some((_, column_reg)) = column_arg {
            if !self.positional_args.is_empty() {
                return Err(CompileError::UnsupportedInstruction(
                    "rename --column cannot be combined with positional field names in eBPF".into(),
                ));
            }
            Some(self.rename_column_pairs(column_reg)?)
        } else {
            None
        };

        let mut positional_names = Vec::new();
        if column_renames.is_none() {
            for (_, reg) in &self.positional_args {
                let name = self.top_level_field_name_arg(*reg, "rename")?;
                positional_names.push(name);
            }
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

        let block_names = block_rename
            .map(|block_id| self.rename_block_field_names(block_id, &input_meta.record_fields))
            .transpose()?;

        let mut renamed_fields = input_meta.record_fields.clone();
        if let Some(block_names) = block_names.as_ref() {
            for (field, name) in renamed_fields.iter_mut().zip(block_names) {
                field.name = name.clone();
            }
        } else if let Some(column_renames) = column_renames.as_ref() {
            for (source, target) in column_renames {
                let mut found = false;
                for field in &mut renamed_fields {
                    if field.name == *source {
                        field.name = target.clone();
                        found = true;
                    }
                }
                if !found {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "rename --column cannot find record field '{source}'"
                    )));
                }
            }
        } else {
            for (field, name) in renamed_fields.iter_mut().zip(positional_names.iter()) {
                field.name = name.clone();
            }
        }

        let constant_value = match input_meta.constant_value.clone() {
            Some(nu_protocol::Value::Record { val, .. }) => {
                let mut out = nu_protocol::Record::new();
                for (idx, (key, value)) in val.iter().enumerate() {
                    let out_key = if let Some(block_names) = block_names.as_ref() {
                        block_names.get(idx).unwrap_or(key).clone()
                    } else if let Some(column_renames) = column_renames.as_ref() {
                        column_renames
                            .iter()
                            .find_map(|(source, target)| (source == key).then_some(target.clone()))
                            .unwrap_or_else(|| key.to_string())
                    } else {
                        positional_names.get(idx).unwrap_or(key).clone()
                    };
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

        if let Some(nu_protocol::Value::Record { val, .. }) = input_meta.constant_value.as_ref() {
            let vals = val
                .iter()
                .map(|(_key, value)| value.clone())
                .collect::<Vec<_>>();
            let value_list = nu_protocol::Value::list(vals, Span::unknown());
            if self.current_call_result_metadata_only
                && !crate::compiler::hir::supports_numeric_constant_list(&value_list)
                && !crate::compiler::hir::supports_fixed_array_constant_list(&value_list)
                && Self::record_values_list_is_metadata_only_supported(&value_list)
            {
                self.lower_compile_time_only_constant_value(src_dst, &value_list);
                return Ok(());
            }
            if !crate::compiler::hir::supports_numeric_constant_list(&value_list)
                && crate::compiler::hir::supports_fixed_array_constant_list(&value_list)
            {
                self.lower_constant_value(src_dst, &value_list)?;
                return Ok(());
            }
        }

        if input_meta.record_fields.is_empty() && !input_is_known_empty_record {
            return Err(CompileError::UnsupportedInstruction(
                "values requires record input with compiler-known fields in eBPF".into(),
            ));
        }

        for field in &input_meta.record_fields {
            if !Self::metadata_record_values_supported_field(&input_meta, field) {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "values supports only numeric scalar record fields in eBPF; field '{}' has type {:?}",
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

    fn record_values_list_is_metadata_only_supported(value: &nu_protocol::Value) -> bool {
        matches!(
            value,
            nu_protocol::Value::List { vals, .. } if vals.iter().all(Self::record_values_metadata_only_value_supported)
        )
    }

    fn record_values_metadata_only_value_supported(value: &nu_protocol::Value) -> bool {
        match value {
            nu_protocol::Value::Bool { .. }
            | nu_protocol::Value::Int { .. }
            | nu_protocol::Value::Filesize { .. }
            | nu_protocol::Value::Duration { .. }
            | nu_protocol::Value::Nothing { .. }
            | nu_protocol::Value::Binary { .. }
            | nu_protocol::Value::String { .. }
            | nu_protocol::Value::Glob { .. } => true,
            nu_protocol::Value::Float { val, .. } => val.is_finite(),
            _ => false,
        }
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
        let input_is_known_empty_record = matches!(
            input_meta.constant_value.as_ref(),
            Some(nu_protocol::Value::Record { val, .. }) if val.is_empty()
        );
        if input_meta.record_fields.is_empty() && !input_is_known_empty_record {
            return Err(CompileError::UnsupportedInstruction(
                "columns requires record input with compiler-known fields in eBPF".into(),
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

    pub(super) fn lower_metadata_record_transpose(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let _ = dst_vreg;
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !self.named_args.is_empty() || !self.parser_info_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "transpose supports only record input and positional output column names in eBPF"
                    .into(),
            ));
        }
        let ignore_titles = match self.named_flags.as_slice() {
            [] => false,
            [flag] if matches!(flag.as_str(), "ignore-titles" | "i") => true,
            _ => {
                return Err(CompileError::UnsupportedInstruction(
                    "transpose supports only the --ignore-titles flag for record input in eBPF"
                        .into(),
                ));
            }
        };

        let mut output_names = ["column0".to_string(), "column1".to_string()];
        for (idx, (_, reg)) in self.positional_args.iter().enumerate() {
            let name = self.top_level_field_name_arg(*reg, "transpose")?;
            if idx < output_names.len() {
                output_names[idx] = name;
            }
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "transpose requires compile-time known record input in eBPF".into(),
                )
            })?;
        let Some(nu_protocol::Value::Record { val, .. }) = input_meta.constant_value.as_ref()
        else {
            return Err(CompileError::UnsupportedInstruction(
                "transpose requires compile-time known record values in eBPF".into(),
            ));
        };

        let mut rows = Vec::with_capacity(val.len());
        for (key, value) in val.iter() {
            let mut row = nu_protocol::Record::new();
            if ignore_titles {
                row.push(output_names[0].clone(), value.clone());
            } else {
                row.push(
                    output_names[0].clone(),
                    nu_protocol::Value::string(key.to_string(), Span::unknown()),
                );
                row.push(output_names[1].clone(), value.clone());
            }
            rows.push(nu_protocol::Value::record(row, Span::unknown()));
        }
        let value_list = nu_protocol::Value::list(rows, Span::unknown());

        if self.current_call_result_metadata_only {
            self.lower_compile_time_only_constant_value(src_dst, &value_list);
            return Ok(());
        }

        if crate::compiler::hir::supports_constant_value(&value_list) {
            self.lower_constant_value(src_dst, &value_list)?;
            return Ok(());
        }

        Err(CompileError::UnsupportedInstruction(
            "transpose output requires homogeneous row value layouts unless consumed by metadata-only fixed-list operations in eBPF"
                .into(),
        ))
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
        let scalar_constant = field_constant
            .as_ref()
            .and_then(Self::constant_scalar_i64)
            .map(MirValue::Const);
        let src = if let Some(src) = scalar_constant {
            src
        } else {
            MirValue::VReg(field.value_vreg)
        };
        self.emit(MirInst::Copy {
            dst: result_vreg,
            src,
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
