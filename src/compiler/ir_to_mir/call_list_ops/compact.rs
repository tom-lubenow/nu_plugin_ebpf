use super::*;

impl<'a> HirToMirLowering<'a> {
    pub(in crate::compiler::ir_to_mir) fn lower_stack_list_compact(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        if let Some(flag) = self
            .named_flags
            .iter()
            .find(|flag| flag.as_str() != "empty")
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "compact --{flag} is not supported for stack-backed numeric lists in eBPF"
            )));
        }
        if !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "compact does not accept named arguments in eBPF".into(),
            ));
        }
        let remove_empty = self.named_flags.iter().any(|flag| flag == "empty");

        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let input_reg = input_reg.ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "compact requires a pipeline input with tracked metadata in eBPF".into(),
            )
        })?;

        if let Some(values) = self
            .compile_time_only_list_builder_values(input_reg, input_vreg)
            .map(|values| values.to_vec())
        {
            let columns = self.compact_column_names()?;
            if !columns.is_empty()
                && !values
                    .iter()
                    .all(|value| matches!(value, nu_protocol::Value::Record { .. }))
            {
                return Err(CompileError::UnsupportedInstruction(
                    "compact does not accept column arguments for non-record fixed lists in eBPF"
                        .into(),
                ));
            }
            let vals = values
                .into_iter()
                .filter(|value| {
                    Self::compact_keeps_value_for_columns(value, remove_empty, &columns)
                })
                .collect::<Vec<_>>();
            self.lower_compile_time_list_transform_result(
                src_dst,
                &nu_protocol::Value::list(vals, Span::unknown()),
            )?;
            return Ok(());
        }

        if !self.positional_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "compact does not accept column arguments for stack-backed numeric lists in eBPF"
                    .into(),
            ));
        }

        let input_meta = self.get_metadata(input_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "compact requires a pipeline input with tracked metadata in eBPF".into(),
            )
        })?;
        if self.lower_typed_fixed_array_compact_identity(
            src_dst,
            dst_vreg,
            src_dst_had_value,
            input_reg,
            input_vreg,
            &input_meta,
            remove_empty,
        )? {
            return Ok(());
        }
        if input_meta.list_buffer.is_none() {
            return Err(CompileError::UnsupportedInstruction(
                "compact requires a stack-backed numeric list input in eBPF".into(),
            ));
        }

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        self.emit(MirInst::Copy {
            dst: result_vreg,
            src: MirValue::VReg(input_vreg),
        });
        self.propagate_passthrough_reg_metadata(src_dst, result_vreg, input_reg, input_vreg);
        Ok(())
    }

    fn lower_typed_fixed_array_compact_identity(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        input_reg: RegId,
        mut input_vreg: VReg,
        input_meta: &RegMetadata,
        remove_empty: bool,
    ) -> Result<bool, CompileError> {
        if matches!(
            input_meta.constant_value,
            Some(nu_protocol::Value::List { .. })
        ) && !matches!(
            input_meta.annotated_semantics,
            Some(AnnotatedValueSemantics::FixedArray { .. })
        ) {
            return Ok(false);
        }

        let Some(mut base_runtime_ty) = self.typed_value_runtime_type(input_reg, input_vreg) else {
            return Ok(false);
        };
        let Some(elem_ty) =
            Self::aggregate_call_value_type(&base_runtime_ty).and_then(|ty| match ty {
                MirType::Array { elem, .. } => Some(elem.as_ref().clone()),
                _ => None,
            })
        else {
            return Ok(false);
        };

        let elem_semantics = match input_meta.annotated_semantics.as_ref() {
            Some(AnnotatedValueSemantics::FixedArray { elem, .. }) => Some(elem.as_ref()),
            _ => None,
        };
        let always_kept = Self::typed_fixed_array_compact_identity_always_kept_type(&elem_ty);
        if remove_empty && !always_kept {
            return Err(CompileError::UnsupportedInstruction(format!(
                "compact --empty on typed fixed arrays currently supports only numeric or bool elements in eBPF, got {:?}",
                elem_ty
            )));
        }
        if !always_kept
            && !Self::typed_fixed_array_compact_identity_default_semantics(elem_semantics)
        {
            return Ok(false);
        }

        if !matches!(base_runtime_ty, MirType::Ptr { .. })
            && Self::aggregate_call_value_type(&base_runtime_ty).is_some()
        {
            input_vreg = self.materialized_metadata_aggregate_vreg(input_reg, input_vreg)?;
            base_runtime_ty = self
                .typed_value_runtime_type(input_reg, input_vreg)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "compact requires typed fixed-array input in eBPF".into(),
                    )
                })?;
        }

        let MirType::Ptr { address_space, .. } = base_runtime_ty else {
            return Err(CompileError::UnsupportedInstruction(
                "compact requires typed fixed-array pointer input in eBPF".into(),
            ));
        };
        if !matches!(
            address_space,
            AddressSpace::Stack | AddressSpace::Map | AddressSpace::Context
        ) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "compact on typed fixed-array pointers in {address_space:?} address space is not yet supported in eBPF"
            )));
        }

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        self.emit(MirInst::Copy {
            dst: result_vreg,
            src: MirValue::VReg(input_vreg),
        });
        self.propagate_passthrough_reg_metadata(src_dst, result_vreg, input_reg, input_vreg);
        Ok(true)
    }

    fn typed_fixed_array_compact_identity_always_kept_type(ty: &MirType) -> bool {
        matches!(
            ty,
            MirType::I8
                | MirType::I16
                | MirType::I32
                | MirType::I64
                | MirType::U8
                | MirType::U16
                | MirType::U32
                | MirType::U64
                | MirType::Bool
        )
    }

    fn typed_fixed_array_compact_identity_default_semantics(
        semantics: Option<&AnnotatedValueSemantics>,
    ) -> bool {
        matches!(
            semantics,
            Some(
                AnnotatedValueSemantics::String { .. }
                    | AnnotatedValueSemantics::Binary { .. }
                    | AnnotatedValueSemantics::NumericList { .. }
                    | AnnotatedValueSemantics::Record(_)
                    | AnnotatedValueSemantics::FixedArray { .. }
            )
        )
    }

    fn compact_column_names(&self) -> Result<Vec<String>, CompileError> {
        let mut columns = Vec::with_capacity(self.positional_args.len());
        for (_, reg) in &self.positional_args {
            columns.push(self.top_level_field_name_arg(*reg, "compact")?);
        }
        Ok(columns)
    }

    fn compact_keeps_value_for_columns(
        value: &nu_protocol::Value,
        remove_empty: bool,
        columns: &[String],
    ) -> bool {
        if columns.is_empty() {
            return Self::compact_keeps_value(value, remove_empty);
        }

        let nu_protocol::Value::Record { val, .. } = value else {
            return true;
        };

        columns.iter().all(|column| {
            val.get(column)
                .is_some_and(|value| Self::compact_keeps_value(value, remove_empty))
        })
    }

    fn compact_keeps_value(value: &nu_protocol::Value, remove_empty: bool) -> bool {
        match value {
            nu_protocol::Value::Nothing { .. } => false,
            nu_protocol::Value::String { val, .. } => !remove_empty || !val.is_empty(),
            nu_protocol::Value::Binary { val, .. } => !remove_empty || !val.is_empty(),
            nu_protocol::Value::List { vals, .. } => !remove_empty || !vals.is_empty(),
            nu_protocol::Value::Record { val, .. } => !remove_empty || !val.is_empty(),
            _ => true,
        }
    }
}
