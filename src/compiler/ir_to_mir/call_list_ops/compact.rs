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
        if !self.named_args.is_empty() || !self.positional_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "compact does not accept column arguments for stack-backed numeric lists in eBPF"
                    .into(),
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
            .direct_list_builder_values(input_reg, input_vreg)
            .map(|values| values.to_vec())
        {
            let vals = values
                .into_iter()
                .filter(|value| Self::compact_keeps_value(value, remove_empty))
                .collect::<Vec<_>>();
            self.lower_constant_value(src_dst, &nu_protocol::Value::list(vals, Span::unknown()))?;
            return Ok(());
        }

        let input_meta = self.get_metadata(input_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "compact requires a pipeline input with tracked metadata in eBPF".into(),
            )
        })?;
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
