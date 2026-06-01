use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SplitListMode {
    On,
    Before,
    After,
}

impl<'a> HirToMirLowering<'a> {
    pub(in crate::compiler::ir_to_mir) fn lower_compile_time_split_list(
        &mut self,
        src_dst: RegId,
        _dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        if let Some(flag) = self.named_flags.first() {
            if flag == "regex" {
                return Err(CompileError::UnsupportedInstruction(
                    "split list --regex is not supported in eBPF".into(),
                ));
            }
            return Err(CompileError::UnsupportedInstruction(format!(
                "split list --{flag} is not supported in eBPF"
            )));
        }
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "split list requires exactly one separator argument in eBPF".into(),
            ));
        }
        for key in self.named_args.keys() {
            if key != "split" {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "split list does not support named argument --{key} in eBPF"
                )));
            }
        }

        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "split list requires a compile-time known list pipeline input in eBPF".into(),
                )
            })?;
        let input_values = self
            .get_metadata(input_reg)
            .and_then(|meta| meta.constant_value.clone())
            .and_then(|value| match value {
                nu_protocol::Value::List { vals, .. } => Some(vals),
                _ => None,
            })
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "split list requires a compile-time known list pipeline input in eBPF".into(),
                )
            })?;

        let (_, separator_reg) = self.positional_args[0];
        let separator = self.compile_time_separator_value(separator_reg)?;
        let mode = self.split_list_mode()?;

        let mut groups = vec![Vec::new()];
        for value in input_values {
            if value == separator {
                match mode {
                    SplitListMode::On => groups.push(Vec::new()),
                    SplitListMode::Before => groups.push(vec![value]),
                    SplitListMode::After => {
                        groups
                            .last_mut()
                            .expect("split list always has a current group")
                            .push(value);
                        groups.push(Vec::new());
                    }
                }
            } else {
                groups
                    .last_mut()
                    .expect("split list always has a current group")
                    .push(value);
            }
        }

        let result = nu_protocol::Value::list(
            groups
                .into_iter()
                .map(|group| nu_protocol::Value::list(group, Span::unknown()))
                .collect(),
            Span::unknown(),
        );
        if !crate::compiler::hir::supports_constant_value(&result) {
            return Err(CompileError::UnsupportedInstruction(
                "split list result requires homogeneous fixed-layout groups in eBPF".into(),
            ));
        }

        self.lower_constant_value(src_dst, &result)?;
        Ok(())
    }

    fn compile_time_separator_value(
        &self,
        separator_reg: RegId,
    ) -> Result<nu_protocol::Value, CompileError> {
        self.get_metadata(separator_reg)
            .and_then(|meta| {
                meta.constant_value.clone().or_else(|| {
                    meta.literal_int
                        .map(|value| nu_protocol::Value::int(value, Span::unknown()))
                })
            })
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "split list separator must be compile-time known in eBPF".into(),
                )
            })
    }

    fn split_list_mode(&self) -> Result<SplitListMode, CompileError> {
        let Some((_, mode_reg)) = self.named_args.get("split").copied() else {
            return Ok(SplitListMode::On);
        };
        let mode = self
            .get_metadata(mode_reg)
            .and_then(|meta| match meta.constant_value.as_ref() {
                Some(nu_protocol::Value::String { val, .. })
                | Some(nu_protocol::Value::Glob { val, .. }) => Some(val.as_str()),
                _ => None,
            })
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "split list --split requires a compile-time known string in eBPF".into(),
                )
            })?;

        match mode {
            "on" => Ok(SplitListMode::On),
            "before" => Ok(SplitListMode::Before),
            "after" => Ok(SplitListMode::After),
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "split list --split must be 'on', 'before', or 'after' in eBPF, got '{mode}'"
            ))),
        }
    }
}
