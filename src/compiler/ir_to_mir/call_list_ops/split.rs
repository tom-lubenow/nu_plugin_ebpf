use super::*;
use fancy_regex::Regex as FancyRegex;

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
        let mut use_regex = false;
        for flag in &self.named_flags {
            if flag == "regex" {
                use_regex = true;
            } else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "split list --{flag} is not supported in eBPF"
                )));
            }
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
        let regex = if use_regex {
            Some(Self::compile_time_split_list_regex(&separator)?)
        } else {
            None
        };
        let mode = self.split_list_mode()?;

        let mut groups = vec![Vec::new()];
        for value in input_values {
            let is_separator = if let Some(regex) = regex.as_ref() {
                Self::split_list_regex_matches(&value, regex)?
            } else {
                value == separator
            };
            if is_separator {
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

    fn compile_time_split_list_regex(
        separator: &nu_protocol::Value,
    ) -> Result<FancyRegex, CompileError> {
        let pattern = match separator {
            nu_protocol::Value::String { val, .. } | nu_protocol::Value::Glob { val, .. } => val,
            other => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "split list --regex separator must be a compile-time string in eBPF; got {}",
                    other.get_type()
                )));
            }
        };
        FancyRegex::new(pattern).map_err(|err| {
            CompileError::UnsupportedInstruction(format!(
                "split list --regex pattern is invalid in eBPF: {err}"
            ))
        })
    }

    fn split_list_regex_matches(
        value: &nu_protocol::Value,
        regex: &FancyRegex,
    ) -> Result<bool, CompileError> {
        let Some(text) = Self::split_list_regex_item_text(value)? else {
            return Ok(false);
        };
        regex.is_match(&text).map_err(|err| {
            CompileError::UnsupportedInstruction(format!(
                "split list --regex failed at compile time in eBPF: {err}"
            ))
        })
    }

    fn split_list_regex_item_text(
        value: &nu_protocol::Value,
    ) -> Result<Option<String>, CompileError> {
        match value {
            nu_protocol::Value::String { val, .. } | nu_protocol::Value::Glob { val, .. } => {
                Ok(Some(val.clone()))
            }
            nu_protocol::Value::Int { val, .. } => Ok(Some(val.to_string())),
            nu_protocol::Value::Bool { val, .. } => Ok(Some(val.to_string())),
            nu_protocol::Value::Nothing { .. }
            | nu_protocol::Value::Filesize { .. }
            | nu_protocol::Value::Duration { .. } => Ok(None),
            other => Err(CompileError::UnsupportedInstruction(format!(
                "split list --regex supports only string, int, bool, null, filesize, and duration compile-time list items in eBPF; got {}",
                other.get_type()
            ))),
        }
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
