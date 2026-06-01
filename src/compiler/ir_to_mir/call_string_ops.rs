use super::*;
use unicode_segmentation::UnicodeSegmentation;

struct KnownStringSearchOperands {
    input_slot: StackSlotId,
    input_slot_size: usize,
    input_len: usize,
    needle_slot: StackSlotId,
    needle_len: usize,
}

impl<'a> HirToMirLowering<'a> {
    pub(super) fn lower_string_length(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        if !self.named_flags.is_empty()
            || !self.named_args.is_empty()
            || !self.positional_args.is_empty()
        {
            return Err(CompileError::UnsupportedInstruction(
                "str length does not accept arguments in eBPF".into(),
            ));
        }

        let input_meta = input_reg.and_then(|reg| self.get_metadata(reg).cloned());
        if let Some(len_vreg) = input_meta.as_ref().and_then(|meta| {
            meta.string_len_vreg.or_else(|| match &meta.constant_value {
                Some(nu_protocol::Value::String { val, .. }) => {
                    let const_len_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::Copy {
                        dst: const_len_vreg,
                        src: MirValue::Const(val.len() as i64),
                    });
                    self.vreg_type_hints.insert(const_len_vreg, MirType::I64);
                    Some(const_len_vreg)
                }
                _ => None,
            })
        }) {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::VReg(len_vreg),
            });
        } else {
            return Err(CompileError::UnsupportedInstruction(
                "str length requires a tracked string input in eBPF".into(),
            ));
        }

        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(MirType::I64);
        self.vreg_type_hints.insert(result_vreg, MirType::I64);
        Ok(())
    }

    pub(super) fn lower_string_starts_with(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        if !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "str starts-with does not accept named arguments in eBPF".into(),
            ));
        }
        let ignore_case = self.string_ignore_case_flag("str starts-with")?;
        let (_, prefix_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str starts-with requires a string prefix argument in eBPF".into(),
            )
        })?;
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "str starts-with accepts exactly one prefix argument in eBPF".into(),
            ));
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "str starts-with requires tracked string input in eBPF".into(),
                )
            })?;
        let Some(input_slot) = input_meta.string_slot else {
            return Err(CompileError::UnsupportedInstruction(
                "str starts-with requires tracked string input in eBPF".into(),
            ));
        };
        let input_slot_size = self.stack_slot_size(input_slot).ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str starts-with could not determine input string capacity in eBPF".into(),
            )
        })?;

        let prefix = self.literal_string_arg(prefix_reg, "str starts-with")?;
        if prefix.as_bytes().contains(&0) {
            return Err(CompileError::UnsupportedInstruction(
                "str starts-with does not support NUL bytes in the prefix in eBPF".into(),
            ));
        }
        if ignore_case {
            let input = self.exact_string_input(input_reg, "str starts-with --ignore-case")?;
            let matches = input.to_lowercase().starts_with(&prefix.to_lowercase());
            return self.lower_bool_result(src_dst, result_vreg, matches);
        }

        let prefix_meta = self.get_metadata(prefix_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str starts-with requires a tracked string prefix in eBPF".into(),
            )
        })?;
        let Some(prefix_slot) = prefix_meta.string_slot else {
            return Err(CompileError::UnsupportedInstruction(
                "str starts-with requires a tracked string prefix in eBPF".into(),
            ));
        };
        let prefix_len = prefix.len();

        if prefix_len == 0 {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(1),
            });
        } else if prefix_len > input_slot_size.saturating_sub(1) {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(0),
            });
        } else {
            self.emit(MirInst::StrCmp {
                dst: result_vreg,
                lhs: input_slot,
                lhs_offset: 0,
                rhs: prefix_slot,
                rhs_offset: 0,
                len: prefix_len,
            });
        }

        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(MirType::Bool);
        self.vreg_type_hints.insert(result_vreg, MirType::Bool);
        Ok(())
    }

    pub(super) fn lower_string_ends_with(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        if !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "str ends-with does not accept named arguments in eBPF".into(),
            ));
        }
        let ignore_case = self.string_ignore_case_flag("str ends-with")?;
        let (_, suffix_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str ends-with requires a string suffix argument in eBPF".into(),
            )
        })?;
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "str ends-with accepts exactly one suffix argument in eBPF".into(),
            ));
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "str ends-with requires tracked string input in eBPF".into(),
                )
            })?;
        let Some(input_slot) = input_meta.string_slot else {
            return Err(CompileError::UnsupportedInstruction(
                "str ends-with requires tracked string input in eBPF".into(),
            ));
        };
        let input_slot_size = self.stack_slot_size(input_slot).ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str ends-with could not determine input string capacity in eBPF".into(),
            )
        })?;
        let input_len = Self::exact_string_len(&input_meta).ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str ends-with requires a compile-time known input string length in eBPF".into(),
            )
        })?;

        let suffix = self.literal_string_arg(suffix_reg, "str ends-with")?;
        if suffix.as_bytes().contains(&0) {
            return Err(CompileError::UnsupportedInstruction(
                "str ends-with does not support NUL bytes in the suffix in eBPF".into(),
            ));
        }
        if ignore_case {
            let input = self.exact_string_input(input_reg, "str ends-with --ignore-case")?;
            let matches = input.to_lowercase().ends_with(&suffix.to_lowercase());
            return self.lower_bool_result(src_dst, result_vreg, matches);
        }

        let suffix_meta = self.get_metadata(suffix_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str ends-with requires a tracked string suffix in eBPF".into(),
            )
        })?;
        let Some(suffix_slot) = suffix_meta.string_slot else {
            return Err(CompileError::UnsupportedInstruction(
                "str ends-with requires a tracked string suffix in eBPF".into(),
            ));
        };
        let suffix_len = suffix.len();

        if suffix_len == 0 {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(1),
            });
        } else if suffix_len > input_len || input_len > input_slot_size.saturating_sub(1) {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(0),
            });
        } else {
            self.emit(MirInst::StrCmp {
                dst: result_vreg,
                lhs: input_slot,
                lhs_offset: input_len - suffix_len,
                rhs: suffix_slot,
                rhs_offset: 0,
                len: suffix_len,
            });
        }

        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(MirType::Bool);
        self.vreg_type_hints.insert(result_vreg, MirType::Bool);
        Ok(())
    }

    pub(super) fn lower_string_contains(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        if !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "str contains does not accept named arguments in eBPF".into(),
            ));
        }
        let ignore_case = self.string_ignore_case_flag("str contains")?;
        let (_, needle_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str contains requires a string substring argument in eBPF".into(),
            )
        })?;
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "str contains accepts exactly one substring argument in eBPF".into(),
            ));
        }

        if ignore_case {
            let input = self.exact_string_input(input_reg, "str contains --ignore-case")?;
            let needle = self.literal_string_arg(needle_reg, "str contains")?;
            if needle.as_bytes().contains(&0) {
                return Err(CompileError::UnsupportedInstruction(
                    "str contains does not support NUL bytes in the substring in eBPF".into(),
                ));
            }
            let matches = input.to_lowercase().contains(&needle.to_lowercase());
            return self.lower_bool_result(src_dst, result_vreg, matches);
        }

        let operands = self.known_string_search_operands(input_reg, needle_reg, "str contains")?;

        if operands.needle_len == 0 {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(1),
            });
        } else if operands.needle_len > operands.input_len
            || operands.input_len > operands.input_slot_size.saturating_sub(1)
        {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(0),
            });
        } else {
            let found_block = self.func.alloc_block();
            let not_found_block = self.func.alloc_block();
            let continuation_block = self.func.alloc_block();
            let last_offset = operands.input_len - operands.needle_len;

            for offset in 0..=last_offset {
                let next_block = if offset == last_offset {
                    not_found_block
                } else {
                    self.func.alloc_block()
                };
                let candidate_vreg = self.func.alloc_vreg();
                self.emit(MirInst::StrCmp {
                    dst: candidate_vreg,
                    lhs: operands.input_slot,
                    lhs_offset: offset,
                    rhs: operands.needle_slot,
                    rhs_offset: 0,
                    len: operands.needle_len,
                });
                self.vreg_type_hints.insert(candidate_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: candidate_vreg,
                    if_true: found_block,
                    if_false: next_block,
                });
                self.current_block = next_block;
            }

            self.current_block = found_block;
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(1),
            });
            self.terminate(MirInst::Jump {
                target: continuation_block,
            });

            self.current_block = not_found_block;
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(0),
            });
            self.terminate(MirInst::Jump {
                target: continuation_block,
            });

            self.current_block = continuation_block;
        }

        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(MirType::Bool);
        self.vreg_type_hints.insert(result_vreg, MirType::Bool);
        Ok(())
    }

    pub(super) fn lower_string_index_of(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        let (search_from_end, use_grapheme_clusters) = self.string_index_of_flags()?;
        let (_, needle_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "str index-of requires a string substring argument in eBPF".into(),
            )
        })?;
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "str index-of accepts exactly one substring argument in eBPF".into(),
            ));
        }

        if use_grapheme_clusters {
            let input = self.exact_string_input(input_reg, "str index-of --grapheme-clusters")?;
            let needle = self.literal_string_arg(needle_reg, "str index-of")?;
            if needle.as_bytes().contains(&0) {
                return Err(CompileError::UnsupportedInstruction(
                    "str index-of does not support NUL bytes in the substring in eBPF".into(),
                ));
            }
            let (search_start, search_end) = self.string_index_of_search_bounds(input.len())?;
            let index = Self::grapheme_index_of_in_byte_range(
                &input,
                &needle,
                search_from_end,
                search_start,
                search_end,
            )?;
            return self.lower_i64_result(src_dst, result_vreg, index);
        }

        let operands = self.known_string_search_operands(input_reg, needle_reg, "str index-of")?;
        let (search_start, search_end) = self.string_index_of_search_bounds(operands.input_len)?;

        if operands.needle_len == 0 {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(if search_from_end {
                    search_end as i64
                } else {
                    search_start as i64
                }),
            });
        } else if operands.needle_len > operands.input_len
            || search_start.saturating_add(operands.needle_len) > search_end
            || operands.input_len > operands.input_slot_size.saturating_sub(1)
        {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(-1),
            });
        } else {
            let not_found_block = self.func.alloc_block();
            let continuation_block = self.func.alloc_block();
            let last_offset = search_end - operands.needle_len;

            let offsets: Box<dyn Iterator<Item = usize>> = if search_from_end {
                Box::new((search_start..=last_offset).rev())
            } else {
                Box::new(search_start..=last_offset)
            };

            for offset in offsets {
                let found_block = self.func.alloc_block();
                let is_last_probe = if search_from_end {
                    offset == search_start
                } else {
                    offset == last_offset
                };
                let next_block = if is_last_probe {
                    not_found_block
                } else {
                    self.func.alloc_block()
                };
                let candidate_vreg = self.func.alloc_vreg();
                self.emit(MirInst::StrCmp {
                    dst: candidate_vreg,
                    lhs: operands.input_slot,
                    lhs_offset: offset,
                    rhs: operands.needle_slot,
                    rhs_offset: 0,
                    len: operands.needle_len,
                });
                self.vreg_type_hints.insert(candidate_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: candidate_vreg,
                    if_true: found_block,
                    if_false: next_block,
                });

                self.current_block = found_block;
                self.emit(MirInst::Copy {
                    dst: result_vreg,
                    src: MirValue::Const(offset as i64),
                });
                self.terminate(MirInst::Jump {
                    target: continuation_block,
                });

                self.current_block = next_block;
            }

            self.current_block = not_found_block;
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(-1),
            });
            self.terminate(MirInst::Jump {
                target: continuation_block,
            });

            self.current_block = continuation_block;
        }

        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(MirType::I64);
        self.vreg_type_hints.insert(result_vreg, MirType::I64);
        Ok(())
    }

    pub(super) fn lower_string_substring(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        if !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "str substring does not accept named arguments in eBPF".into(),
            ));
        }
        let use_grapheme_clusters = self.string_grapheme_cluster_indexing_flag("str substring")?;
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "str substring requires exactly one explicit range argument in eBPF".into(),
            ));
        }

        let input = self.exact_string_input(input_reg, "str substring")?;
        let range_reg = self.positional_args[0].1;
        let range = self
            .get_metadata(range_reg)
            .and_then(|meta| meta.maybe_open_range)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "str substring requires a compile-time known range argument in eBPF".into(),
                )
            })?;
        if range.step != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "str substring currently supports only default unit-step ranges in eBPF".into(),
            ));
        }

        if use_grapheme_clusters {
            let graphemes: Vec<&str> =
                UnicodeSegmentation::graphemes(input.as_str(), true).collect();
            let (start, end) = Self::string_range_byte_bounds(range, graphemes.len());
            let output = graphemes[start..end].concat();
            return self.lower_known_string_result(src_dst, result_vreg, output);
        }

        let (start, end) = Self::string_range_byte_bounds(range, input.len());
        let bytes = input.as_bytes().get(start..end).ok_or_else(|| {
            CompileError::UnsupportedInstruction("invalid substring bounds".into())
        })?;
        let output = String::from_utf8(bytes.to_vec()).map_err(|_| {
            CompileError::UnsupportedInstruction(
                "str substring byte bounds must preserve valid UTF-8 in eBPF".into(),
            )
        })?;

        self.lower_known_string_result(src_dst, result_vreg, output)
    }

    pub(super) fn lower_string_replace(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        if !self.named_args.is_empty() || self.named_flags.iter().any(|flag| flag != "all") {
            return Err(CompileError::UnsupportedInstruction(
                "str replace currently supports only default substring replacement and --all in eBPF"
                    .into(),
            ));
        }
        if self.positional_args.len() != 2 {
            return Err(CompileError::UnsupportedInstruction(
                "str replace requires exactly two string arguments in eBPF".into(),
            ));
        }

        let input = self.exact_string_input(input_reg, "str replace")?;
        let find = self.literal_string_arg(self.positional_args[0].1, "str replace find")?;
        let replacement =
            self.literal_string_arg(self.positional_args[1].1, "str replace replacement")?;

        let replace_all = self.named_flags.iter().any(|flag| flag == "all");
        let output = if replace_all {
            input.replace(&find, &replacement)
        } else {
            input.replacen(&find, &replacement, 1)
        };
        self.lower_known_string_result(src_dst, result_vreg, output)
    }

    pub(super) fn lower_string_trim(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        if !self.positional_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "str trim does not support cell-path arguments in eBPF".into(),
            ));
        }
        if self
            .named_flags
            .iter()
            .any(|flag| flag != "left" && flag != "right")
        {
            return Err(CompileError::UnsupportedInstruction(
                "str trim currently supports only --left, --right, and --char in eBPF".into(),
            ));
        }
        for key in self.named_args.keys() {
            if key != "char" {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "str trim does not support named argument --{key} in eBPF"
                )));
            }
        }

        let input = self.exact_string_input(input_reg, "str trim")?;
        let trim_char = if let Some((_, char_reg)) = self.named_args.get("char").copied() {
            let raw = self.literal_string_arg(char_reg, "str trim --char")?;
            let mut chars = raw.chars();
            let Some(ch) = chars.next() else {
                return Err(CompileError::UnsupportedInstruction(
                    "str trim --char requires exactly one character in eBPF".into(),
                ));
            };
            if chars.next().is_some() {
                return Err(CompileError::UnsupportedInstruction(
                    "str trim --char requires exactly one character in eBPF".into(),
                ));
            }
            Some(ch)
        } else {
            None
        };

        let trim_left = self.named_flags.iter().any(|flag| flag == "left");
        let trim_right = self.named_flags.iter().any(|flag| flag == "right");
        let output = match (trim_char, trim_left, trim_right) {
            (Some(ch), true, false) => input.trim_start_matches(ch).to_string(),
            (Some(ch), false, true) => input.trim_end_matches(ch).to_string(),
            (Some(ch), _, _) => input.trim_matches(ch).to_string(),
            (None, true, false) => input.trim_start().to_string(),
            (None, false, true) => input.trim_end().to_string(),
            (None, _, _) => input.trim().to_string(),
        };
        self.lower_known_string_result(src_dst, result_vreg, output)
    }

    pub(super) fn lower_known_string_transform(
        &mut self,
        command: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        if !self.named_flags.is_empty()
            || !self.named_args.is_empty()
            || !self.positional_args.is_empty()
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{command} currently supports only the default no-argument form in eBPF"
            )));
        }

        let input = self.exact_string_input(input_reg, command)?;
        let output = match command {
            "str downcase" => input.to_lowercase(),
            "str upcase" => input.to_uppercase(),
            "str reverse" => input.chars().rev().collect(),
            "str capitalize" => Self::capitalize_first_char(&input),
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "unsupported string transform command '{command}'"
                )));
            }
        };

        self.lower_known_string_result(src_dst, result_vreg, output)
    }

    fn exact_string_input(
        &self,
        input_reg: Option<RegId>,
        command: &str,
    ) -> Result<String, CompileError> {
        input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .and_then(|meta| Self::exact_string_value(&meta))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{command} requires compile-time known string input in eBPF"
                ))
            })
    }

    fn lower_known_string_result(
        &mut self,
        src_dst: RegId,
        result_vreg: VReg,
        output: String,
    ) -> Result<(), CompileError> {
        self.reset_call_result_metadata(src_dst);
        self.lower_string_like_literal(src_dst, result_vreg, output.as_bytes())?;
        self.set_reg_constant_value(
            src_dst,
            Some(nu_protocol::Value::string(output, Span::unknown())),
        );
        Ok(())
    }

    fn lower_bool_result(
        &mut self,
        src_dst: RegId,
        result_vreg: VReg,
        value: bool,
    ) -> Result<(), CompileError> {
        self.emit(MirInst::Copy {
            dst: result_vreg,
            src: MirValue::Const(if value { 1 } else { 0 }),
        });
        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(MirType::Bool);
        self.vreg_type_hints.insert(result_vreg, MirType::Bool);
        Ok(())
    }

    fn lower_i64_result(
        &mut self,
        src_dst: RegId,
        result_vreg: VReg,
        value: i64,
    ) -> Result<(), CompileError> {
        self.emit(MirInst::Copy {
            dst: result_vreg,
            src: MirValue::Const(value),
        });
        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(MirType::I64);
        self.vreg_type_hints.insert(result_vreg, MirType::I64);
        Ok(())
    }

    fn string_ignore_case_flag(&self, command: &str) -> Result<bool, CompileError> {
        for flag in &self.named_flags {
            if flag != "ignore-case" {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{command} currently supports only --ignore-case as a flag in eBPF"
                )));
            }
        }
        Ok(self.named_flags.iter().any(|flag| flag == "ignore-case"))
    }

    fn string_index_of_flags(&self) -> Result<(bool, bool), CompileError> {
        let mut from_end = false;
        let mut use_grapheme_clusters = false;
        let mut use_utf8_bytes = false;
        for flag in &self.named_flags {
            match flag.as_str() {
                "end" => from_end = true,
                "utf-8-bytes" => use_utf8_bytes = true,
                "grapheme-clusters" => use_grapheme_clusters = true,
                _ => {
                    return Err(CompileError::UnsupportedInstruction(
                        "str index-of currently supports only --end, --utf-8-bytes, and --grapheme-clusters flags in eBPF"
                            .into(),
                    ));
                }
            }
        }
        if use_grapheme_clusters && use_utf8_bytes {
            return Err(CompileError::UnsupportedInstruction(
                "str index-of accepts either --utf-8-bytes or --grapheme-clusters, not both, in eBPF"
                    .into(),
            ));
        }
        Ok((from_end, use_grapheme_clusters))
    }

    fn string_grapheme_cluster_indexing_flag(&self, command: &str) -> Result<bool, CompileError> {
        let mut use_grapheme_clusters = false;
        let mut use_utf8_bytes = false;
        for flag in &self.named_flags {
            match flag.as_str() {
                "grapheme-clusters" => use_grapheme_clusters = true,
                "utf-8-bytes" => use_utf8_bytes = true,
                _ => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{command} currently supports only --utf-8-bytes and --grapheme-clusters flags in eBPF"
                    )));
                }
            }
        }
        if use_grapheme_clusters && use_utf8_bytes {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{command} accepts either --utf-8-bytes or --grapheme-clusters, not both, in eBPF"
            )));
        }
        Ok(use_grapheme_clusters)
    }

    fn string_index_of_search_bounds(
        &self,
        input_len: usize,
    ) -> Result<(usize, usize), CompileError> {
        for key in self.named_args.keys() {
            if key != "range" {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "str index-of does not support named argument --{key} in eBPF"
                )));
            }
        }

        let Some((_, range_reg)) = self.named_args.get("range").copied() else {
            return Ok((0, input_len));
        };
        let range = self
            .get_metadata(range_reg)
            .and_then(|meta| meta.maybe_open_range)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "str index-of --range requires a compile-time known range in eBPF".into(),
                )
            })?;
        if range.step != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "str index-of --range currently supports only default unit-step ranges in eBPF"
                    .into(),
            ));
        }

        Ok(Self::string_range_byte_bounds(range, input_len))
    }

    fn capitalize_first_char(input: &str) -> String {
        let mut chars = input.chars();
        let Some(first) = chars.next() else {
            return String::new();
        };

        let mut output = first.to_uppercase().collect::<String>();
        output.push_str(chars.as_str());
        output
    }

    fn string_range_byte_bounds(range: MaybeOpenRange, len: usize) -> (usize, usize) {
        let len = len as i64;
        let start = range
            .start
            .map(|start| Self::substring_start_bound(start, len))
            .unwrap_or(0);
        let end = range
            .end
            .map(|end| Self::substring_end_bound(end, range.inclusive, len))
            .unwrap_or(len)
            .max(start);
        (start as usize, end as usize)
    }

    fn substring_start_bound(index: i64, len: i64) -> i64 {
        let raw = if index < 0 {
            len.saturating_add(index)
        } else {
            index
        };
        raw.clamp(0, len)
    }

    fn substring_end_bound(index: i64, inclusive: bool, len: i64) -> i64 {
        let raw = if index < 0 {
            len.saturating_add(index)
        } else {
            index
        };
        let exclusive = if inclusive {
            raw.saturating_add(1)
        } else {
            raw
        };
        exclusive.clamp(0, len)
    }

    fn grapheme_index_of(input: &str, needle: &str, search_from_end: bool) -> i64 {
        let input_graphemes: Vec<&str> = UnicodeSegmentation::graphemes(input, true).collect();
        let needle_graphemes: Vec<&str> = UnicodeSegmentation::graphemes(needle, true).collect();

        if needle_graphemes.is_empty() {
            return if search_from_end {
                input_graphemes.len() as i64
            } else {
                0
            };
        }

        if needle_graphemes.len() > input_graphemes.len() {
            return -1;
        }

        let last_offset = input_graphemes.len() - needle_graphemes.len();
        let offsets: Box<dyn Iterator<Item = usize>> = if search_from_end {
            Box::new((0..=last_offset).rev())
        } else {
            Box::new(0..=last_offset)
        };

        offsets
            .filter(|offset| {
                input_graphemes[*offset..*offset + needle_graphemes.len()] == needle_graphemes
            })
            .map(|offset| offset as i64)
            .next()
            .unwrap_or(-1)
    }

    fn grapheme_index_of_in_byte_range(
        input: &str,
        needle: &str,
        search_from_end: bool,
        search_start: usize,
        search_end: usize,
    ) -> Result<i64, CompileError> {
        let Some(search_input) = input.get(search_start..search_end) else {
            return Err(CompileError::UnsupportedInstruction(
                "str index-of --grapheme-clusters --range bounds must align to UTF-8 character boundaries in eBPF"
                    .into(),
            ));
        };
        let Some(prefix) = input.get(..search_start) else {
            return Err(CompileError::UnsupportedInstruction(
                "str index-of --grapheme-clusters --range start must align to a UTF-8 character boundary in eBPF"
                    .into(),
            ));
        };

        let local_index = Self::grapheme_index_of(search_input, needle, search_from_end);
        if local_index < 0 {
            return Ok(-1);
        }

        let prefix_graphemes = UnicodeSegmentation::graphemes(prefix, true).count() as i64;
        Ok(prefix_graphemes + local_index)
    }

    fn known_string_search_operands(
        &self,
        input_reg: Option<RegId>,
        needle_reg: RegId,
        command: &str,
    ) -> Result<KnownStringSearchOperands, CompileError> {
        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{command} requires tracked string input in eBPF"
                ))
            })?;
        let input_slot = input_meta.string_slot.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{command} requires tracked string input in eBPF"
            ))
        })?;
        let input_slot_size = self.stack_slot_size(input_slot).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{command} could not determine input string capacity in eBPF"
            ))
        })?;
        let input_len = Self::exact_string_len(&input_meta).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{command} requires a compile-time known input string length in eBPF"
            ))
        })?;

        let needle = self.literal_string_arg(needle_reg, command)?;
        if needle.as_bytes().contains(&0) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{command} does not support NUL bytes in the substring in eBPF"
            )));
        }
        let needle_meta = self.get_metadata(needle_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{command} requires a tracked string substring in eBPF"
            ))
        })?;
        let needle_slot = needle_meta.string_slot.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{command} requires a tracked string substring in eBPF"
            ))
        })?;

        Ok(KnownStringSearchOperands {
            input_slot,
            input_slot_size,
            input_len,
            needle_slot,
            needle_len: needle.len(),
        })
    }

    fn exact_string_len(meta: &RegMetadata) -> Option<usize> {
        match &meta.constant_value {
            Some(nu_protocol::Value::String { val, .. }) => Some(val.len()),
            Some(nu_protocol::Value::Glob { val, .. }) => Some(val.len()),
            Some(nu_protocol::Value::Binary { val, .. }) => Some(val.len()),
            _ => meta.literal_string.as_ref().map(|val| val.len()),
        }
    }

    fn exact_string_value(meta: &RegMetadata) -> Option<String> {
        match &meta.constant_value {
            Some(nu_protocol::Value::String { val, .. }) => Some(val.clone()),
            Some(nu_protocol::Value::Glob { val, .. }) => Some(val.clone()),
            Some(nu_protocol::Value::Binary { val, .. }) => String::from_utf8(val.clone()).ok(),
            _ => meta.literal_string.clone(),
        }
    }
}
