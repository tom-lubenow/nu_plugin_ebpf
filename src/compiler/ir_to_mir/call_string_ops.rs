use super::*;
use crate::compiler::mir::AddressSpace;
use fancy_regex::{NoExpand, Regex as FancyRegex};
use heck::{
    ToKebabCase, ToLowerCamelCase, ToShoutySnakeCase, ToSnakeCase, ToTitleCase, ToUpperCamelCase,
};
use nu_protocol::levenshtein_distance;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

struct KnownStringSearchOperands {
    input_slot: StackSlotId,
    input_slot_size: usize,
    input_len: usize,
    needle_slot: StackSlotId,
    needle_len: usize,
}

const MAX_STRING_EXPAND_RESULTS: usize = 60;

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

        if !self.named_args.is_empty() || !self.positional_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "str length does not accept arguments in eBPF".into(),
            ));
        }
        let use_grapheme_clusters = self.string_grapheme_cluster_indexing_flag("str length")?;

        if use_grapheme_clusters {
            if let Some(input) = self.exact_string_list_input(input_reg, "str length")? {
                let lengths = input
                    .into_iter()
                    .map(|item| {
                        nu_protocol::Value::int(
                            UnicodeSegmentation::graphemes(item.as_str(), true).count() as i64,
                            Span::unknown(),
                        )
                    })
                    .collect();
                self.lower_constant_value(
                    src_dst,
                    &nu_protocol::Value::list(lengths, Span::unknown()),
                )?;
                return Ok(());
            }

            let input = self.exact_string_input(input_reg, "str length --grapheme-clusters")?;
            let grapheme_len = UnicodeSegmentation::graphemes(input.as_str(), true).count() as i64;
            return self.lower_i64_result(src_dst, result_vreg, grapheme_len);
        }

        if let Some(input) = self.exact_string_list_input(input_reg, "str length")? {
            let lengths = input
                .into_iter()
                .map(|item| nu_protocol::Value::int(item.len() as i64, Span::unknown()))
                .collect();
            self.lower_constant_value(
                src_dst,
                &nu_protocol::Value::list(lengths, Span::unknown()),
            )?;
            return Ok(());
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

    pub(super) fn lower_string_distance(
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

        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "str distance does not accept named arguments in eBPF".into(),
            ));
        }
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "str distance requires exactly one compare-string argument in eBPF".into(),
            ));
        }

        let input = self.exact_string_input(input_reg, "str distance")?;
        let compare = self.literal_string_arg(self.positional_args[0].1, "str distance")?;
        let distance = levenshtein_distance(&input, &compare) as i64;
        self.lower_i64_result(src_dst, result_vreg, distance)
    }

    pub(super) fn lower_string_join(
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

        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "str join does not accept named arguments in eBPF".into(),
            ));
        }
        if self.positional_args.len() > 1 {
            return Err(CompileError::UnsupportedInstruction(
                "str join accepts at most one separator argument in eBPF".into(),
            ));
        }
        if let Some((_, separator_reg)) = self.positional_args.first().copied() {
            let separator = self.literal_string_arg(separator_reg, "str join separator")?;
            if let Some(input) = self.string_join_list_input(input_reg, "str join")? {
                return self.lower_known_string_result(
                    src_dst,
                    result_vreg,
                    input.join(&separator),
                );
            }
        } else if let Some(input) = self.string_join_list_input(input_reg, "str join")? {
            return self.lower_known_string_result(src_dst, result_vreg, input.concat());
        }

        let input = self.exact_string_input(input_reg, "str join")?;
        self.lower_known_string_result(src_dst, result_vreg, input)
    }

    pub(super) fn lower_string_stats(
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
                "str stats does not accept arguments in eBPF".into(),
            ));
        }

        let input = self.exact_string_input(input_reg, "str stats")?;
        let counts = [
            ("lines", Self::string_stats_line_count(&input) as i64),
            ("words", input.unicode_words().count() as i64),
            ("bytes", input.len() as i64),
            ("chars", input.chars().count() as i64),
            (
                "graphemes",
                UnicodeSegmentation::graphemes(input.as_str(), true).count() as i64,
            ),
            (
                "unicode-width",
                Self::string_stats_unicode_width(&input) as i64,
            ),
        ];

        let mut record = nu_protocol::Record::new();
        let mut record_fields = Vec::with_capacity(counts.len());
        for (name, count) in counts {
            let value_vreg = self.func.alloc_vreg();
            self.emit(MirInst::Copy {
                dst: value_vreg,
                src: MirValue::Const(count),
            });
            self.vreg_type_hints.insert(value_vreg, MirType::I64);
            record.push(name, nu_protocol::Value::int(count, Span::unknown()));
            record_fields.push(RecordField {
                name: name.to_string(),
                value_vreg,
                source_reg: None,
                stack_offset: None,
                ty: MirType::I64,
                semantics: None,
                is_context: false,
                root_ctx_field: None,
            });
        }

        let projected_meta = RegMetadata {
            constant_value: Some(nu_protocol::Value::record(record, Span::unknown())),
            record_fields,
            ..Default::default()
        };
        self.emit_metadata_record_result(src_dst, result_vreg, projected_meta)
    }

    pub(super) fn lower_string_expand(
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

        if !self.named_args.is_empty() || !self.positional_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "str expand does not accept arguments in eBPF".into(),
            ));
        }
        for flag in &self.named_flags {
            if flag != "path" {
                return Err(CompileError::UnsupportedInstruction(
                    "str expand currently supports only --path as a flag in eBPF".into(),
                ));
            }
        }

        let input = self.exact_string_input(input_reg, "str expand")?;
        let expansion_input = if self.named_flags.iter().any(|flag| flag == "path") {
            input.replace('\\', "\\\\")
        } else {
            input
        };
        let outputs = Self::string_expand_pattern(&expansion_input)?;
        self.lower_known_string_list_result(src_dst, result_vreg, outputs)
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

        if let Some(input) = self.exact_string_list_input(input_reg, "str substring")? {
            let output = input
                .into_iter()
                .map(|item| Self::substring_known_string(item, range, use_grapheme_clusters))
                .collect::<Result<Vec<_>, _>>()?;
            return self.lower_known_string_list_result(src_dst, result_vreg, output);
        }

        let input = self.exact_string_input(input_reg, "str substring")?;
        let output = Self::substring_known_string(input, range, use_grapheme_clusters)?;

        self.lower_known_string_result(src_dst, result_vreg, output)
    }

    fn substring_known_string(
        input: String,
        range: MaybeOpenRange,
        use_grapheme_clusters: bool,
    ) -> Result<String, CompileError> {
        if use_grapheme_clusters {
            let graphemes: Vec<&str> =
                UnicodeSegmentation::graphemes(input.as_str(), true).collect();
            let (start, end) = Self::string_range_byte_bounds(range, graphemes.len());
            return Ok(graphemes[start..end].concat());
        }

        let (start, end) = Self::string_range_byte_bounds(range, input.len());
        let bytes = input.as_bytes().get(start..end).ok_or_else(|| {
            CompileError::UnsupportedInstruction("invalid substring bounds".into())
        })?;
        String::from_utf8(bytes.to_vec()).map_err(|_| {
            CompileError::UnsupportedInstruction(
                "str substring byte bounds must preserve valid UTF-8 in eBPF".into(),
            )
        })
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

        if !self.named_args.is_empty()
            || self
                .named_flags
                .iter()
                .any(|flag| !matches!(flag.as_str(), "all" | "no-expand" | "regex" | "multiline"))
        {
            return Err(CompileError::UnsupportedInstruction(
                "str replace currently supports only default substring replacement, --all, --regex, --multiline, and --no-expand in eBPF"
                    .into(),
            ));
        }
        if self.positional_args.len() != 2 {
            return Err(CompileError::UnsupportedInstruction(
                "str replace requires exactly two string arguments in eBPF".into(),
            ));
        }

        let find = self.literal_string_arg(self.positional_args[0].1, "str replace find")?;
        let replacement =
            self.literal_string_arg(self.positional_args[1].1, "str replace replacement")?;

        let replace_all = self.named_flags.iter().any(|flag| flag == "all");
        let use_regex = self
            .named_flags
            .iter()
            .any(|flag| flag == "regex" || flag == "multiline");
        let no_expand = self.named_flags.iter().any(|flag| flag == "no-expand");
        let multiline = self.named_flags.iter().any(|flag| flag == "multiline");

        if let Some(input) = self.exact_string_list_input(input_reg, "str replace")? {
            let output = input
                .into_iter()
                .map(|item| {
                    Self::replace_known_string(
                        &item,
                        &find,
                        &replacement,
                        replace_all,
                        use_regex,
                        no_expand,
                        multiline,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            return self.lower_known_string_list_result(src_dst, result_vreg, output);
        }

        let input = self.exact_string_input(input_reg, "str replace")?;
        let output = Self::replace_known_string(
            &input,
            &find,
            &replacement,
            replace_all,
            use_regex,
            no_expand,
            multiline,
        )?;
        self.lower_known_string_result(src_dst, result_vreg, output)
    }

    fn replace_known_string(
        input: &str,
        find: &str,
        replacement: &str,
        replace_all: bool,
        use_regex: bool,
        no_expand: bool,
        multiline: bool,
    ) -> Result<String, CompileError> {
        if use_regex {
            Self::string_replace_regex(input, find, replacement, replace_all, no_expand, multiline)
        } else if replace_all {
            Ok(input.replace(find, replacement))
        } else {
            Ok(input.replacen(find, replacement, 1))
        }
    }

    fn string_replace_regex(
        input: &str,
        find: &str,
        replacement: &str,
        replace_all: bool,
        no_expand: bool,
        multiline: bool,
    ) -> Result<String, CompileError> {
        let pattern = if multiline {
            format!("(?m){find}")
        } else {
            find.to_string()
        };
        let regex = FancyRegex::new(&pattern).map_err(|err| {
            CompileError::UnsupportedInstruction(format!(
                "str replace --regex pattern is invalid in eBPF: {err}"
            ))
        })?;
        let limit = if replace_all { 0 } else { 1 };
        let output = if no_expand {
            regex.try_replacen(input, limit, NoExpand(replacement))
        } else {
            regex.try_replacen(input, limit, replacement)
        }
        .map_err(|err| {
            CompileError::UnsupportedInstruction(format!(
                "str replace --regex failed at compile time in eBPF: {err}"
            ))
        })?;
        Ok(output.into_owned())
    }

    fn string_stats_line_count(input: &str) -> usize {
        if input.is_empty() {
            return 0;
        }

        const LINE_ENDINGS: [&str; 7] = [
            "\r\n", "\n", "\r", "\u{0085}", "\u{000C}", "\u{2028}", "\u{2029}",
        ];

        let mut count = 0;
        let mut index = 0;
        while index < input.len() {
            let rest = &input[index..];
            if rest.starts_with("\r\n") {
                count += 1;
                index += "\r\n".len();
                continue;
            }

            let Some(ch) = rest.chars().next() else {
                break;
            };
            if matches!(
                ch,
                '\n' | '\r' | '\u{0085}' | '\u{000C}' | '\u{2028}' | '\u{2029}'
            ) {
                count += 1;
            }
            index += ch.len_utf8();
        }

        if LINE_ENDINGS.iter().any(|ending| input.ends_with(ending)) {
            count
        } else {
            count + 1
        }
    }

    fn string_stats_unicode_width(input: &str) -> usize {
        UnicodeSegmentation::graphemes(input, true)
            .map(|grapheme| {
                let width = UnicodeWidthStr::width(grapheme);
                if width == 0 && grapheme.chars().any(Self::string_stats_counts_width_one) {
                    1
                } else {
                    width
                }
            })
            .sum()
    }

    fn string_stats_counts_width_one(ch: char) -> bool {
        ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}')
    }

    fn string_expand_pattern(input: &str) -> Result<Vec<String>, CompileError> {
        let mut saw_braces = false;
        let outputs = Self::string_expand_segment(input, &mut saw_braces)?;
        if !saw_braces {
            return Err(CompileError::UnsupportedInstruction(
                "str expand requires at least one brace expression in eBPF".into(),
            ));
        }
        if outputs.len() > MAX_STRING_EXPAND_RESULTS {
            return Err(CompileError::UnsupportedInstruction(format!(
                "str expand produced {} strings; eBPF lowering supports at most {}",
                outputs.len(),
                MAX_STRING_EXPAND_RESULTS
            )));
        }
        for output in &outputs {
            if output.len().saturating_add(1) > MAX_STRING_SIZE {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "str expand output requires {} bytes (limit {})",
                    output.len() + 1,
                    MAX_STRING_SIZE
                )));
            }
        }
        Ok(outputs)
    }

    fn string_expand_segment(
        input: &str,
        saw_braces: &mut bool,
    ) -> Result<Vec<String>, CompileError> {
        let Some(open) = Self::string_expand_find_open_brace(input)? else {
            return Ok(vec![Self::string_expand_unescape(input)]);
        };
        *saw_braces = true;
        let close = Self::string_expand_find_matching_brace(input, open)?;
        let prefix = Self::string_expand_unescape(&input[..open]);
        let inner = &input[open + '{'.len_utf8()..close];
        let suffix = &input[close + '}'.len_utf8()..];
        let alternatives = Self::string_expand_alternatives(inner, saw_braces)?;
        let suffixes = Self::string_expand_segment(suffix, saw_braces)?;

        let mut outputs = Vec::new();
        for alternative in alternatives {
            for suffix in &suffixes {
                outputs.push(format!("{prefix}{alternative}{suffix}"));
                if outputs.len() > MAX_STRING_EXPAND_RESULTS {
                    return Ok(outputs);
                }
            }
        }
        Ok(outputs)
    }

    fn string_expand_alternatives(
        input: &str,
        saw_braces: &mut bool,
    ) -> Result<Vec<String>, CompileError> {
        if let Some(parts) = Self::string_expand_split_commas(input)? {
            let mut outputs = Vec::new();
            for part in parts {
                outputs.extend(Self::string_expand_segment(part, saw_braces)?);
                if outputs.len() > MAX_STRING_EXPAND_RESULTS {
                    return Ok(outputs);
                }
            }
            return Ok(outputs);
        }

        if let Some(range) = Self::string_expand_numeric_range(input)? {
            return Ok(range);
        }

        Self::string_expand_segment(input, saw_braces)
    }

    fn string_expand_find_open_brace(input: &str) -> Result<Option<usize>, CompileError> {
        let mut escaped = false;
        for (index, ch) in input.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '{' => return Ok(Some(index)),
                '}' => {
                    return Err(CompileError::UnsupportedInstruction(
                        "str expand requires balanced brace expressions in eBPF".into(),
                    ));
                }
                _ => {}
            }
        }
        Ok(None)
    }

    fn string_expand_find_matching_brace(input: &str, open: usize) -> Result<usize, CompileError> {
        let mut escaped = false;
        let mut depth = 1usize;
        for (offset, ch) in input[open + '{'.len_utf8()..].char_indices() {
            let index = open + '{'.len_utf8() + offset;
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '{' => depth = depth.saturating_add(1),
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Ok(index);
                    }
                }
                _ => {}
            }
        }
        Err(CompileError::UnsupportedInstruction(
            "str expand requires balanced brace expressions in eBPF".into(),
        ))
    }

    fn string_expand_split_commas(input: &str) -> Result<Option<Vec<&str>>, CompileError> {
        let mut escaped = false;
        let mut depth = 0usize;
        let mut start = 0usize;
        let mut parts = Vec::new();
        for (index, ch) in input.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '{' => depth = depth.saturating_add(1),
                '}' if depth == 0 => {
                    return Err(CompileError::UnsupportedInstruction(
                        "str expand requires balanced brace expressions in eBPF".into(),
                    ));
                }
                '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    parts.push(&input[start..index]);
                    start = index + ','.len_utf8();
                }
                _ => {}
            }
        }
        if depth != 0 {
            return Err(CompileError::UnsupportedInstruction(
                "str expand requires balanced brace expressions in eBPF".into(),
            ));
        }
        if parts.is_empty() {
            Ok(None)
        } else {
            parts.push(&input[start..]);
            Ok(Some(parts))
        }
    }

    fn string_expand_numeric_range(input: &str) -> Result<Option<Vec<String>>, CompileError> {
        let mut escaped = false;
        let mut ranges = Vec::new();
        let mut iter = input.char_indices().peekable();
        while let Some((index, ch)) = iter.next() {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == '.'
                && let Some((_, '.')) = iter.peek().copied()
            {
                ranges.push(index);
                iter.next();
            }
        }

        match ranges.as_slice() {
            [] => Ok(None),
            [_first, _second, ..] => Err(CompileError::UnsupportedInstruction(
                "str expand numeric ranges must use exactly one '..' operator in eBPF".into(),
            )),
            [range_index] => {
                let start_text = Self::string_expand_unescape(&input[..*range_index]);
                let end_text = Self::string_expand_unescape(&input[*range_index + 2..]);
                if start_text.is_empty()
                    || end_text.is_empty()
                    || !start_text.chars().all(|ch| ch.is_ascii_digit())
                    || !end_text.chars().all(|ch| ch.is_ascii_digit())
                {
                    return Err(CompileError::UnsupportedInstruction(
                        "str expand numeric ranges must use unsigned integer bounds in eBPF".into(),
                    ));
                }

                let start = start_text.parse::<u64>().map_err(|err| {
                    CompileError::UnsupportedInstruction(format!(
                        "str expand range start is too large in eBPF: {err}"
                    ))
                })?;
                let end = end_text.parse::<u64>().map_err(|err| {
                    CompileError::UnsupportedInstruction(format!(
                        "str expand range end is too large in eBPF: {err}"
                    ))
                })?;
                if start > end {
                    return Ok(Some(Vec::new()));
                }
                let count = end.saturating_sub(start).saturating_add(1);
                if count > MAX_STRING_EXPAND_RESULTS as u64 {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "str expand range produces {count} strings; eBPF lowering supports at most {MAX_STRING_EXPAND_RESULTS}"
                    )));
                }

                let padded = start_text.starts_with('0') || end_text.starts_with('0');
                let width = if padded {
                    start_text.len().max(end_text.len())
                } else {
                    0
                };
                let values = (start..=end)
                    .map(|value| {
                        if padded {
                            format!("{value:0width$}")
                        } else {
                            value.to_string()
                        }
                    })
                    .collect();
                Ok(Some(values))
            }
        }
    }

    fn string_expand_unescape(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let mut chars = input.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\'
                && let Some(next) = chars.next()
            {
                out.push(next);
            } else {
                out.push(ch);
            }
        }
        out
    }

    pub(super) fn lower_known_string_list_result(
        &mut self,
        src_dst: RegId,
        result_vreg: VReg,
        outputs: Vec<String>,
    ) -> Result<(), CompileError> {
        let max_len = outputs.iter().map(String::len).max().unwrap_or(0);
        let aligned_len = align_to_eight(max_len + 1).min(MAX_STRING_SIZE).max(16);
        let elem_ty = MirType::Array {
            elem: Box::new(MirType::U8),
            len: 8 + aligned_len,
        };
        let array_ty = MirType::Array {
            elem: Box::new(elem_ty.clone()),
            len: outputs.len(),
        };
        let base_runtime_ty = MirType::Ptr {
            pointee: Box::new(array_ty.clone()),
            address_space: AddressSpace::Map,
        };
        if outputs.is_empty() {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(0),
            });
        } else {
            let mut data = vec![0u8; array_ty.size()];
            for (index, output) in outputs.iter().enumerate() {
                let offset = index * elem_ty.size();
                data[offset..offset + 8].copy_from_slice(&(output.len() as u64).to_le_bytes());
                data[offset + 8..offset + 8 + output.len()].copy_from_slice(output.as_bytes());
            }

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
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::VReg(global_vreg),
            });
            self.vreg_type_hints
                .insert(global_vreg, base_runtime_ty.clone());
        }
        self.vreg_type_hints.insert(result_vreg, base_runtime_ty);

        self.reset_call_result_metadata(src_dst);
        let values = outputs
            .into_iter()
            .map(|output| nu_protocol::Value::string(output, Span::unknown()))
            .collect();
        let meta = self.get_or_create_metadata(src_dst);
        meta.constant_value = Some(nu_protocol::Value::list(values, Span::unknown()));
        meta.field_type = Some(array_ty);
        meta.annotated_semantics = Some(AnnotatedValueSemantics::FixedArray {
            elem: Box::new(AnnotatedValueSemantics::String {
                slot_len: aligned_len,
                content_cap: aligned_len.saturating_sub(1),
            }),
            len: match &meta.constant_value {
                Some(nu_protocol::Value::List { vals, .. }) => vals.len(),
                _ => 0,
            },
        });
        Ok(())
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

        if let Some(input) = self.exact_string_list_input(input_reg, "str trim")? {
            let output = input
                .into_iter()
                .map(|item| Self::trim_known_string(item, trim_char, trim_left, trim_right))
                .collect();
            return self.lower_known_string_list_result(src_dst, result_vreg, output);
        }

        let input = self.exact_string_input(input_reg, "str trim")?;
        let output = Self::trim_known_string(input, trim_char, trim_left, trim_right);
        self.lower_known_string_result(src_dst, result_vreg, output)
    }

    fn trim_known_string(
        input: String,
        trim_char: Option<char>,
        trim_left: bool,
        trim_right: bool,
    ) -> String {
        match (trim_char, trim_left, trim_right) {
            (Some(ch), true, false) => input.trim_start_matches(ch).to_string(),
            (Some(ch), false, true) => input.trim_end_matches(ch).to_string(),
            (Some(ch), _, _) => input.trim_matches(ch).to_string(),
            (None, true, false) => input.trim_start().to_string(),
            (None, false, true) => input.trim_end().to_string(),
            (None, _, _) => input.trim().to_string(),
        }
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

        if let Some(input) = self.exact_string_list_input(input_reg, command)? {
            let output = input
                .into_iter()
                .map(|item| Self::known_string_transform(command, item))
                .collect::<Result<Vec<_>, _>>()?;
            return self.lower_known_string_list_result(src_dst, result_vreg, output);
        }

        let input = self.exact_string_input(input_reg, command)?;
        let output = Self::known_string_transform(command, input)?;

        self.lower_known_string_result(src_dst, result_vreg, output)
    }

    pub(super) fn known_string_transform(
        command: &str,
        input: String,
    ) -> Result<String, CompileError> {
        match command {
            "str downcase" => Ok(input.to_lowercase()),
            "str upcase" => Ok(input.to_uppercase()),
            "str reverse" => Ok(input.chars().rev().collect()),
            "str capitalize" => Ok(Self::capitalize_first_char(&input)),
            "str camel-case" => Ok(input.to_lower_camel_case()),
            "str kebab-case" => Ok(input.to_kebab_case()),
            "str pascal-case" => Ok(input.to_upper_camel_case()),
            "str screaming-snake-case" => Ok(input.to_shouty_snake_case()),
            "str snake-case" => Ok(input.to_snake_case()),
            "str title-case" => Ok(input.to_title_case()),
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "unsupported string transform command '{command}'"
            ))),
        }
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

    fn exact_string_list_input(
        &self,
        input_reg: Option<RegId>,
        command: &str,
    ) -> Result<Option<Vec<String>>, CompileError> {
        let Some(meta) = input_reg.and_then(|reg| self.get_metadata(reg).cloned()) else {
            return Ok(None);
        };
        let Some(nu_protocol::Value::List { vals, .. }) = meta.constant_value else {
            return Ok(None);
        };

        vals.into_iter()
            .enumerate()
            .map(|(index, item)| match item {
                nu_protocol::Value::String { val, .. } | nu_protocol::Value::Glob { val, .. } => {
                    Ok(val)
                }
                other => Err(CompileError::UnsupportedInstruction(format!(
                    "{command} requires string list items in eBPF; item {index} has type {}",
                    other.get_type()
                ))),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    fn string_join_list_input(
        &self,
        input_reg: Option<RegId>,
        command: &str,
    ) -> Result<Option<Vec<String>>, CompileError> {
        let Some(meta) = input_reg.and_then(|reg| self.get_metadata(reg).cloned()) else {
            return Ok(None);
        };
        let Some(nu_protocol::Value::List { vals, .. }) = meta.constant_value else {
            return Ok(None);
        };

        vals.into_iter()
            .enumerate()
            .map(|(index, item)| Self::string_join_item_value(item, command, index))
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    fn string_join_item_value(
        value: nu_protocol::Value,
        command: &str,
        index: usize,
    ) -> Result<String, CompileError> {
        match value {
            nu_protocol::Value::String { val, .. } | nu_protocol::Value::Glob { val, .. } => {
                Ok(val)
            }
            nu_protocol::Value::Int { val, .. } => Ok(val.to_string()),
            nu_protocol::Value::Bool { val, .. } => Ok(val.to_string()),
            nu_protocol::Value::Nothing { .. } => Ok(String::new()),
            other => Err(CompileError::UnsupportedInstruction(format!(
                "{command} supports only string, int, bool, and null compile-time list items in eBPF; item {index} has type {}",
                other.get_type()
            ))),
        }
    }

    pub(super) fn lower_known_string_result(
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

    pub(super) fn lower_describe(
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
                "describe does not accept arguments in eBPF".into(),
            ));
        }

        let output = if let Some(input_reg) = input_reg {
            let meta = self.get_metadata(input_reg).ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "describe requires compile-time known input in eBPF".into(),
                )
            })?;
            let value = meta.constant_value.as_ref().ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "describe requires compile-time known input in eBPF".into(),
                )
            })?;
            value.get_type().to_string()
        } else {
            "nothing".to_string()
        };

        if output.len().saturating_add(1) > MAX_STRING_SIZE {
            return Err(CompileError::UnsupportedInstruction(format!(
                "describe output is {} bytes; eBPF lowering supports at most {} bytes",
                output.len(),
                MAX_STRING_SIZE - 1
            )));
        }

        self.lower_known_string_result(src_dst, result_vreg, output)
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
