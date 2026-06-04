use super::*;
use crate::compiler::elf::{MessageAdjustMode, PacketAdjustMode};
use crate::compiler::instruction::{
    BpfHelper, HelperArgKind, HelperExplicitMapKindFamily, HelperRetKind, HelperSignature,
    KfuncArgKind, KfuncRetKind, KfuncSignature, helper_acquire_ref_kind,
};
use crate::compiler::mir::{
    AddressSpace, BYTES_COUNTER_MAP_NAME, COUNTER_MAP_NAME, CtxField, MapOpKind,
    STRING_COUNTER_MAP_NAME,
};
use crate::compiler::{ProgramIntrinsic, TypeInference};
use chrono::{Duration, NaiveDate};

const BPF_SK_LOOKUP_F_REPLACE: u64 = 1 << 0;
const BPF_SK_LOOKUP_F_NO_REUSEPORT: u64 = 1 << 1;

enum SeqNumericArg {
    Int(i64),
    Float(f64),
}

impl SeqNumericArg {
    fn as_f64(&self) -> f64 {
        match self {
            Self::Int(value) => *value as f64,
            Self::Float(value) => *value,
        }
    }
}

impl<'a> HirToMirLowering<'a> {
    fn bytes_index_of_all_offsets(input: &[u8], pattern: &[u8], from_end: bool) -> Vec<i64> {
        if pattern.is_empty() || pattern.len() > input.len() {
            return Vec::new();
        }

        let mut offsets = Vec::new();
        if from_end {
            let mut end = input.len();
            while end >= pattern.len() {
                let Some(found) = input[..end]
                    .windows(pattern.len())
                    .rposition(|candidate| candidate == pattern)
                else {
                    break;
                };
                offsets.push(found as i64);
                end = found;
            }
        } else {
            let mut index = 0;
            while index + pattern.len() <= input.len() {
                if input[index..].starts_with(pattern) {
                    offsets.push(index as i64);
                    index += pattern.len();
                } else {
                    index += 1;
                }
            }
        }
        offsets
    }

    fn bytes_at_output(input: &[u8], range: MaybeOpenRange) -> Vec<u8> {
        let len = input.len() as i64;
        let start = range
            .start
            .map(|idx| {
                let raw = if idx < 0 {
                    len.saturating_add(idx)
                } else {
                    idx
                };
                raw.clamp(0, len)
            })
            .unwrap_or(0);
        let end = range
            .end
            .map(|idx| {
                let raw = if idx < 0 {
                    len.saturating_add(idx)
                } else {
                    idx
                };
                let exclusive = if range.inclusive {
                    raw.saturating_add(1)
                } else {
                    raw
                };
                exclusive.clamp(0, len)
            })
            .unwrap_or(len)
            .max(start);

        input[start as usize..end as usize].to_vec()
    }

    fn bytes_add_output(input: &[u8], data: &[u8], index: i64, from_end: bool) -> Vec<u8> {
        let input_len = input.len();
        let index = index as usize;
        let insert_at = if from_end {
            input_len.saturating_sub(index)
        } else {
            index.min(input_len)
        };

        let mut output = Vec::with_capacity(input.len().saturating_add(data.len()));
        output.extend_from_slice(&input[..insert_at]);
        output.extend_from_slice(data);
        output.extend_from_slice(&input[insert_at..]);
        output
    }

    fn lower_synthetic_follow_cell_path(
        &mut self,
        src_dst: RegId,
        path: CellPath,
    ) -> Result<(), CompileError> {
        const SYNTHETIC_GET_PATH_REG: u32 = u32::MAX;

        let path_reg = RegId::new(SYNTHETIC_GET_PATH_REG);
        let old_meta = self.reg_metadata.insert(
            path_reg.get(),
            RegMetadata {
                cell_path: Some(path),
                ..Default::default()
            },
        );
        let result = self.lower_follow_cell_path(src_dst, path_reg);
        if let Some(old_meta) = old_meta {
            self.reg_metadata.insert(path_reg.get(), old_meta);
        } else {
            self.reg_metadata.remove(&path_reg.get());
        }
        result
    }

    fn lower_field_path_get(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        input_reg: RegId,
        input_vreg: VReg,
        input_meta: Option<RegMetadata>,
        path: CellPath,
    ) -> Result<(), CompileError> {
        if input_meta.as_ref().is_some_and(|meta| meta.is_context) {
            let result_vreg = if src_dst_had_value {
                self.assign_fresh_vreg(src_dst)
            } else {
                dst_vreg
            };
            self.reg_map.insert(src_dst.get(), result_vreg);
            let mut meta = input_meta.unwrap_or_default();
            meta.is_context = true;
            meta.record_fields.clear();
            self.reg_metadata.insert(src_dst.get(), meta);
            return self.lower_synthetic_follow_cell_path(src_dst, path);
        }

        let base_runtime_ty = self
            .typed_value_runtime_type(input_reg, input_vreg)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "get FIELD requires record, context, or typed pointer input in eBPF".into(),
                )
            })?;
        if !matches!(base_runtime_ty, MirType::Ptr { .. })
            && Self::aggregate_call_value_type(&base_runtime_ty).is_none()
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "get FIELD requires record, context, or typed pointer input in eBPF, got {:?}",
                base_runtime_ty
            )));
        }

        self.reg_map.insert(src_dst.get(), input_vreg);
        if let Some(meta) = input_meta {
            self.reg_metadata.insert(src_dst.get(), meta);
        } else {
            self.reg_metadata.insert(
                src_dst.get(),
                RegMetadata {
                    field_type: Some(base_runtime_ty),
                    ..Default::default()
                },
            );
        }
        self.lower_synthetic_follow_cell_path(src_dst, path)
    }

    fn lower_stack_list_append_or_prepend(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const MAX_STACK_LIST_CAPACITY: usize = 60;

        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} does not accept named flags or arguments in eBPF"
            )));
        }

        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires exactly one positional item argument in eBPF"
            )));
        }

        let (item_vreg, item_reg) = self.positional_args[0];
        if let Some(values) = input_reg.and_then(|reg| {
            self.compile_time_only_list_builder_values(reg, input_vreg)
                .map(|values| values.to_vec())
        }) {
            let item_constant = self.get_metadata(item_reg).and_then(|meta| {
                meta.constant_value.clone().or_else(|| {
                    meta.literal_int
                        .map(|value| nu_protocol::Value::int(value, Span::unknown()))
                })
            });
            let Some(item) = item_constant else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} item must be compile-time constant for compile-time known fixed lists in eBPF"
                )));
            };
            let mut vals = values;
            if cmd_name == "prepend" {
                vals.insert(0, item);
            } else {
                vals.push(item);
            }
            let list = nu_protocol::Value::list(vals, Span::unknown());
            self.lower_compile_time_list_transform_result(src_dst, &list)?;
            return Ok(());
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires a pipeline input with tracked metadata in eBPF"
                ))
            })?;
        let Some((_input_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a stack-backed list input in eBPF"
            )));
        };

        let out_max_len = max_len.checked_add(1).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} would overflow stack-backed numeric list capacity"
            ))
        })?;
        if out_max_len > MAX_STACK_LIST_CAPACITY {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} would exceed stack-backed numeric list capacity {MAX_STACK_LIST_CAPACITY}"
            )));
        }

        let result_vreg = if self.pipeline_input.is_none() && src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let buffer_size = align_to_eight(8 + out_max_len * 8);
        let out_ty = MirType::Array {
            elem: Box::new(MirType::I64),
            len: out_max_len.saturating_add(1),
        };
        let out_slot = self
            .func
            .alloc_stack_slot(buffer_size, 8, StackSlotKind::ListBuffer);
        self.record_list_buffer_slot_type(out_slot, out_max_len);
        self.emit(MirInst::ListNew {
            dst: result_vreg,
            buffer: out_slot,
            max_len: out_max_len,
        });
        self.vreg_type_hints.insert(
            result_vreg,
            MirType::Ptr {
                pointee: Box::new(out_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );

        if cmd_name == "prepend" {
            self.emit(MirInst::ListPush {
                list: result_vreg,
                item: item_vreg,
            });
        }

        if max_len > 0 {
            let len_vreg = self.func.alloc_vreg();
            self.emit(MirInst::ListLen {
                dst: len_vreg,
                list: input_vreg,
            });
            self.vreg_type_hints.insert(len_vreg, MirType::U64);

            let continuation_block = self.func.alloc_block();
            for source_index in 0..max_len {
                let copy_block = self.func.alloc_block();
                let next_block = if source_index + 1 == max_len {
                    continuation_block
                } else {
                    self.func.alloc_block()
                };

                let cond_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: cond_vreg,
                    op: BinOpKind::Lt,
                    lhs: MirValue::Const(source_index as i64),
                    rhs: MirValue::VReg(len_vreg),
                });
                self.vreg_type_hints.insert(cond_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: cond_vreg,
                    if_true: copy_block,
                    if_false: next_block,
                });

                self.current_block = copy_block;
                let copied_item_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListGet {
                    dst: copied_item_vreg,
                    list: input_vreg,
                    idx: MirValue::Const(source_index as i64),
                });
                self.vreg_type_hints.insert(copied_item_vreg, MirType::I64);
                self.emit(MirInst::ListPush {
                    list: result_vreg,
                    item: copied_item_vreg,
                });
                self.terminate(MirInst::Jump { target: next_block });

                self.current_block = next_block;
            }
        }

        if cmd_name == "append" {
            self.emit(MirInst::ListPush {
                list: result_vreg,
                item: item_vreg,
            });
        }

        self.reset_call_result_metadata(src_dst);
        let item_constant = self.get_metadata(item_reg).and_then(|meta| {
            meta.constant_value.clone().or_else(|| {
                meta.literal_int
                    .map(|value| nu_protocol::Value::int(value, Span::unknown()))
            })
        });
        let known_len_from_semantics = match input_meta.annotated_semantics {
            Some(AnnotatedValueSemantics::NumericList { known_len, .. }) => known_len,
            _ => None,
        };
        let known_len_from_constant = match input_meta.constant_value.clone() {
            Some(nu_protocol::Value::List { ref vals, .. }) => Some(vals.len()),
            _ => None,
        };

        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(out_ty);
        out_meta.list_buffer = Some((out_slot, out_max_len));
        out_meta.annotated_semantics = Some(AnnotatedValueSemantics::NumericList {
            max_len: out_max_len,
            known_len: known_len_from_semantics
                .or(known_len_from_constant)
                .map(|known_len| known_len.min(max_len).saturating_add(1).min(out_max_len)),
        });
        out_meta.constant_value = match (input_meta.constant_value, item_constant) {
            (Some(nu_protocol::Value::List { mut vals, .. }), Some(item)) => {
                if cmd_name == "prepend" {
                    vals.insert(0, item);
                } else {
                    vals.push(item);
                }
                Some(nu_protocol::Value::list(vals, Span::unknown()))
            }
            _ => None,
        };

        Ok(())
    }

    fn lower_seq_constant(&mut self, src_dst: RegId) -> Result<(), CompileError> {
        const MAX_SEQ_LIST_CAPACITY: usize = 60;

        if self.pipeline_input.is_some() || self.pipeline_input_reg.is_some() {
            return Err(CompileError::UnsupportedInstruction(
                "seq does not accept pipeline input in eBPF".into(),
            ));
        }
        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "seq does not accept named flags or arguments in eBPF".into(),
            ));
        }
        if !(1..=3).contains(&self.positional_args.len()) {
            return Err(CompileError::UnsupportedInstruction(
                "seq supports one to three numeric arguments in eBPF".into(),
            ));
        }

        let maybe_float_args = self
            .positional_args
            .iter()
            .map(|(_, reg)| self.seq_numeric_arg(*reg))
            .collect::<Result<Vec<_>, _>>()?;
        if maybe_float_args
            .iter()
            .any(|arg| matches!(arg, SeqNumericArg::Float(_)))
        {
            let values = match maybe_float_args.as_slice() {
                [value] => vec![nu_protocol::Value::float(value.as_f64(), Span::unknown())],
                [start, end] => Self::seq_float_values(
                    start.as_f64(),
                    1.0,
                    end.as_f64(),
                    MAX_SEQ_LIST_CAPACITY,
                )?,
                [start, step, end] => Self::seq_float_values(
                    start.as_f64(),
                    step.as_f64(),
                    end.as_f64(),
                    MAX_SEQ_LIST_CAPACITY,
                )?,
                _ => unreachable!("seq argument count was validated"),
            };
            let list = nu_protocol::Value::list(values, Span::unknown());
            if self.current_call_result_metadata_only {
                self.lower_compile_time_only_constant_value(src_dst, &list);
                return Ok(());
            }
            return Err(CompileError::UnsupportedInstruction(
                "seq float output is supported only when folded by metadata consumers in eBPF"
                    .into(),
            ));
        }

        let args = self
            .positional_args
            .iter()
            .map(|(_, reg)| self.seq_integer_arg(*reg))
            .collect::<Result<Vec<_>, _>>()?;
        let values = match args.as_slice() {
            [value] => vec![nu_protocol::Value::int(*value, Span::unknown())],
            [start, end] => Self::seq_integer_values(*start, 1, *end, MAX_SEQ_LIST_CAPACITY)?,
            [start, step, end] => {
                Self::seq_integer_values(*start, *step, *end, MAX_SEQ_LIST_CAPACITY)?
            }
            _ => unreachable!("seq argument count was validated"),
        };

        self.lower_constant_value(src_dst, &nu_protocol::Value::list(values, Span::unknown()))
    }

    fn lower_seq_char_constant(&mut self, src_dst: RegId) -> Result<(), CompileError> {
        const MAX_SEQ_STRING_LIST_CAPACITY: usize = 60;

        if self.pipeline_input.is_some() || self.pipeline_input_reg.is_some() {
            return Err(CompileError::UnsupportedInstruction(
                "seq char does not accept pipeline input in eBPF".into(),
            ));
        }
        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "seq char does not accept named flags or arguments in eBPF".into(),
            ));
        }
        if self.positional_args.len() != 2 {
            return Err(CompileError::UnsupportedInstruction(
                "seq char supports exactly two ASCII character arguments in eBPF".into(),
            ));
        }

        let start = self.seq_char_arg(self.positional_args[0].1)?;
        let end = self.seq_char_arg(self.positional_args[1].1)?;
        let len = usize::from(start.abs_diff(end)) + 1;
        if len > MAX_SEQ_STRING_LIST_CAPACITY {
            return Err(CompileError::UnsupportedInstruction(format!(
                "seq char output exceeds fixed string-list capacity {MAX_SEQ_STRING_LIST_CAPACITY}"
            )));
        }

        let values = if start <= end {
            (start..=end).collect::<Vec<_>>()
        } else {
            (end..=start).rev().collect::<Vec<_>>()
        }
        .into_iter()
        .map(|byte| {
            nu_protocol::Value::string(char::from(byte).to_string(), nu_protocol::Span::unknown())
        })
        .collect();

        self.lower_constant_value(src_dst, &nu_protocol::Value::list(values, Span::unknown()))
    }

    fn lower_seq_date_constant(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
    ) -> Result<(), CompileError> {
        const MAX_SEQ_DATE_LIST_CAPACITY: usize = 60;

        if self.pipeline_input.is_some() || self.pipeline_input_reg.is_some() {
            return Err(CompileError::UnsupportedInstruction(
                "seq date does not accept pipeline input in eBPF".into(),
            ));
        }
        if !self.positional_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "seq date does not accept positional arguments in eBPF".into(),
            ));
        }
        if !self.named_flags.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "seq date does not accept named flags in eBPF".into(),
            ));
        }
        self.require_only_named_args(
            "seq date",
            &[
                "begin-date",
                "b",
                "end-date",
                "e",
                "increment",
                "n",
                "days",
                "d",
                "periods",
                "p",
                "input-format",
                "i",
                "output-format",
                "o",
            ],
        )?;

        let input_format = self
            .seq_date_string_named_arg("input-format", "i", "seq date --input-format")?
            .unwrap_or_else(|| "%Y-%m-%d".to_string());
        let output_format = self
            .seq_date_string_named_arg("output-format", "o", "seq date --output-format")?
            .unwrap_or_else(|| "%Y-%m-%d".to_string());
        let begin_raw = self
            .seq_date_string_named_arg("begin-date", "b", "seq date --begin-date")?
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "seq date requires explicit --begin-date in eBPF".into(),
                )
            })?;

        let begin = Self::seq_date_parse_with_format(&begin_raw, "begin-date", &input_format)?;
        let step_days = self.seq_date_increment_days()?.unwrap_or(1);
        if step_days <= 0 {
            return Err(CompileError::UnsupportedInstruction(
                "seq date --increment requires a positive integer day count in eBPF".into(),
            ));
        }

        let values = if let Some(periods) =
            self.seq_date_integer_named_arg("periods", "p", "seq date --periods")?
        {
            let count = Self::seq_date_positive_count(periods, "periods")?;
            if count > MAX_SEQ_DATE_LIST_CAPACITY {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "seq date output exceeds fixed string-list capacity {MAX_SEQ_DATE_LIST_CAPACITY}"
                )));
            }
            Self::seq_date_values_for_count(
                begin,
                step_days,
                count,
                MAX_SEQ_DATE_LIST_CAPACITY,
                &output_format,
            )?
        } else if let Some(days) =
            self.seq_date_integer_named_arg("days", "d", "seq date --days")?
        {
            let day_count = Self::seq_date_positive_count(days, "days")?;
            let end_offset = days.checked_sub(1).ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "seq date --days requires a positive integer in eBPF".into(),
                )
            })?;
            let end = begin
                .checked_add_signed(Duration::try_days(end_offset).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "seq date --days is too large to model in eBPF".into(),
                    )
                })?)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction("seq date overflows in eBPF".into())
                })?;
            let values = Self::seq_date_values_between(
                begin,
                end,
                step_days,
                MAX_SEQ_DATE_LIST_CAPACITY,
                &output_format,
            )?;
            debug_assert!(values.len() <= day_count);
            values
        } else {
            let end_raw = self
                .seq_date_string_named_arg("end-date", "e", "seq date --end-date")?
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "seq date requires explicit --end-date, --days, or --periods in eBPF"
                            .into(),
                    )
                })?;
            let end = Self::seq_date_parse_with_format(&end_raw, "end-date", &input_format)?;
            Self::seq_date_values_between(
                begin,
                end,
                step_days,
                MAX_SEQ_DATE_LIST_CAPACITY,
                &output_format,
            )?
        };

        self.lower_known_string_list_result(src_dst, dst_vreg, values)
    }

    fn seq_date_values_between(
        begin: NaiveDate,
        end: NaiveDate,
        step_days: i64,
        max_len: usize,
        output_format: &str,
    ) -> Result<Vec<String>, CompileError> {
        let ascending = begin <= end;
        let signed_step = if ascending { step_days } else { -step_days };
        let delta = Duration::try_days(signed_step).ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "seq date --increment is too large to model in eBPF".into(),
            )
        })?;
        let mut date = begin;
        let mut values = Vec::new();
        loop {
            if values.len() >= max_len {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "seq date output exceeds fixed string-list capacity {max_len}"
                )));
            }
            values.push(Self::seq_date_format_value(date, output_format)?);
            if date == end {
                break;
            }

            let next = date.checked_add_signed(delta).ok_or_else(|| {
                CompileError::UnsupportedInstruction("seq date overflows in eBPF".into())
            })?;
            if (ascending && next > end) || (!ascending && next < end) {
                break;
            }
            date = next;
        }

        Ok(values)
    }

    fn seq_date_values_for_count(
        begin: NaiveDate,
        step_days: i64,
        count: usize,
        max_len: usize,
        output_format: &str,
    ) -> Result<Vec<String>, CompileError> {
        if count > max_len {
            return Err(CompileError::UnsupportedInstruction(format!(
                "seq date output exceeds fixed string-list capacity {max_len}"
            )));
        }
        let delta = Duration::try_days(step_days).ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "seq date --increment is too large to model in eBPF".into(),
            )
        })?;
        let mut date = begin;
        let mut values = Vec::with_capacity(count);
        for index in 0..count {
            if index > 0 {
                date = date.checked_add_signed(delta).ok_or_else(|| {
                    CompileError::UnsupportedInstruction("seq date overflows in eBPF".into())
                })?;
            }
            values.push(Self::seq_date_format_value(date, output_format)?);
        }

        Ok(values)
    }

    fn seq_date_named_arg_reg(&self, long: &str, short: &str) -> Option<RegId> {
        self.named_args
            .get(long)
            .or_else(|| self.named_args.get(short))
            .map(|(_, reg)| *reg)
    }

    fn seq_date_string_named_arg(
        &self,
        long: &str,
        short: &str,
        context: &str,
    ) -> Result<Option<String>, CompileError> {
        self.seq_date_named_arg_reg(long, short)
            .map(|reg| self.literal_string_arg(reg, context))
            .transpose()
    }

    fn seq_date_increment_days(&self) -> Result<Option<i64>, CompileError> {
        self.seq_date_integer_named_arg("increment", "n", "seq date --increment")
    }

    fn seq_date_integer_named_arg(
        &self,
        long: &str,
        short: &str,
        context: &str,
    ) -> Result<Option<i64>, CompileError> {
        self.seq_date_named_arg_reg(long, short)
            .map(|reg| {
                self.get_metadata(reg)
                    .and_then(|meta| meta.literal_int)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "{context} requires a compile-time known integer in eBPF"
                        ))
                    })
            })
            .transpose()
    }

    fn seq_date_positive_count(raw: i64, arg_name: &str) -> Result<usize, CompileError> {
        if raw <= 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "seq date --{arg_name} requires a positive integer in eBPF"
            )));
        }
        usize::try_from(raw).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "seq date --{arg_name} is too large to model in eBPF"
            ))
        })
    }

    fn seq_date_parse_with_format(
        raw: &str,
        arg_name: &str,
        input_format: &str,
    ) -> Result<NaiveDate, CompileError> {
        NaiveDate::parse_from_str(raw, input_format).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "seq date --{arg_name} does not match --input-format '{input_format}' in eBPF"
            ))
        })
    }

    fn seq_date_format_value(date: NaiveDate, output_format: &str) -> Result<String, CompileError> {
        let timestamp = date.and_hms_opt(0, 0, 0).ok_or_else(|| {
            CompileError::UnsupportedInstruction("seq date overflows in eBPF".into())
        })?;
        let output = timestamp.format(output_format).to_string();
        if output.as_bytes().contains(&0) {
            return Err(CompileError::UnsupportedInstruction(
                "seq date --output-format produced NUL bytes, which are not supported in eBPF"
                    .into(),
            ));
        }
        if output.len().saturating_add(1) > MAX_STRING_SIZE {
            return Err(CompileError::UnsupportedInstruction(format!(
                "seq date --output-format produced {} bytes; eBPF lowering supports at most {} bytes",
                output.len(),
                MAX_STRING_SIZE - 1
            )));
        }
        Ok(output)
    }

    fn seq_char_arg(&self, reg: RegId) -> Result<u8, CompileError> {
        let value = self.literal_string_arg(reg, "seq char")?;
        let bytes = value.as_bytes();
        if bytes.len() == 1 && bytes[0].is_ascii() {
            Ok(bytes[0])
        } else {
            Err(CompileError::UnsupportedInstruction(
                "seq char requires individual ASCII character arguments in eBPF".into(),
            ))
        }
    }

    fn seq_integer_arg(&self, reg: RegId) -> Result<i64, CompileError> {
        self.get_metadata(reg)
            .and_then(|meta| {
                meta.literal_int
                    .or_else(|| match meta.constant_value.as_ref() {
                        Some(nu_protocol::Value::Int { val, .. }) => Some(*val),
                        _ => None,
                    })
            })
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "seq arguments must be compile-time known integers in eBPF".into(),
                )
            })
    }

    fn seq_numeric_arg(&self, reg: RegId) -> Result<SeqNumericArg, CompileError> {
        self.get_metadata(reg)
            .and_then(|meta| {
                meta.literal_int.map(SeqNumericArg::Int).or_else(|| {
                    match meta.constant_value.as_ref() {
                        Some(nu_protocol::Value::Int { val, .. }) => Some(SeqNumericArg::Int(*val)),
                        Some(nu_protocol::Value::Float { val, .. }) => {
                            Some(SeqNumericArg::Float(*val))
                        }
                        _ => None,
                    }
                })
            })
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "seq arguments must be compile-time known integers or floats in eBPF".into(),
                )
            })
    }

    fn seq_integer_values(
        start: i64,
        step: i64,
        end: i64,
        max_len: usize,
    ) -> Result<Vec<nu_protocol::Value>, CompileError> {
        if step == 0 {
            return Ok(Vec::new());
        }

        let mut values = Vec::new();
        let mut current = start;
        loop {
            let in_range = if step > 0 {
                current <= end
            } else {
                current >= end
            };
            if !in_range {
                break;
            }
            if values.len() >= max_len {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "seq output exceeds stack-backed numeric list capacity {max_len} in eBPF"
                )));
            }
            values.push(nu_protocol::Value::int(current, Span::unknown()));

            let next = (current as i128) + (step as i128);
            let next_is_in_range = if step > 0 {
                next <= end as i128
            } else {
                next >= end as i128
            };
            if !next_is_in_range {
                break;
            }
            current = i64::try_from(next).map_err(|_| {
                CompileError::UnsupportedInstruction("seq overflows i64 in eBPF".into())
            })?;
        }

        Ok(values)
    }

    fn seq_float_values(
        start: f64,
        step: f64,
        end: f64,
        max_len: usize,
    ) -> Result<Vec<nu_protocol::Value>, CompileError> {
        if step == 0.0 {
            return Ok(Vec::new());
        }
        if !start.is_finite() || !step.is_finite() || !end.is_finite() {
            return Err(CompileError::UnsupportedInstruction(
                "seq float arguments must be finite in eBPF".into(),
            ));
        }

        let mut values = Vec::new();
        let mut current = start;
        loop {
            let in_range = if step > 0.0 {
                current <= end
            } else {
                current >= end
            };
            if !in_range {
                break;
            }
            if values.len() >= max_len {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "seq float output exceeds compile-time list capacity {max_len} in eBPF"
                )));
            }
            values.push(nu_protocol::Value::float(current, Span::unknown()));

            let next = current + step;
            if !next.is_finite() {
                return Err(CompileError::UnsupportedInstruction(
                    "seq float overflows in eBPF".into(),
                ));
            }
            current = next;
        }

        Ok(values)
    }

    pub(super) fn lower_call(
        &mut self,
        decl_id: DeclId,
        src_dst: RegId,
    ) -> Result<(), CompileError> {
        let src_dst_had_value = self.reg_map.contains_key(&src_dst.get());
        let dst_vreg = self.get_vreg(src_dst);

        if self.user_functions.contains_key(&decl_id) {
            self.lower_user_function_call(decl_id, src_dst, dst_vreg)?;
            self.clear_call_state();
            return Ok(());
        }

        // Look up command name from our decl_names mapping
        let cmd_name = self
            .decl_names
            .get(&decl_id)
            .cloned()
            .unwrap_or_else(|| format!("decl_{}", decl_id.get()));

        if let Some(intrinsic) = ProgramIntrinsic::from_command_name(&cmd_name) {
            self.validate_intrinsic_support(intrinsic)?;
        }

        match cmd_name.as_str() {
            "emit" => {
                self.needs_ringbuf = true;
                // Check if we're emitting a record - check both pipeline_input_reg and src_dst
                // (src_dst is used when record is piped directly: { ... } | emit)
                let record_input_reg = self
                    .pipeline_input_reg
                    .filter(|reg| {
                        self.get_metadata(*reg)
                            .is_some_and(|m| !m.record_fields.is_empty())
                    })
                    .or_else(|| {
                        self.get_metadata(src_dst)
                            .is_some_and(|m| !m.record_fields.is_empty())
                            .then_some(src_dst)
                    });
                let record_fields = record_input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .map(|m| m.record_fields.clone())
                    .unwrap_or_default();

                if !record_fields.is_empty() {
                    self.reject_context_pointer_payload(record_input_reg, "emit")?;
                    // Emit a structured record
                    let fields: Vec<RecordFieldDef> = record_fields
                        .iter()
                        .map(|f| {
                            let value =
                                if matches!(f.ty, MirType::Array { .. } | MirType::Struct { .. }) {
                                    self.materialized_record_field_value_vreg(f)?
                                } else {
                                    f.value_vreg
                                };
                            Ok(RecordFieldDef {
                                name: f.name.clone(),
                                value,
                                ty: f.ty.clone(),
                            })
                        })
                        .collect::<Result<Vec<_>, CompileError>>()?;
                    self.emit(MirInst::EmitRecord { fields });
                } else {
                    let field_type = self
                        .pipeline_input_reg
                        .and_then(|reg| self.get_metadata(reg))
                        .and_then(|m| m.field_type.clone())
                        .or_else(|| {
                            self.get_metadata(src_dst)
                                .and_then(|m| m.field_type.clone())
                        });
                    let size = match field_type.as_ref() {
                        Some(ty) if Self::aggregate_call_value_byte_array_len(ty).is_some() => {
                            Self::aggregate_call_value_byte_array_len(ty).unwrap()
                        }
                        Some(ty) if Self::aggregate_call_value_type(ty).is_some() => {
                            Self::aggregate_call_value_type(ty).unwrap().size()
                        }
                        _ => 8,
                    };
                    // Emit a single value
                    let data_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                    let data_reg = self
                        .pipeline_input_reg
                        .or_else(|| src_dst_had_value.then_some(src_dst));
                    self.reject_context_pointer_payload(data_reg, "emit")?;
                    self.emit(MirInst::EmitEvent {
                        data: data_vreg,
                        size,
                    });
                }
                // Set result to 0
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
                self.reset_call_result_metadata(src_dst);
            }

            "count" => {
                self.needs_counter_map = true;
                let key_reg = self.pipeline_input_reg.unwrap_or(src_dst);
                let mut key_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                self.reject_context_pointer_payload(Some(key_reg), "count key")?;
                let key_type = self
                    .get_metadata(key_reg)
                    .and_then(|m| {
                        m.field_type
                            .clone()
                            .or_else(|| Self::metadata_record_layout(m))
                    })
                    .or_else(|| self.vreg_type_hints.get(&key_vreg).cloned())
                    .map(|ty| self.stored_generic_map_value_type(&ty));

                if let Some(key_type) = key_type.as_ref()
                    && Self::aggregate_call_value_type(key_type).is_some()
                {
                    key_vreg = self.materialized_metadata_aggregate_vreg(key_reg, key_vreg)?;
                }

                // Check for --per-cpu flag
                let per_cpu = self.named_flags.contains(&"per-cpu".to_string());

                let (map_name, map_kind) = match key_type.as_ref() {
                    Some(ty) if Self::aggregate_call_value_byte_array_len(ty) == Some(16) => {
                        let kind = if per_cpu {
                            MapKind::PerCpuHash
                        } else {
                            MapKind::Hash
                        };
                        (STRING_COUNTER_MAP_NAME, kind)
                    }
                    Some(ty) if Self::aggregate_call_value_type(ty).is_some() => {
                        let kind = if per_cpu {
                            MapKind::PerCpuHash
                        } else {
                            MapKind::Hash
                        };
                        (BYTES_COUNTER_MAP_NAME, kind)
                    }
                    _ => {
                        let kind = if per_cpu {
                            MapKind::PerCpuHash
                        } else {
                            MapKind::Hash
                        };
                        (COUNTER_MAP_NAME, kind)
                    }
                };

                // Map update increments counter for key
                self.emit(MirInst::MapUpdate {
                    map: MapRef {
                        name: map_name.to_string(),
                        kind: map_kind,
                    },
                    key: key_vreg,
                    val: dst_vreg, // handled specially in MIR->eBPF
                    flags: 0,
                });

                let result_vreg = self.assign_fresh_vreg(src_dst);

                // Return 0
                self.emit(MirInst::Copy {
                    dst: result_vreg,
                    src: MirValue::Const(0),
                });
                self.vreg_type_hints.insert(result_vreg, MirType::I64);

                self.reset_call_result_metadata(src_dst);
            }

            "histogram" => {
                self.needs_histogram_map = true;
                let value_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let value_reg = self
                    .pipeline_input_reg
                    .or_else(|| src_dst_had_value.then_some(src_dst));
                self.reject_context_pointer_payload(value_reg, "histogram value")?;
                self.emit(MirInst::Histogram { value: value_vreg });
                // Return 0 (pass-through)
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
                self.reset_call_result_metadata(src_dst);
            }

            "start-timer" => {
                if self.pipeline_input.is_some() {
                    return Err(CompileError::UnsupportedInstruction(
                        "start-timer does not accept pipeline input in eBPF".into(),
                    ));
                }
                self.needs_timestamp_map = true;
                self.emit(MirInst::StartTimer);
                // Return 0 (void)
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
                self.reset_call_result_metadata(src_dst);
            }

            "stop-timer" => {
                if self.pipeline_input.is_some() {
                    return Err(CompileError::UnsupportedInstruction(
                        "stop-timer does not accept pipeline input in eBPF".into(),
                    ));
                }
                self.needs_timestamp_map = true;
                self.emit(MirInst::StopTimer { dst: dst_vreg });
            }

            "seq" => {
                self.lower_seq_constant(src_dst)?;
            }

            "seq char" => {
                self.lower_seq_char_constant(src_dst)?;
            }

            "seq date" => {
                self.lower_seq_date_constant(src_dst, dst_vreg)?;
            }

            "random int" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "random int does not accept flags in eBPF".into(),
                    ));
                }
                self.require_only_named_args("random int", &[])?;
                if self.positional_args.len() > 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "random int accepts at most one range argument in eBPF".into(),
                    ));
                }
                if self.pipeline_input.is_some() {
                    return Err(CompileError::UnsupportedInstruction(
                        "random int does not accept pipeline input in eBPF".into(),
                    ));
                }

                self.emit(MirInst::CallHelper {
                    dst: dst_vreg,
                    helper: BpfHelper::GetPrandomU32 as u32,
                    args: Vec::new(),
                });

                if let Some((_, range_reg)) = self.positional_args.first().copied() {
                    let range = self
                        .get_metadata(range_reg)
                        .and_then(|meta| meta.bounded_range)
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "random int range must be a compile-time bounded integer range"
                                    .into(),
                            )
                        })?;
                    let min = range.start;
                    let max = if range.inclusive {
                        range.end
                    } else {
                        range.end.checked_sub(1).ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "random int range end is too small".into(),
                            )
                        })?
                    };
                    if max < min {
                        return Err(CompileError::UnsupportedInstruction(
                            "random int range end must be >= start".into(),
                        ));
                    }
                    let span = (max as i128) - (min as i128) + 1;
                    let max_span = u32::MAX as i128 + 1;
                    if !(1..=max_span).contains(&span) {
                        return Err(CompileError::UnsupportedInstruction(
                            "random int eBPF ranges must cover at most 2^32 values".into(),
                        ));
                    }

                    let span_operand = self.large_const_operand(&MirType::I64, span as i64);
                    self.emit(MirInst::BinOp {
                        dst: dst_vreg,
                        op: BinOpKind::Mod,
                        lhs: MirValue::VReg(dst_vreg),
                        rhs: span_operand,
                    });
                    if min != 0 {
                        let min_operand = self.large_const_operand(&MirType::I64, min);
                        self.emit(MirInst::BinOp {
                            dst: dst_vreg,
                            op: BinOpKind::Add,
                            lhs: MirValue::VReg(dst_vreg),
                            rhs: min_operand,
                        });
                    }
                }

                self.vreg_type_hints.insert(dst_vreg, MirType::I64);
                self.reset_call_result_metadata(src_dst);
            }

            "read-str" => {
                let ptr_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let ptr_reg = self
                    .pipeline_input_reg
                    .or_else(|| src_dst_had_value.then_some(src_dst));
                self.reject_context_pointer_payload(ptr_reg, "read-str source")?;

                // Check for --max-len argument (default 128)
                let requested_len = self
                    .named_args
                    .get("max-len")
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.literal_int)
                    .map(|v| v as usize)
                    .unwrap_or(MAX_STRING_SIZE);

                // Warn and cap if exceeds limit
                let max_len = if requested_len > MAX_STRING_SIZE {
                    eprintln!(
                        "Warning: read-str max-len ({} bytes) exceeds eBPF limit of {} bytes, capping",
                        requested_len, MAX_STRING_SIZE
                    );
                    MAX_STRING_SIZE
                } else {
                    requested_len
                };
                let aligned_len = align_to_eight(max_len).min(MAX_STRING_SIZE).max(16);
                self.lower_probe_read_string(src_dst, dst_vreg, ptr_vreg, true, aligned_len)?;
            }

            "read-kernel-str" => {
                let ptr_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let ptr_reg = self
                    .pipeline_input_reg
                    .or_else(|| src_dst_had_value.then_some(src_dst));
                self.reject_context_pointer_payload(ptr_reg, "read-kernel-str source")?;

                // Check for --max-len argument (default 128)
                let requested_len = self
                    .named_args
                    .get("max-len")
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.literal_int)
                    .map(|v| v as usize)
                    .unwrap_or(MAX_STRING_SIZE);

                // Warn and cap if exceeds limit
                let max_len = if requested_len > MAX_STRING_SIZE {
                    eprintln!(
                        "Warning: read-kernel-str max-len ({} bytes) exceeds eBPF limit of {} bytes, capping",
                        requested_len, MAX_STRING_SIZE
                    );
                    MAX_STRING_SIZE
                } else {
                    requested_len
                };
                let aligned_len = align_to_eight(max_len).min(MAX_STRING_SIZE).max(16);
                self.lower_probe_read_string(src_dst, dst_vreg, ptr_vreg, false, aligned_len)?;
            }

            "adjust-packet" => {
                self.require_only_named_args("adjust-packet", &["mode", "flags"])?;
                let mode = self.packet_adjust_mode_from_named_flags("adjust-packet")?;
                let helper =
                    self.packet_adjust_helper_for_current_program("adjust-packet", mode)?;

                if mode != PacketAdjustMode::Room {
                    if self.named_args.contains_key("mode") {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "adjust-packet --{} does not accept --mode",
                            mode.flag_name()
                        )));
                    }
                    if self.named_args.contains_key("flags") {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "adjust-packet --{} does not accept --flags",
                            mode.flag_name()
                        )));
                    }
                }

                let value_vreg = self
                    .positional_args
                    .first()
                    .map(|(vreg, _)| *vreg)
                    .or(self.pipeline_input)
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "adjust-packet --{} requires a {} from pipeline input or a first positional argument",
                            mode.flag_name(),
                            mode.value_name()
                        ))
                    })?;
                let value_reg = self
                    .positional_args
                    .first()
                    .map(|(_, reg)| *reg)
                    .or(self.pipeline_input_reg)
                    .or_else(|| src_dst_had_value.then_some(src_dst));
                self.reject_context_pointer_payload(
                    value_reg,
                    &format!("adjust-packet --{} {}", mode.flag_name(), mode.value_name()),
                )?;
                let ctx_vreg = self.materialize_context_pointer_arg();
                let args = match helper {
                    BpfHelper::XdpAdjustHead
                    | BpfHelper::XdpAdjustMeta
                    | BpfHelper::XdpAdjustTail
                    | BpfHelper::SkbPullData => {
                        vec![MirValue::VReg(ctx_vreg), MirValue::VReg(value_vreg)]
                    }
                    BpfHelper::SkbChangeHead | BpfHelper::SkbChangeTail => vec![
                        MirValue::VReg(ctx_vreg),
                        MirValue::VReg(value_vreg),
                        MirValue::Const(0),
                    ],
                    BpfHelper::SkbAdjustRoom => {
                        let mode_value = self
                            .optional_nonnegative_named_u64_arg("adjust-packet --room", "mode")?
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(
                                    "adjust-packet --room requires --mode".into(),
                                )
                            })?;
                        let flags = self
                            .optional_nonnegative_named_u64_arg("adjust-packet --room", "flags")?
                            .unwrap_or(0);
                        vec![
                            MirValue::VReg(ctx_vreg),
                            MirValue::VReg(value_vreg),
                            MirValue::Const(mode_value as i64),
                            MirValue::Const(flags as i64),
                        ]
                    }
                    _ => unreachable!("packet adjust helper selection returned unexpected helper"),
                };
                self.emit(MirInst::CallHelper {
                    dst: dst_vreg,
                    helper: helper as u32,
                    args,
                });
                self.vreg_type_hints.insert(dst_vreg, MirType::I64);
                self.reset_call_result_metadata(src_dst);
            }

            "adjust-message" => {
                self.require_only_named_args("adjust-message", &["flags"])?;
                let mode = self.message_adjust_mode_from_named_flags("adjust-message")?;
                let helper =
                    self.message_adjust_helper_for_current_program("adjust-message", mode)?;

                if matches!(mode, MessageAdjustMode::Apply | MessageAdjustMode::Cork)
                    && self.named_args.contains_key("flags")
                {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "adjust-message --{} does not accept --flags",
                        mode.flag_name()
                    )));
                }

                let first_vreg = self
                    .positional_args
                    .first()
                    .map(|(vreg, _)| *vreg)
                    .or(self.pipeline_input)
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "adjust-message --{} requires {} from pipeline input or a first positional argument",
                            mode.flag_name(),
                            mode.first_value_name()
                        ))
                    })?;
                let first_reg = self
                    .positional_args
                    .first()
                    .map(|(_, reg)| *reg)
                    .or(self.pipeline_input_reg)
                    .or_else(|| src_dst_had_value.then_some(src_dst));
                self.reject_context_pointer_payload(
                    first_reg,
                    &format!(
                        "adjust-message --{} {}",
                        mode.flag_name(),
                        mode.first_value_name()
                    ),
                )?;
                let ctx_vreg = self.materialize_context_pointer_arg();
                let args = match mode {
                    MessageAdjustMode::Apply | MessageAdjustMode::Cork => {
                        vec![MirValue::VReg(ctx_vreg), MirValue::VReg(first_vreg)]
                    }
                    MessageAdjustMode::Pull | MessageAdjustMode::Push | MessageAdjustMode::Pop => {
                        let second_name = mode
                            .second_value_name()
                            .expect("pull/push/pop require a second scalar");
                        let second_vreg = self
                            .positional_args
                            .get(1)
                            .map(|(vreg, _)| *vreg)
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "adjust-message --{} requires a {} as the second positional argument",
                                    mode.flag_name(),
                                    second_name
                                ))
                            })?;
                        let second_reg = self.positional_args.get(1).map(|(_, reg)| *reg);
                        self.reject_context_pointer_payload(
                            second_reg,
                            &format!("adjust-message --{} {}", mode.flag_name(), second_name),
                        )?;
                        let flags = self
                            .optional_nonnegative_named_u64_arg("adjust-message", "flags")?
                            .unwrap_or(0);
                        vec![
                            MirValue::VReg(ctx_vreg),
                            MirValue::VReg(first_vreg),
                            MirValue::VReg(second_vreg),
                            MirValue::Const(flags as i64),
                        ]
                    }
                };
                self.emit(MirInst::CallHelper {
                    dst: dst_vreg,
                    helper: helper as u32,
                    args,
                });
                self.vreg_type_hints.insert(dst_vreg, MirType::I64);
                self.reset_call_result_metadata(src_dst);
            }

            "redirect" => {
                self.require_only_named_args("redirect", &["flags"])?;
                let helper = self.packet_redirect_helper_from_named_flags("redirect")?;
                if let Some(message) = self.probe_ctx.and_then(|ctx| ctx.helper_call_error(helper))
                {
                    return Err(CompileError::UnsupportedInstruction(message));
                }

                let ifindex_vreg = self
                    .positional_args
                    .first()
                    .map(|(vreg, _)| *vreg)
                    .or(self.pipeline_input)
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "redirect requires an ifindex from pipeline input or a first positional argument"
                                .into(),
                        )
                    })?;
                let ifindex_reg = self
                    .positional_args
                    .first()
                    .map(|(_, reg)| *reg)
                    .or(self.pipeline_input_reg)
                    .or_else(|| src_dst_had_value.then_some(src_dst));
                self.reject_context_pointer_payload(ifindex_reg, "redirect ifindex")?;
                let flags = self
                    .optional_nonnegative_named_u64_arg("redirect", "flags")?
                    .unwrap_or(0);
                self.validate_packet_redirect_flags(helper, flags)?;

                let args = match helper {
                    BpfHelper::Redirect | BpfHelper::RedirectPeer => {
                        vec![MirValue::VReg(ifindex_vreg), MirValue::Const(flags as i64)]
                    }
                    BpfHelper::RedirectNeigh => vec![
                        MirValue::VReg(ifindex_vreg),
                        MirValue::Const(0),
                        MirValue::Const(0),
                        MirValue::Const(flags as i64),
                    ],
                    _ => unreachable!(
                        "packet redirect helper selection returned non-redirect helper"
                    ),
                };
                self.emit(MirInst::CallHelper {
                    dst: dst_vreg,
                    helper: helper as u32,
                    args,
                });
                self.vreg_type_hints.insert(dst_vreg, MirType::I64);
                self.reset_call_result_metadata(src_dst);
            }

            "redirect-map" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "redirect-map does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("redirect-map", &["kind", "flags"])?;
                if let Some(message) = self
                    .probe_ctx
                    .and_then(|ctx| ctx.helper_call_error(BpfHelper::RedirectMap))
                {
                    return Err(CompileError::UnsupportedInstruction(message));
                }

                let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "redirect-map requires a literal map name as the first positional argument"
                            .into(),
                    )
                })?;
                let map_name = self.literal_string_arg(map_reg, "redirect-map")?;
                self.validate_generic_map_name(&map_name, "redirect-map")?;
                let map_kind = self.required_redirect_map_kind_arg("redirect-map", &map_name)?;
                let key_vreg = self
                    .positional_args
                    .get(1)
                    .map(|(vreg, _)| *vreg)
                    .or(self.pipeline_input)
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "redirect-map requires a key from pipeline input or a second positional argument"
                                .into(),
                        )
                    })?;
                let key_reg = self
                    .positional_args
                    .get(1)
                    .map(|(_, reg)| *reg)
                    .or(self.pipeline_input_reg)
                    .or_else(|| src_dst_had_value.then_some(src_dst));
                self.reject_context_pointer_payload(key_reg, "redirect-map key")?;
                let flags = self
                    .optional_nonnegative_named_u64_arg("redirect-map", "flags")?
                    .unwrap_or(0);

                let map_vreg = self.emit_typed_map_fd_load(map_name, map_kind);
                self.emit(MirInst::CallHelper {
                    dst: dst_vreg,
                    helper: BpfHelper::RedirectMap as u32,
                    args: vec![
                        MirValue::VReg(map_vreg),
                        MirValue::VReg(key_vreg),
                        MirValue::Const(flags as i64),
                    ],
                });
                self.vreg_type_hints.insert(dst_vreg, MirType::I64);
                self.reset_call_result_metadata(src_dst);
            }

            "redirect-socket" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "redirect-socket does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("redirect-socket", &["kind", "flags"])?;

                let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "redirect-socket requires a literal map name as the first positional argument"
                            .into(),
                    )
                })?;
                let map_name = self.literal_string_arg(map_reg, "redirect-socket")?;
                self.validate_generic_map_name(&map_name, "redirect-socket")?;
                let map_kind = self.required_socket_map_kind_arg("redirect-socket", &map_name)?;
                let helper =
                    self.socket_redirect_helper_for_current_program("redirect-socket", map_kind)?;
                let key_arg = self
                    .positional_args
                    .get(1)
                    .copied()
                    .map(|(vreg, reg)| (vreg, Some(reg)))
                    .or_else(|| self.pipeline_input.map(|vreg| (vreg, self.pipeline_input_reg)))
                    .or_else(|| src_dst_had_value.then_some((dst_vreg, Some(src_dst))))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "redirect-socket requires a key from pipeline input or a second positional argument"
                                .into(),
                        )
                    })?;
                self.reject_context_pointer_payload(key_arg.1, "redirect-socket key")?;
                let flags = self
                    .optional_nonnegative_named_u64_arg("redirect-socket", "flags")?
                    .unwrap_or(0);

                let ctx_vreg = self.materialize_context_pointer_arg();
                let map_vreg = self.emit_typed_map_fd_load(map_name, map_kind);
                let key_value = if helper.signature().arg_kind(2) == HelperArgKind::Pointer {
                    let (key_ptr_vreg, _) = self.materialize_map_value_probe_pointer(
                        key_arg.1,
                        key_arg.0,
                        "redirect-socket",
                    )?;
                    MirValue::VReg(key_ptr_vreg)
                } else {
                    MirValue::VReg(key_arg.0)
                };
                self.emit(MirInst::CallHelper {
                    dst: dst_vreg,
                    helper: helper as u32,
                    args: vec![
                        MirValue::VReg(ctx_vreg),
                        MirValue::VReg(map_vreg),
                        key_value,
                        MirValue::Const(flags as i64),
                    ],
                });
                self.vreg_type_hints.insert(dst_vreg, MirType::I64);
                self.reset_call_result_metadata(src_dst);
            }

            "assign-socket" => {
                self.require_only_named_args("assign-socket", &["flags"])?;
                if self.positional_args.len() > 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "assign-socket accepts at most one socket argument".into(),
                    ));
                }

                let Some(ctx) = self.probe_ctx else {
                    return Err(CompileError::UnsupportedInstruction(
                        "assign-socket requires a known attached program context".into(),
                    ));
                };
                if let Some(message) = ctx.helper_call_error(BpfHelper::SkAssign) {
                    return Err(CompileError::UnsupportedInstruction(message));
                }

                let mut flags = self
                    .optional_nonnegative_named_u64_arg("assign-socket", "flags")?
                    .unwrap_or(0);
                for flag in &self.named_flags {
                    match flag.as_str() {
                        "replace" => flags |= BPF_SK_LOOKUP_F_REPLACE,
                        "no-reuseport" => flags |= BPF_SK_LOOKUP_F_NO_REUSEPORT,
                        _ => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "assign-socket does not accept flag '{}'",
                                flag
                            )));
                        }
                    }
                }
                if let Some((2, message)) = ctx.helper_zero_arg_requirement(BpfHelper::SkAssign)
                    && flags != 0
                {
                    return Err(CompileError::UnsupportedInstruction(message.to_string()));
                }

                let sk_arg = self
                    .positional_args
                    .first()
                    .copied()
                    .map(|(vreg, reg)| (vreg, Some(reg)))
                    .or_else(|| self.pipeline_input.map(|vreg| (vreg, self.pipeline_input_reg)))
                    .or_else(|| src_dst_had_value.then_some((dst_vreg, Some(src_dst))))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "assign-socket requires a socket pointer or null from pipeline input or the first positional argument"
                                .into(),
                        )
                    })?;
                self.reject_context_pointer_payload(sk_arg.1, "assign-socket socket")?;
                let sk_vreg = sk_arg.0;

                let ctx_vreg = self.materialize_context_pointer_arg();
                self.emit(MirInst::CallHelper {
                    dst: dst_vreg,
                    helper: BpfHelper::SkAssign as u32,
                    args: vec![
                        MirValue::VReg(ctx_vreg),
                        MirValue::VReg(sk_vreg),
                        MirValue::Const(flags as i64),
                    ],
                });
                self.implied_ctx_fields.insert(CtxField::Socket);
                self.vreg_type_hints.insert(dst_vreg, MirType::I64);
                self.reset_call_result_metadata(src_dst);
            }

            "kfunc-call" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "kfunc-call does not accept flags".into(),
                    ));
                }

                let (_, name_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "kfunc-call requires a literal kfunc name as the first positional argument"
                            .into(),
                    )
                })?;

                let kfunc = self
                    .get_metadata(name_reg)
                    .and_then(|m| m.literal_string.clone())
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "kfunc-call requires first positional argument to be a string literal"
                                .into(),
                        )
                    })?;

                let btf_id = if let Some((_, reg)) = self.named_args.get("btf-id") {
                    let raw = self
                        .get_metadata(*reg)
                        .and_then(|m| m.literal_int)
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "kfunc-call --btf-id must be a compile-time integer literal".into(),
                            )
                        })?;
                    Some(u32::try_from(raw).map_err(|_| {
                        CompileError::UnsupportedInstruction(
                            "kfunc-call --btf-id must be >= 0".into(),
                        )
                    })?)
                } else {
                    None
                };

                for key in self.named_args.keys() {
                    if key != "btf-id" {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "kfunc-call does not accept named argument '{}'",
                            key
                        )));
                    }
                }

                let positional_args: Vec<_> =
                    self.positional_args.iter().skip(1).copied().collect();
                let has_explicit_context_arg = positional_args
                    .iter()
                    .any(|(_, arg_reg)| self.is_context_reg(*arg_reg));
                let mut args = Vec::new();
                let kfunc_signature = KfuncSignature::for_name_or_kernel_btf(&kfunc);
                let is_known_zero_arg = kfunc_signature
                    .map(|sig| sig.max_args == 0)
                    .unwrap_or(false);
                if let Some(input) = self.pipeline_input
                    && !is_known_zero_arg
                {
                    if has_explicit_context_arg {
                        // Match helper-call behavior: an explicit `$ctx` should
                        // not be duplicated by the ambient pipeline input.
                    } else {
                        let arg_vreg = if self
                            .pipeline_input_reg
                            .is_some_and(|reg| self.is_context_reg(reg))
                        {
                            self.materialize_context_pointer_arg()
                        } else {
                            input
                        };
                        args.push((arg_vreg, self.pipeline_input_reg));
                    }
                }

                for (arg_vreg, arg_reg) in positional_args {
                    let call_arg_vreg = if self.is_context_reg(arg_reg) {
                        self.materialize_context_pointer_arg()
                    } else {
                        arg_vreg
                    };
                    args.push((call_arg_vreg, Some(arg_reg)));
                }

                if args.len() > 5 {
                    return Err(CompileError::UnsupportedInstruction(
                        "BPF kfunc calls support at most 5 arguments".into(),
                    ));
                }

                let mut call_args = Vec::with_capacity(args.len());
                let mut writebacks = Vec::new();
                for (idx, (arg_vreg, arg_reg)) in args.iter().copied().enumerate() {
                    if kfunc_signature
                        .is_some_and(|sig| matches!(sig.arg_kind(idx), KfuncArgKind::Subprogram))
                    {
                        let arg_reg = arg_reg.ok_or_else(|| {
                            CompileError::UnsupportedInstruction(format!(
                                "kfunc-call '{}' arg{} requires an explicit callback argument",
                                kfunc, idx
                            ))
                        })?;
                        let MirValue::VReg(call_arg_vreg) =
                            self.lower_kfunc_callback_subprogram_arg(&kfunc, idx, arg_reg, &args)?
                        else {
                            unreachable!("callback lowering always returns a vreg")
                        };
                        call_args.push(call_arg_vreg);
                        continue;
                    }
                    if let Some(call_arg_vreg) =
                        self.materialize_kfunc_map_fd_arg(&kfunc, idx, arg_reg, &args)?
                    {
                        call_args.push(call_arg_vreg);
                        continue;
                    }
                    let arg_vreg = self.materialize_kernel_btf_field_addr_kfunc_arg(
                        &kfunc, idx, arg_vreg, arg_reg,
                    );
                    let (call_arg_vreg, writeback) =
                        self.materialize_scalar_kfunc_out_arg(&kfunc, idx, arg_vreg, arg_reg)?;
                    call_args.push(call_arg_vreg);
                    if let Some(writeback) = writeback {
                        writebacks.push(writeback);
                    }
                }

                let call_dst_vreg = if src_dst_had_value {
                    self.assign_fresh_vreg(src_dst)
                } else {
                    dst_vreg
                };
                let call_arg_types = args
                    .iter()
                    .zip(call_args.iter())
                    .map(|((source_vreg, source_reg), call_vreg)| {
                        self.vreg_type_hints
                            .get(call_vreg)
                            .cloned()
                            .or_else(|| {
                                source_reg.and_then(|reg| {
                                    self.typed_value_runtime_type(reg, *source_vreg)
                                })
                            })
                            .or_else(|| self.vreg_type_hints.get(source_vreg).cloned())
                            .unwrap_or(MirType::Unknown)
                    })
                    .collect::<Vec<_>>();
                let ret_hint = kfunc_signature.map(|sig| match sig.ret_kind {
                    KfuncRetKind::Scalar | KfuncRetKind::Void => MirType::I64,
                    KfuncRetKind::PointerMaybeNull => {
                        TypeInference::precise_kfunc_return_mir_type_for_args(
                            &kfunc,
                            &call_arg_types,
                        )
                        .unwrap_or(MirType::Ptr {
                            pointee: Box::new(MirType::Unknown),
                            address_space: AddressSpace::Kernel,
                        })
                    }
                });

                self.emit(MirInst::CallKfunc {
                    dst: call_dst_vreg,
                    kfunc,
                    btf_id,
                    args: call_args,
                });
                if let Some(ret_hint) = ret_hint {
                    self.vreg_type_hints.insert(call_dst_vreg, ret_hint.clone());
                    self.reset_call_result_metadata(src_dst);
                    let meta = self.get_or_create_metadata(src_dst);
                    meta.field_type = Some(ret_hint.clone());
                    meta.trusted_btf = matches!(
                        ret_hint,
                        MirType::Ptr {
                            address_space: AddressSpace::Kernel,
                            ..
                        }
                    );
                }
                self.write_back_scalar_kfunc_out_args(writebacks)?;
            }

            "helper-call" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "helper-call does not accept flags".into(),
                    ));
                }

                let (_, name_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "helper-call requires a literal helper name as the first positional argument"
                            .into(),
                    )
                })?;
                let helper_name = self.literal_string_arg(name_reg, "helper-call")?;
                let helper = BpfHelper::from_name(&helper_name).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "helper-call does not support helper '{}'",
                        helper_name
                    ))
                })?;
                let helper_id = helper as u32;
                let sig = HelperSignature::for_id(helper_id).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "helper-call does not have a modeled signature for '{}'",
                        helper.name()
                    ))
                })?;
                if helper.requires_callback_subprogram()
                    && !helper.supports_modeled_callback_subprogram()
                {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "helper-call '{}' requires callback subprogram pointer support, which is not modeled yet",
                        helper.name()
                    )));
                }
                self.require_only_named_args("helper-call", &["kind"])?;
                if self.named_args.contains_key("kind")
                    && !(0..5).any(|idx| helper.helper_requires_explicit_map_kind(idx))
                {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "helper-call --kind is only supported for helpers whose map family is ambiguous; '{}' already implies its map kind",
                        helper.name()
                    )));
                }

                let positional_args: Vec<_> =
                    self.positional_args.iter().skip(1).copied().collect();
                let has_explicit_context_arg = positional_args
                    .iter()
                    .any(|(_, arg_reg)| self.is_context_reg(*arg_reg));
                let mut args = Vec::new();
                let mut helper_arg_regs: Vec<(usize, RegId)> = Vec::new();
                let mut helper_map_args: Vec<(usize, MapRef, VReg)> = Vec::new();
                if let Some(input) = self.pipeline_input
                    && self.positional_args.len() == 1
                    && sig.max_args != 0
                {
                    if has_explicit_context_arg {
                        // Real attached closures carry the program context as ambient
                        // pipeline input. If the caller already passed `$ctx`
                        // explicitly, don't prepend that ambient value again.
                    } else {
                        let arg_vreg = if self
                            .pipeline_input_reg
                            .is_some_and(|reg| self.is_context_reg(reg))
                        {
                            self.materialize_context_pointer_arg()
                        } else {
                            input
                        };
                        let helper_arg_idx = args.len();
                        let arg_vreg =
                            if matches!(sig.arg_kind(helper_arg_idx), HelperArgKind::Pointer)
                                && let Some(input_reg) = self.pipeline_input_reg
                            {
                                self.materialized_metadata_aggregate_vreg(input_reg, arg_vreg)?
                            } else {
                                arg_vreg
                            };
                        let arg_vreg = self.materialize_kernel_btf_field_addr_helper_arg(
                            helper,
                            helper_arg_idx,
                            arg_vreg,
                            self.pipeline_input_reg,
                        );
                        if let Some(input_reg) = self.pipeline_input_reg {
                            helper_arg_regs.push((helper_arg_idx, input_reg));
                        }
                        args.push(MirValue::VReg(arg_vreg));
                    }
                }
                for (pos_idx, (arg_vreg, arg_reg)) in positional_args.iter().copied().enumerate() {
                    let helper_arg_idx = args.len();
                    if helper.supports_local_helper_map_fd(helper_arg_idx) {
                        let (arg, map_ref, map_vreg) =
                            self.materialize_helper_map_fd_arg(helper, helper_arg_idx, arg_reg)?;
                        helper_map_args.push((helper_arg_idx, map_ref, map_vreg));
                        args.push(arg);
                        continue;
                    }
                    if helper.supports_modeled_callback_subprogram()
                        && matches!(sig.arg_kind(helper_arg_idx), HelperArgKind::Subprogram)
                    {
                        let arg = self.lower_helper_callback_subprogram_arg(
                            helper,
                            helper_arg_idx,
                            arg_reg,
                            &helper_map_args,
                            &helper_arg_regs,
                            positional_args.get(pos_idx + 1).copied(),
                        )?;
                        helper_arg_regs.push((helper_arg_idx, arg_reg));
                        args.push(arg);
                        continue;
                    }
                    let helper_arg_vreg = if self.is_context_reg(arg_reg) {
                        self.materialize_context_pointer_arg()
                    } else {
                        arg_vreg
                    };
                    let helper_arg_vreg =
                        if matches!(sig.arg_kind(helper_arg_idx), HelperArgKind::Pointer) {
                            self.materialized_metadata_aggregate_vreg(arg_reg, helper_arg_vreg)?
                        } else {
                            helper_arg_vreg
                        };
                    let helper_arg_vreg = self.materialize_kernel_btf_field_addr_helper_arg(
                        helper,
                        helper_arg_idx,
                        helper_arg_vreg,
                        Some(arg_reg),
                    );
                    helper_arg_regs.push((helper_arg_idx, arg_reg));
                    args.push(MirValue::VReg(helper_arg_vreg));
                }
                if args.len() > 5 {
                    return Err(CompileError::UnsupportedInstruction(
                        "BPF helper calls support at most 5 arguments".into(),
                    ));
                }
                if args.len() < sig.min_args || args.len() > sig.max_args {
                    let with_live_value = args.len().saturating_add(1);
                    if self.pipeline_input.is_some()
                        && self.positional_args.len() > 1
                        && with_live_value >= sig.min_args
                        && with_live_value <= sig.max_args
                    {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "helper-call '{}' does not prepend the piped value when explicit helper arguments are present; pass that value explicitly as the first helper argument",
                            helper.name()
                        )));
                    }
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "helper-call '{}' expects {}..={} helper arguments after the helper name, got {}",
                        helper.name(),
                        sig.min_args,
                        sig.max_args,
                        args.len()
                    )));
                }
                self.validate_timer_helper_call_args(helper, &helper_map_args, &helper_arg_regs)?;
                self.validate_kptr_xchg_helper_call_args(helper, &args, &helper_arg_regs)?;

                self.record_storage_helper_value_schema(
                    helper,
                    dst_vreg,
                    &helper_map_args,
                    &helper_arg_regs,
                )?;

                self.emit(MirInst::CallHelper {
                    dst: dst_vreg,
                    helper: helper_id,
                    args,
                });
                match sig.ret_kind {
                    HelperRetKind::Scalar | HelperRetKind::Void => {
                        let ret_ty = TypeInference::precise_helper_return_mir_type(helper)
                            .unwrap_or(MirType::I64);
                        self.vreg_type_hints.insert(dst_vreg, ret_ty);
                    }
                    HelperRetKind::PointerNonNull | HelperRetKind::PointerMaybeNull => {
                        let ret_ty = TypeInference::precise_helper_return_mir_type(helper)
                            .unwrap_or_else(|| {
                                let address_space = if matches!(helper, BpfHelper::KptrXchg)
                                    || helper_acquire_ref_kind(helper).is_some()
                                {
                                    AddressSpace::Kernel
                                } else {
                                    AddressSpace::Map
                                };
                                MirType::Ptr {
                                    pointee: Box::new(MirType::Unknown),
                                    address_space,
                                }
                            });
                        self.vreg_type_hints.insert(dst_vreg, ret_ty);
                    }
                }
            }

            "tail-call" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "tail-call does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("tail-call", &[])?;

                let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "tail-call requires a literal program-array map name as the first positional argument"
                            .into(),
                    )
                })?;
                let map_name = self.literal_string_arg(map_reg, "tail-call")?;
                self.validate_generic_map_name(&map_name, "tail-call")?;
                let index_vreg = self
                    .positional_args
                    .get(1)
                    .map(|(vreg, _)| *vreg)
                    .or(self.pipeline_input)
                    .or_else(|| src_dst_had_value.then_some(dst_vreg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "tail-call requires a target index from pipeline input or a second positional argument"
                                .into(),
                        )
                    })?;
                let index_reg = self
                    .positional_args
                    .get(1)
                    .map(|(_, reg)| *reg)
                    .or(self.pipeline_input_reg)
                    .or_else(|| src_dst_had_value.then_some(src_dst));
                self.reject_context_pointer_payload(index_reg, "tail-call index")?;

                self.terminate(MirInst::TailCall {
                    prog_map: MapRef {
                        name: map_name,
                        kind: MapKind::ProgArray,
                    },
                    index: MirValue::VReg(index_vreg),
                });
                self.reset_call_result_metadata(src_dst);
            }

            "map-define" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "map-define does not accept flags".into(),
                    ));
                }
                self.require_only_named_args(
                    "map-define",
                    &["kind", "key-type", "value-type", "max-entries", "inner-map"],
                )?;
                if self.pipeline_input.is_some() {
                    return Err(CompileError::UnsupportedInstruction(
                        "map-define does not accept pipeline input".into(),
                    ));
                }
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "map-define requires exactly one positional map name".into(),
                    ));
                }

                let (_, map_reg) = self.positional_args[0];
                let map_name = self.literal_string_arg(map_reg, "map-define")?;
                self.validate_generic_map_name(&map_name, "map-define")?;
                let map_kind = self.map_define_kind_arg("map-define")?;
                let map_ref = MapRef {
                    name: map_name,
                    kind: map_kind,
                };
                if map_ref.kind.is_map_in_map() && self.named_args.contains_key("value-type") {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "map-define --value-type is not supported for map-in-map outer map '{}'; use --inner-map to name a previously declared inner map template",
                        map_ref.name
                    )));
                }
                if map_ref.kind.is_map_in_map() && !self.named_args.contains_key("inner-map") {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "map-define --kind {} requires --inner-map naming a previously declared inner map template",
                        map_ref.kind
                    )));
                }
                if !map_ref.kind.is_map_in_map() && self.named_args.contains_key("inner-map") {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "map-define --inner-map is only supported for array-of-maps or hash-of-maps, got {}",
                        map_ref.kind
                    )));
                }
                if let Some(max_entries) =
                    self.optional_nonnegative_named_u64_arg("map-define", "max-entries")?
                {
                    let max_entries = u32::try_from(max_entries).map_err(|_| {
                        CompileError::UnsupportedInstruction(
                            "map-define --max-entries must fit in u32".into(),
                        )
                    })?;
                    if max_entries == 0 {
                        return Err(CompileError::UnsupportedInstruction(
                            "map-define --max-entries must be positive".into(),
                        ));
                    }
                    if map_ref.kind.is_local_storage() {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "map-define --max-entries is not supported for object-local storage map kind {}",
                            map_ref.kind
                        )));
                    }
                    if let Some(existing) = self.named_map_max_entries(&map_ref)
                        && existing != max_entries
                    {
                        let schema_source =
                            if self.externally_seeded_map_max_entries.contains(&map_ref) {
                                "pinned"
                            } else {
                                "declared"
                            };
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "map-define max entries for '{}' conflicts with {schema_source} map schema",
                            map_ref.name
                        )));
                    }
                    self.register_named_map_max_entries(&map_ref, max_entries);
                } else if map_ref.kind.is_map_in_map() {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "map-define --kind {} requires --max-entries for the outer map",
                        map_ref.kind
                    )));
                }
                if let Some((_, key_type_reg)) = self.named_args.get("key-type").copied() {
                    let key_type_spec =
                        self.literal_string_arg(key_type_reg, "map-define --key-type")?;
                    let key_ty = Self::parse_named_map_key_type_spec(&key_type_spec)?;
                    self.validate_declared_map_key_type(&map_ref, &key_ty, "map-define")?;
                    if self.externally_seeded_map_key_types.contains(&map_ref)
                        && let Some(existing) = self.named_map_key_type(&map_ref)
                        && existing != &key_ty
                    {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "map-define key type for '{}' conflicts with pinned map schema",
                            map_ref.name
                        )));
                    }
                    self.register_named_map_key_type(&map_ref, &key_ty);
                } else if matches!(map_ref.kind, MapKind::HashOfMaps) {
                    return Err(CompileError::UnsupportedInstruction(
                        "map-define --kind hash-of-maps requires --key-type for the outer map"
                            .into(),
                    ));
                }

                if map_ref.kind.is_map_in_map() {
                    let (_, inner_map_reg) =
                        self.named_args.get("inner-map").copied().ok_or_else(|| {
                            CompileError::UnsupportedInstruction(format!(
                                "map-define --kind {} requires --inner-map naming a previously declared inner map template",
                                map_ref.kind
                            ))
                        })?;
                    let inner_map_name =
                        self.literal_string_arg(inner_map_reg, "map-define --inner-map")?;
                    self.validate_generic_map_name(&inner_map_name, "map-define --inner-map")?;
                    if inner_map_name == map_ref.name {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "map-in-map '{}' cannot use itself as its inner map template",
                            map_ref.name
                        )));
                    }
                    let matching_inner_maps = self
                        .map_value_types
                        .keys()
                        .filter(|candidate| candidate.name == inner_map_name)
                        .cloned()
                        .collect::<Vec<_>>();
                    let inner_map_ref = match matching_inner_maps.as_slice() {
                        [inner] => inner,
                        [] => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "map-define --inner-map '{}' must name a previously declared inner map with --value-type",
                                inner_map_name
                            )));
                        }
                        _ => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "map-define --inner-map '{}' is ambiguous; use distinct map names for inner map templates",
                                inner_map_name
                            )));
                        }
                    };
                    if inner_map_ref.kind.is_map_in_map() {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "map-define --inner-map '{}' cannot name another map-in-map template yet",
                            inner_map_name
                        )));
                    }
                    if !inner_map_ref.kind.supports_map_fd_materialization() {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "map-define --inner-map '{}' uses unsupported inner map kind {}",
                            inner_map_name, inner_map_ref.kind
                        )));
                    }
                    self.register_named_map_inner_template(
                        &map_ref,
                        inner_map_ref,
                        "map-define --inner-map",
                    )?;
                    self.declared_map_inner_templates.insert(map_ref.clone());
                } else {
                    let (_, type_reg) =
                        self.named_args.get("value-type").copied().ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "map-define requires --value-type with a compile-time type string"
                                    .into(),
                            )
                        })?;
                    let type_spec = self.literal_string_arg(type_reg, "map-define --value-type")?;
                    let (value_ty, value_semantics) =
                        Self::parse_named_map_value_type_spec(&type_spec)?;
                    Self::validate_named_map_value_type_for_map(
                        &map_ref,
                        &value_ty,
                        "map-define --value-type",
                    )?;

                    if self.externally_seeded_map_value_types.contains(&map_ref)
                        && let Some(existing) = self.named_map_value_type(&map_ref)
                        && existing != &value_ty
                    {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "map-define value type for '{}' conflicts with pinned map schema",
                            map_ref.name
                        )));
                    }
                    self.register_named_map_value_type(&map_ref, &value_ty);
                    self.declared_map_value_types.insert(map_ref.clone());

                    if let Some(value_semantics) = value_semantics {
                        if self
                            .externally_seeded_map_value_semantics
                            .contains(&map_ref)
                            && let Some(existing) = self.named_map_value_semantics(&map_ref)
                            && existing != &value_semantics
                        {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "map-define value semantics for '{}' conflicts with pinned map schema",
                                map_ref.name
                            )));
                        }
                        self.register_named_map_value_semantics(&map_ref, &value_semantics);
                    }
                }

                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
                self.reset_call_result_metadata(src_dst);
            }

            "map-get" => {
                let result_vreg = if src_dst_had_value {
                    self.assign_fresh_vreg(src_dst)
                } else {
                    dst_vreg
                };
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "map-get does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("map-get", &["kind", "init", "flags"])?;

                let (map_arg_vreg, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "map-get requires a literal map name or map-in-map lookup result as the first positional argument"
                            .into(),
                    )
                })?;
                if let Some(inner_map) = self
                    .get_metadata(map_reg)
                    .and_then(|meta| meta.dynamic_map_ref.clone())
                {
                    if !self.named_args.is_empty() {
                        return Err(CompileError::UnsupportedInstruction(
                            "map-get on a dynamic inner-map pointer does not accept named arguments"
                                .into(),
                        ));
                    }
                    let key_vreg = self
                        .positional_args
                        .get(1)
                        .map(|(vreg, _)| *vreg)
                        .or(self.pipeline_input)
                        .or_else(|| src_dst_had_value.then_some(dst_vreg))
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "map-get requires a key from pipeline input or a second positional argument"
                                    .into(),
                            )
                        })?;
                    let key_reg = self
                        .positional_args
                        .get(1)
                        .map(|(_, reg)| *reg)
                        .or(self.pipeline_input_reg)
                        .or_else(|| src_dst_had_value.then_some(src_dst));
                    let key_vreg = self.map_key_vreg_for_named_schema(
                        &inner_map,
                        key_vreg,
                        key_reg,
                        "map-get dynamic map",
                    )?;
                    let lookup_vreg = self.func.alloc_vreg();

                    self.emit(MirInst::MapLookupDynamic {
                        dst: lookup_vreg,
                        map_ptr: map_arg_vreg,
                        inner_map: inner_map.clone(),
                        key: key_vreg,
                    });
                    self.emit(MirInst::Copy {
                        dst: result_vreg,
                        src: MirValue::VReg(lookup_vreg),
                    });

                    let stored_ty = self.validated_named_map_value_type(
                        &inner_map,
                        "map-get dynamic value schema",
                    )?;
                    self.record_map_value_lookup_result(
                        src_dst,
                        lookup_vreg,
                        result_vreg,
                        &inner_map,
                        key_vreg,
                        stored_ty,
                    );
                } else {
                    let map_name = self.literal_string_arg(map_reg, "map-get")?;
                    self.validate_generic_map_name(&map_name, "map-get")?;
                    let map_kind = self.map_get_kind_arg("map-get", &map_name)?;
                    let map_ref = MapRef {
                        name: map_name.clone(),
                        kind: map_kind,
                    };
                    if map_kind.is_local_storage() {
                        self.lower_local_storage_map_get(
                            src_dst,
                            dst_vreg,
                            result_vreg,
                            src_dst_had_value,
                            map_ref,
                        )?;
                    } else {
                        if self.named_args.contains_key("init") {
                            return Err(CompileError::UnsupportedInstruction(
                                "map-get --init is only supported for local-storage map kinds"
                                    .into(),
                            ));
                        }
                        if self.named_args.contains_key("flags") {
                            return Err(CompileError::UnsupportedInstruction(
                                "map-get --flags is only supported for local-storage map kinds"
                                    .into(),
                            ));
                        }
                        self.validate_generic_map_lookup_kind(map_kind, &map_name)?;
                        let key_vreg = self
                        .positional_args
                        .get(1)
                        .map(|(vreg, _)| *vreg)
                        .or(self.pipeline_input)
                        .or_else(|| src_dst_had_value.then_some(dst_vreg))
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "map-get requires a key from pipeline input or a second positional argument"
                                    .into(),
                            )
                        })?;
                        let key_reg = self
                            .positional_args
                            .get(1)
                            .map(|(_, reg)| *reg)
                            .or(self.pipeline_input_reg)
                            .or_else(|| src_dst_had_value.then_some(src_dst));
                        let key_vreg = self.map_key_vreg_for_named_schema(
                            &map_ref, key_vreg, key_reg, "map-get",
                        )?;
                        let lookup_vreg = self.func.alloc_vreg();

                        self.emit(MirInst::MapLookup {
                            dst: lookup_vreg,
                            map: map_ref.clone(),
                            key: key_vreg,
                        });
                        self.emit(MirInst::Copy {
                            dst: result_vreg,
                            src: MirValue::VReg(lookup_vreg),
                        });

                        if map_ref.kind.is_map_in_map() {
                            let inner_map = self.map_in_map_inner_template(&map_ref, "map-get")?;
                            let runtime_ty = MirType::named_kernel_struct_ptr("bpf_map");
                            self.vreg_type_hints.insert(lookup_vreg, runtime_ty.clone());
                            self.vreg_type_hints.insert(result_vreg, runtime_ty.clone());
                            self.reset_call_result_metadata(src_dst);
                            let meta = self.get_or_create_metadata(src_dst);
                            meta.field_type = Some(runtime_ty);
                            meta.dynamic_map_ref = Some(inner_map);
                        } else {
                            let stored_ty = self
                                .validated_named_map_value_type(&map_ref, "map-get value schema")?;
                            self.record_map_value_lookup_result(
                                src_dst,
                                lookup_vreg,
                                result_vreg,
                                &map_ref,
                                key_vreg,
                                stored_ty,
                            );
                        }
                    }
                }
            }

            "map-put" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "map-put does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("map-put", &["kind", "flags"])?;

                let (map_arg_vreg, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "map-put requires a literal map name or map-in-map lookup result as the first positional argument"
                            .into(),
                    )
                })?;
                let (key_vreg, key_reg) = self
                    .positional_args
                    .get(1)
                    .map(|(vreg, reg)| (*vreg, *reg))
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "map-put requires a key as the second positional argument".into(),
                        )
                    })?;
                let flags = self
                    .optional_nonnegative_named_u64_arg("map-put", "flags")?
                    .unwrap_or(0);

                if let Some(inner_map) = self
                    .get_metadata(map_reg)
                    .and_then(|meta| meta.dynamic_map_ref.clone())
                {
                    if self.named_args.contains_key("kind") {
                        return Err(CompileError::UnsupportedInstruction(
                            "map-put on a dynamic inner-map pointer does not accept --kind".into(),
                        ));
                    }
                    self.validate_generic_map_update_kind(inner_map.kind, &inner_map.name)?;
                    self.reject_context_pointer_payload(Some(key_reg), "map-put key")?;
                    let key_vreg = self.map_key_vreg_for_named_schema(
                        &inner_map,
                        key_vreg,
                        Some(key_reg),
                        "map-put dynamic map",
                    )?;
                    let value_vreg = self.pipeline_input.ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "map-put requires a value from pipeline input".into(),
                        )
                    })?;
                    let value_reg = self.pipeline_input_reg;
                    let stored_value_vreg = if let Some(value_reg) = value_reg {
                        self.reject_context_pointer_payload(Some(value_reg), "map-put value")?;
                        self.materialized_metadata_aggregate_vreg(value_reg, value_vreg)?
                    } else {
                        value_vreg
                    };

                    self.emit(MirInst::MapUpdateDynamic {
                        map_ptr: map_arg_vreg,
                        inner_map: inner_map.clone(),
                        key: key_vreg,
                        val: stored_value_vreg,
                        flags,
                    });
                    self.record_named_map_value_schema_from_reg(
                        &inner_map,
                        value_reg,
                        "map-put dynamic map",
                    )?;

                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::Const(0),
                    });
                    self.reset_call_result_metadata(src_dst);
                } else {
                    let map_name = self.literal_string_arg(map_reg, "map-put")?;
                    self.validate_generic_map_name(&map_name, "map-put")?;
                    let map_kind = self.generic_map_kind_arg("map-put", &map_name)?;
                    let map_ref = MapRef {
                        name: map_name.clone(),
                        kind: map_kind,
                    };
                    if map_kind.is_socket_map() {
                        self.lower_socket_map_put(
                            src_dst, dst_vreg, map_ref, key_vreg, key_reg, flags,
                        )?;
                    } else {
                        self.validate_generic_map_update_kind(map_kind, &map_name)?;
                        self.reject_context_pointer_payload(Some(key_reg), "map-put key")?;
                        let key_vreg = self.map_key_vreg_for_named_schema(
                            &map_ref,
                            key_vreg,
                            Some(key_reg),
                            "map-put",
                        )?;
                        let value_vreg = self.pipeline_input.ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "map-put requires a value from pipeline input".into(),
                            )
                        })?;
                        let value_reg = self.pipeline_input_reg;
                        let stored_value_vreg = if let Some(value_reg) = value_reg {
                            self.reject_context_pointer_payload(Some(value_reg), "map-put value")?;
                            self.materialized_metadata_aggregate_vreg(value_reg, value_vreg)?
                        } else {
                            value_vreg
                        };

                        self.emit(MirInst::MapUpdate {
                            map: map_ref.clone(),
                            key: key_vreg,
                            val: stored_value_vreg,
                            flags,
                        });
                        self.record_named_map_value_schema_from_reg(
                            &map_ref, value_reg, "map-put",
                        )?;

                        self.emit(MirInst::Copy {
                            dst: dst_vreg,
                            src: MirValue::Const(0),
                        });
                        self.reset_call_result_metadata(src_dst);
                    }
                }
            }

            "map-push" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "map-push does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("map-push", &["kind", "flags"])?;

                let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "map-push requires a literal map name as the first positional argument"
                            .into(),
                    )
                })?;
                let map_name = self.literal_string_arg(map_reg, "map-push")?;
                self.validate_generic_map_name(&map_name, "map-push")?;
                let map_kind =
                    self.required_queue_stack_bloom_map_kind_arg("map-push", &map_name)?;
                let map_ref = MapRef {
                    name: map_name,
                    kind: map_kind,
                };
                let flags = if let Some((_, reg)) = self.named_args.get("flags") {
                    let raw = self
                        .get_metadata(*reg)
                        .and_then(|m| m.literal_int)
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "map-push --flags must be a compile-time integer literal".into(),
                            )
                        })?;
                    u64::try_from(raw).map_err(|_| {
                        CompileError::UnsupportedInstruction("map-push --flags must be >= 0".into())
                    })?
                } else {
                    0
                };
                let value_vreg = self.pipeline_input.ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "map-push requires a value from pipeline input".into(),
                    )
                })?;
                let value_reg = self.pipeline_input_reg;
                let stored_value_vreg = if let Some(value_reg) = value_reg {
                    self.reject_context_pointer_payload(Some(value_reg), "map-push value")?;
                    self.materialized_metadata_aggregate_vreg(value_reg, value_vreg)?
                } else {
                    value_vreg
                };
                self.record_named_map_value_schema_from_reg(&map_ref, value_reg, "map-push")?;

                self.emit(MirInst::MapPush {
                    map: map_ref,
                    val: stored_value_vreg,
                    flags,
                });
                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
                self.reset_call_result_metadata(src_dst);
            }

            "map-peek" => {
                self.lower_queue_stack_map_take(
                    src_dst,
                    dst_vreg,
                    "map-peek",
                    BpfHelper::MapPeekElem,
                )?;
            }

            "map-pop" => {
                self.lower_queue_stack_map_take(
                    src_dst,
                    dst_vreg,
                    "map-pop",
                    BpfHelper::MapPopElem,
                )?;
            }

            "map-contains" => {
                self.lower_map_contains(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "map-delete" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "map-delete does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("map-delete", &["kind"])?;

                let (map_arg_vreg, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "map-delete requires a literal map name or map-in-map lookup result as the first positional argument"
                            .into(),
                    )
                })?;

                if let Some(inner_map) = self
                    .get_metadata(map_reg)
                    .and_then(|meta| meta.dynamic_map_ref.clone())
                {
                    if !self.named_args.is_empty() {
                        return Err(CompileError::UnsupportedInstruction(
                            "map-delete on a dynamic inner-map pointer does not accept named arguments"
                                .into(),
                        ));
                    }
                    self.validate_generic_map_delete_kind(inner_map.kind, &inner_map.name)?;
                    let key_vreg = self
                        .positional_args
                        .get(1)
                        .map(|(vreg, _)| *vreg)
                        .or(self.pipeline_input)
                        .or_else(|| src_dst_had_value.then_some(dst_vreg))
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "map-delete requires a key from pipeline input or a second positional argument"
                                    .into(),
                            )
                        })?;
                    let key_reg = self
                        .positional_args
                        .get(1)
                        .map(|(_, reg)| *reg)
                        .or(self.pipeline_input_reg)
                        .or_else(|| src_dst_had_value.then_some(src_dst));
                    let key_vreg = self.map_key_vreg_for_named_schema(
                        &inner_map,
                        key_vreg,
                        key_reg,
                        "map-delete dynamic map",
                    )?;

                    self.emit(MirInst::MapDeleteDynamic {
                        map_ptr: map_arg_vreg,
                        inner_map,
                        key: key_vreg,
                    });
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::Const(0),
                    });
                    self.reset_call_result_metadata(src_dst);
                } else {
                    let map_name = self.literal_string_arg(map_reg, "map-delete")?;
                    self.validate_generic_map_name(&map_name, "map-delete")?;
                    let map_kind = self.map_delete_kind_arg("map-delete", &map_name)?;
                    let map_ref = MapRef {
                        name: map_name,
                        kind: map_kind,
                    };
                    if map_kind.is_local_storage() {
                        self.lower_local_storage_map_delete(
                            src_dst,
                            dst_vreg,
                            src_dst_had_value,
                            map_ref,
                        )?;
                    } else {
                        self.validate_generic_map_delete_kind(map_kind, &map_ref.name)?;
                        let key_vreg = self
                            .positional_args
                            .get(1)
                            .map(|(vreg, _)| *vreg)
                            .or(self.pipeline_input)
                            .or_else(|| src_dst_had_value.then_some(dst_vreg))
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(
                                    "map-delete requires a key from pipeline input or a second positional argument"
                                        .into(),
                                )
                            })?;
                        let key_reg = self
                            .positional_args
                            .get(1)
                            .map(|(_, reg)| *reg)
                            .or(self.pipeline_input_reg)
                            .or_else(|| src_dst_had_value.then_some(src_dst));
                        let key_vreg = self.map_key_vreg_for_named_schema(
                            &map_ref,
                            key_vreg,
                            key_reg,
                            "map-delete",
                        )?;

                        self.emit(MirInst::MapDelete {
                            map: map_ref,
                            key: key_vreg,
                        });
                        self.emit(MirInst::Copy {
                            dst: dst_vreg,
                            src: MirValue::Const(0),
                        });
                        self.reset_call_result_metadata(src_dst);
                    }
                }
            }

            "global-define" => {
                let has_type_spec = self.named_args.contains_key("type");
                let zero_init = self.named_flags.iter().any(|flag| flag == "zero");
                if self.named_flags.iter().any(|flag| flag != "zero") {
                    return Err(CompileError::UnsupportedInstruction(
                        "global-define only accepts the --zero flag".into(),
                    ));
                }
                self.require_only_named_args("global-define", &["type"])?;
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "global-define requires exactly one positional global name".into(),
                    ));
                }

                let (_, name_reg) = self.positional_args[0];
                let global_name = self.literal_string_arg(name_reg, "global-define")?;
                self.validate_generic_map_name(&global_name, "global-define")?;
                if has_type_spec {
                    if zero_init {
                        return Err(CompileError::UnsupportedInstruction(
                            "global-define --type already implies zero initialization; do not combine it with --zero".into(),
                        ));
                    }
                    let (type_vreg, type_reg) =
                        self.named_args.get("type").copied().ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "global-define --type requires a compile-time type string".into(),
                            )
                        })?;
                    let _ = type_vreg;
                    let type_spec = self.literal_string_arg(type_reg, "global-define --type")?;
                    let constant_value = self.pipeline_input_reg.and_then(|reg| {
                        self.get_metadata(reg)
                            .and_then(|meta| meta.constant_value.clone())
                    });
                    if let Some(value) = constant_value.as_ref() {
                        self.define_named_program_global_from_type_spec_and_value(
                            &global_name,
                            &type_spec,
                            value,
                        )?;
                    } else if self.pipeline_input.is_some() {
                        return Err(CompileError::UnsupportedInstruction(
                            "global-define --type with pipeline input requires a compile-time constant value".into(),
                        ));
                    } else {
                        self.define_named_program_global_from_type_spec(&global_name, &type_spec)?;
                    }

                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::Const(0),
                    });
                    self.reset_call_result_metadata(src_dst);
                    return Ok(());
                }
                let value_vreg = self.pipeline_input.ok_or_else(|| {
                    CompileError::UnsupportedInstruction(if zero_init {
                        "global-define --zero requires a value from pipeline input to establish layout"
                            .into()
                    } else {
                        "global-define requires a compile-time constant value from pipeline input"
                            .into()
                    })
                })?;
                let value_reg = self.pipeline_input_reg.ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "global-define requires a source value with tracked metadata".into(),
                    )
                })?;
                self.reject_context_pointer_payload(Some(value_reg), "global-define value")?;
                if !zero_init
                    && self
                        .get_metadata(value_reg)
                        .and_then(|meta| meta.constant_value.as_ref())
                        .is_none()
                {
                    return Err(CompileError::UnsupportedInstruction(
                        "global-define requires a compile-time constant value".into(),
                    ));
                }
                if zero_init {
                    self.ensure_zeroed_named_program_global(&global_name, value_reg, value_vreg)?;
                } else {
                    self.ensure_named_program_global(&global_name, value_reg, value_vreg)?;
                }

                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
                self.reset_call_result_metadata(src_dst);
            }

            "global-get" => {
                let result_vreg = if src_dst_had_value {
                    self.assign_fresh_vreg(src_dst)
                } else {
                    dst_vreg
                };
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "global-get does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("global-get", &[])?;
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "global-get requires exactly one positional global name".into(),
                    ));
                }

                let (_, name_reg) = self.positional_args[0];
                let global_name = self.literal_string_arg(name_reg, "global-get")?;
                self.validate_generic_map_name(&global_name, "global-get")?;
                let global = self
                    .named_program_global(&global_name)
                    .cloned()
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "global-get for '{}' requires a same-program global-define or layout-establishing global-set",
                            global_name
                        ))
                    })?;

                self.load_mutable_global_value(src_dst, result_vreg, &global)?;
                if let Some(semantics) = self.named_program_global_semantics(&global_name).cloned()
                {
                    self.get_or_create_metadata(src_dst).annotated_semantics = Some(semantics);
                }
            }

            "global-set" => {
                if !self.named_flags.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "global-set does not accept flags".into(),
                    ));
                }
                self.require_only_named_args("global-set", &[])?;
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "global-set requires exactly one positional global name".into(),
                    ));
                }

                let (_, name_reg) = self.positional_args[0];
                let global_name = self.literal_string_arg(name_reg, "global-set")?;
                self.validate_generic_map_name(&global_name, "global-set")?;
                let value_vreg = self.pipeline_input.ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "global-set requires a value from pipeline input".into(),
                    )
                })?;
                let value_reg = self.pipeline_input_reg.ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "global-set requires a source value with tracked metadata".into(),
                    )
                })?;
                self.reject_context_pointer_payload(Some(value_reg), "global-set value")?;
                let global =
                    self.ensure_named_program_global(&global_name, value_reg, value_vreg)?;
                self.store_into_mutable_global(
                    &format!("global '{}'", global_name),
                    &global,
                    value_reg,
                    value_vreg,
                )?;

                self.emit(MirInst::Copy {
                    dst: dst_vreg,
                    src: MirValue::Const(0),
                });
                self.reset_call_result_metadata(src_dst);
            }

            "where" => {
                // where { condition } - filter pipeline by condition
                // Get the pipeline input (value to filter)
                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let input_reg = self
                    .pipeline_input_reg
                    .or(src_dst_had_value.then_some(src_dst));
                if !self.named_flags.is_empty() || !self.named_args.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "where does not accept named flags or arguments in eBPF".into(),
                    ));
                }
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "where requires exactly one closure argument in eBPF".into(),
                    ));
                }

                // Get the closure block ID from positional args
                let closure_block_id = self
                    .positional_args
                    .first()
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.closure_block_id);

                if let Some(block_id) = closure_block_id {
                    // Inline the closure with $in bound to input_vreg
                    let closure_ir = self.closure_irs.get(&block_id).ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "Closure block {} not found",
                            block_id.get()
                        ))
                    })?;

                    let meta = input_reg.and_then(|reg| self.get_metadata(reg).cloned());
                    if let Some(meta) = meta
                        && let Some((_slot, max_len)) = meta.list_buffer
                    {
                        let (out_slot, out_ty) =
                            self.create_stack_numeric_list_result(dst_vreg, max_len);

                        if max_len > 0 {
                            let len_vreg = self.func.alloc_vreg();
                            self.emit(MirInst::ListLen {
                                dst: len_vreg,
                                list: input_vreg,
                            });
                            self.vreg_type_hints.insert(len_vreg, MirType::U64);
                            let continuation_block = self.func.alloc_block();
                            for i in 0..max_len {
                                let predicate_block = self.func.alloc_block();
                                let next_block = if i + 1 == max_len {
                                    continuation_block
                                } else {
                                    self.func.alloc_block()
                                };
                                let in_bounds_vreg = self.func.alloc_vreg();
                                self.emit(MirInst::BinOp {
                                    dst: in_bounds_vreg,
                                    op: BinOpKind::Lt,
                                    lhs: MirValue::Const(i as i64),
                                    rhs: MirValue::VReg(len_vreg),
                                });
                                self.vreg_type_hints.insert(in_bounds_vreg, MirType::Bool);
                                self.terminate(MirInst::Branch {
                                    cond: in_bounds_vreg,
                                    if_true: predicate_block,
                                    if_false: next_block,
                                });

                                self.current_block = predicate_block;
                                let elem_vreg = self.func.alloc_vreg();
                                self.emit(MirInst::ListGet {
                                    dst: elem_vreg,
                                    list: input_vreg,
                                    idx: MirValue::Const(i as i64),
                                });
                                self.vreg_type_hints.insert(elem_vreg, MirType::I64);

                                let predicate =
                                    self.inline_closure_with_in(block_id, closure_ir, elem_vreg)?;
                                let push_block = self.func.alloc_block();
                                self.terminate(MirInst::Branch {
                                    cond: predicate,
                                    if_true: push_block,
                                    if_false: next_block,
                                });

                                self.current_block = push_block;
                                self.emit(MirInst::ListPush {
                                    list: dst_vreg,
                                    item: elem_vreg,
                                });
                                self.terminate(MirInst::Jump { target: next_block });

                                self.current_block = next_block;
                            }
                            self.current_block = continuation_block;
                        }

                        self.install_stack_numeric_list_result_metadata(
                            src_dst, out_slot, out_ty, max_len, None,
                        );
                        return Ok(());
                    }

                    let result_vreg =
                        self.inline_closure_with_in(block_id, closure_ir, input_vreg)?;

                    // Create exit block and continue block
                    let exit_block = self.func.alloc_block();
                    let continue_block = self.func.alloc_block();

                    // Branch: if result is 0/false, exit
                    let negated = self.func.alloc_vreg();
                    self.emit(MirInst::UnaryOp {
                        dst: negated,
                        op: crate::compiler::mir::UnaryOpKind::Not,
                        src: MirValue::VReg(result_vreg),
                    });
                    self.terminate(MirInst::Branch {
                        cond: negated,
                        if_true: exit_block,
                        if_false: continue_block,
                    });

                    // Exit block returns 0
                    self.current_block = exit_block;
                    self.terminate(MirInst::Return {
                        val: Some(MirValue::Const(0)),
                    });

                    // Continue block passes the original value through
                    self.current_block = continue_block;
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(input_vreg),
                    });

                    if let Some(reg) = input_reg {
                        self.propagate_passthrough_reg_metadata(src_dst, dst_vreg, reg, input_vreg);
                    }
                } else {
                    return Err(CompileError::UnsupportedInstruction(
                        "where requires a closure argument".into(),
                    ));
                }
            }

            "each" => {
                // each { closure } - transform pipeline values
                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                let input_reg = self.pipeline_input_reg;

                // Get the closure block ID from positional args
                let closure_block_id = self
                    .positional_args
                    .first()
                    .and_then(|(_, reg)| self.get_metadata(*reg))
                    .and_then(|m| m.closure_block_id);

                if let Some(block_id) = closure_block_id {
                    // Look up the closure IR
                    let closure_ir = self.closure_irs.get(&block_id).ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "Closure block {} not found",
                            block_id.get()
                        ))
                    })?;

                    // For lists, we can map each element
                    let meta = input_reg.and_then(|reg| self.get_metadata(reg).cloned());
                    if let Some(meta) = meta {
                        if let Some((_slot, max_len)) = meta.list_buffer {
                            // Create a new list for output
                            let (out_slot, out_ty) =
                                self.create_stack_numeric_list_result(dst_vreg, max_len);

                            if max_len > 0 {
                                let len_vreg = self.func.alloc_vreg();
                                self.emit(MirInst::ListLen {
                                    dst: len_vreg,
                                    list: input_vreg,
                                });
                                self.vreg_type_hints.insert(len_vreg, MirType::U64);
                                let continuation_block = self.func.alloc_block();
                                for i in 0..max_len {
                                    let transform_block = self.func.alloc_block();
                                    let next_block = if i + 1 == max_len {
                                        continuation_block
                                    } else {
                                        self.func.alloc_block()
                                    };
                                    let in_bounds_vreg = self.func.alloc_vreg();
                                    self.emit(MirInst::BinOp {
                                        dst: in_bounds_vreg,
                                        op: BinOpKind::Lt,
                                        lhs: MirValue::Const(i as i64),
                                        rhs: MirValue::VReg(len_vreg),
                                    });
                                    self.vreg_type_hints.insert(in_bounds_vreg, MirType::Bool);
                                    self.terminate(MirInst::Branch {
                                        cond: in_bounds_vreg,
                                        if_true: transform_block,
                                        if_false: next_block,
                                    });

                                    self.current_block = transform_block;
                                    let elem_vreg = self.func.alloc_vreg();
                                    self.emit(MirInst::ListGet {
                                        dst: elem_vreg,
                                        list: input_vreg,
                                        idx: MirValue::Const(i as i64),
                                    });
                                    self.vreg_type_hints.insert(elem_vreg, MirType::I64);

                                    // Transform element with closure
                                    let transformed = self
                                        .inline_closure_with_in(block_id, closure_ir, elem_vreg)?;
                                    self.emit(MirInst::ListPush {
                                        list: dst_vreg,
                                        item: transformed,
                                    });
                                    self.terminate(MirInst::Jump { target: next_block });

                                    self.current_block = next_block;
                                }
                                self.current_block = continuation_block;
                            }

                            // Copy metadata for output list
                            self.install_stack_numeric_list_result_metadata(
                                src_dst,
                                out_slot,
                                out_ty,
                                max_len,
                                Self::numeric_list_known_len(&meta),
                            );
                            return Ok(());
                        }
                    }

                    // Default: apply closure and return transformed value
                    let result_vreg =
                        self.inline_closure_with_in(block_id, closure_ir, input_vreg)?;
                    self.emit(MirInst::Copy {
                        dst: dst_vreg,
                        src: MirValue::VReg(result_vreg),
                    });

                    // Copy metadata from input to output
                    if let Some(reg) = input_reg {
                        if let Some(meta) = self.get_metadata(reg).cloned() {
                            let out_meta = self.get_or_create_metadata(src_dst);
                            out_meta.field_type = meta.field_type;
                            out_meta.string_slot = meta.string_slot;
                            out_meta.record_fields = meta.record_fields;
                        }
                    }
                } else {
                    return Err(CompileError::UnsupportedInstruction(
                        "each requires a closure argument".into(),
                    ));
                }
            }

            "all" | "any" => {
                self.lower_stack_list_all_or_any(&cmd_name, src_dst, dst_vreg, src_dst_had_value)?;
            }

            "take" | "skip" | "drop" => {
                self.lower_stack_list_take_skip_or_drop(
                    &cmd_name,
                    src_dst,
                    dst_vreg,
                    src_dst_had_value,
                )?;
            }

            "reverse" => {
                self.lower_stack_list_reverse(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "uniq" => {
                self.lower_stack_list_uniq(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "sort" => {
                self.lower_stack_list_sort(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "compact" => {
                self.lower_stack_list_compact(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "find" => {
                self.lower_stack_list_find(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "split list" => {
                self.lower_compile_time_split_list(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "append" | "prepend" => {
                self.lower_stack_list_append_or_prepend(
                    &cmd_name,
                    src_dst,
                    dst_vreg,
                    src_dst_had_value,
                )?;
            }

            "is-empty" | "is-not-empty" => {
                let want_non_empty = cmd_name == "is-not-empty";
                let empty_cmp_op = if want_non_empty {
                    BinOpKind::Ne
                } else {
                    BinOpKind::Eq
                };
                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
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
                        "{cmd_name} does not accept arguments in eBPF"
                    )));
                }

                let input_meta = input_reg.and_then(|reg| self.get_metadata(reg).cloned());
                if input_meta
                    .as_ref()
                    .and_then(|meta| meta.list_buffer)
                    .is_some()
                {
                    let len_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::ListLen {
                        dst: len_vreg,
                        list: input_vreg,
                    });
                    self.vreg_type_hints.insert(len_vreg, MirType::U64);
                    self.emit(MirInst::BinOp {
                        dst: result_vreg,
                        op: empty_cmp_op,
                        lhs: MirValue::VReg(len_vreg),
                        rhs: MirValue::Const(0),
                    });
                } else if let Some(len_vreg) = input_meta.as_ref().and_then(|meta| {
                    meta.string_len_vreg.or_else(|| match &meta.constant_value {
                        Some(nu_protocol::Value::String { val, .. }) => {
                            let const_len_vreg = self.func.alloc_vreg();
                            self.emit(MirInst::Copy {
                                dst: const_len_vreg,
                                src: MirValue::Const(val.len() as i64),
                            });
                            self.vreg_type_hints.insert(const_len_vreg, MirType::U64);
                            Some(const_len_vreg)
                        }
                        _ => None,
                    })
                }) {
                    self.emit(MirInst::BinOp {
                        dst: result_vreg,
                        op: empty_cmp_op,
                        lhs: MirValue::VReg(len_vreg),
                        rhs: MirValue::Const(0),
                    });
                } else if let Some(empty) = input_meta.as_ref().and_then(|meta| {
                    if !meta.record_fields.is_empty() {
                        Some(false)
                    } else {
                        meta.constant_value.as_ref().and_then(|value| match value {
                            nu_protocol::Value::Record { val, .. } => Some(val.is_empty()),
                            nu_protocol::Value::Nothing { .. } => Some(true),
                            nu_protocol::Value::List { vals, .. } => Some(vals.is_empty()),
                            _ => None,
                        })
                    }
                }) {
                    self.emit(MirInst::Copy {
                        dst: result_vreg,
                        src: MirValue::Const(if empty ^ want_non_empty { 1 } else { 0 }),
                    });
                } else {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} requires a stack-backed list, tracked string, metadata-backed record, or literal null input in eBPF"
                    )));
                }

                self.reset_call_result_metadata(src_dst);
                let out_meta = self.get_or_create_metadata(src_dst);
                out_meta.field_type = Some(MirType::Bool);
                self.vreg_type_hints.insert(result_vreg, MirType::Bool);
            }

            "length" => {
                let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
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
                        "length does not accept arguments in eBPF".into(),
                    ));
                }

                let input_meta = input_reg.and_then(|reg| self.get_metadata(reg).cloned());
                if input_meta
                    .as_ref()
                    .and_then(|meta| meta.list_buffer)
                    .is_some()
                {
                    self.emit(MirInst::ListLen {
                        dst: result_vreg,
                        list: input_vreg,
                    });
                } else if let Some(len) = input_meta.as_ref().and_then(|meta| {
                    meta.constant_value.as_ref().and_then(|value| match value {
                        nu_protocol::Value::Nothing { .. } => Some(0),
                        nu_protocol::Value::List { vals, .. } => Some(vals.len()),
                        nu_protocol::Value::Binary { val, .. } => Some(val.len()),
                        _ => None,
                    })
                }) {
                    self.emit(MirInst::Copy {
                        dst: result_vreg,
                        src: MirValue::Const(len as i64),
                    });
                } else {
                    return Err(CompileError::UnsupportedInstruction(
                        "length requires a stack-backed list, literal binary, or literal null input in eBPF"
                            .into(),
                    ));
                }

                self.reset_call_result_metadata(src_dst);
                let out_meta = self.get_or_create_metadata(src_dst);
                out_meta.field_type = Some(MirType::I64);
                self.vreg_type_hints.insert(result_vreg, MirType::I64);
            }

            "describe" => {
                self.lower_describe(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "bytes length" => {
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
                        "bytes length does not accept arguments in eBPF".into(),
                    ));
                }

                let input = input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .and_then(|meta| meta.constant_value.as_ref())
                    .cloned()
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "bytes length requires compile-time known binary or list<binary> input in eBPF"
                                .into(),
                        )
                    })?;
                let len = match input {
                    nu_protocol::Value::Binary { val, .. } => val.len(),
                    nu_protocol::Value::List { vals, .. } => {
                        let lengths = vals
                            .iter()
                            .enumerate()
                            .map(|(index, item)| {
                                let nu_protocol::Value::Binary { val, .. } = item else {
                                    return Err(CompileError::UnsupportedInstruction(format!(
                                        "bytes length requires binary list items in eBPF; item {index} has type {}",
                                        item.get_type()
                                    )));
                                };
                                Ok(nu_protocol::Value::int(
                                    val.len() as i64,
                                    nu_protocol::Span::unknown(),
                                ))
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        return self.lower_constant_value(
                            src_dst,
                            &nu_protocol::Value::list(lengths, nu_protocol::Span::unknown()),
                        );
                    }
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(
                            "bytes length requires compile-time known binary or list<binary> input in eBPF"
                                .into(),
                        ));
                    }
                };
                self.emit(MirInst::Copy {
                    dst: result_vreg,
                    src: MirValue::Const(len as i64),
                });
                self.reset_call_result_metadata(src_dst);
                let out_meta = self.get_or_create_metadata(src_dst);
                out_meta.field_type = Some(MirType::I64);
                out_meta.constant_value = Some(nu_protocol::Value::int(
                    len as i64,
                    nu_protocol::Span::unknown(),
                ));
                self.vreg_type_hints.insert(result_vreg, MirType::I64);
            }

            "bytes starts-with" | "bytes ends-with" => {
                let input_reg = self
                    .pipeline_input_reg
                    .or(src_dst_had_value.then_some(src_dst));
                let result_vreg = if src_dst_had_value {
                    self.assign_fresh_vreg(src_dst)
                } else {
                    dst_vreg
                };

                if !self.named_flags.is_empty() || !self.named_args.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} does not accept named flags or arguments in eBPF"
                    )));
                }
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} accepts exactly one binary pattern argument in eBPF"
                    )));
                }

                let input = input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .and_then(|meta| match meta.constant_value.as_ref() {
                        Some(nu_protocol::Value::Binary { val, .. }) => Some(val.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "{cmd_name} requires compile-time known binary input in eBPF"
                        ))
                    })?;
                let (_, pattern_reg) = self.positional_args[0];
                let pattern = self
                    .get_metadata(pattern_reg)
                    .and_then(|meta| match meta.constant_value.as_ref() {
                        Some(nu_protocol::Value::Binary { val, .. }) => Some(val.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "{cmd_name} requires a compile-time known binary pattern in eBPF"
                        ))
                    })?;
                let matched = if cmd_name == "bytes starts-with" {
                    input.starts_with(&pattern)
                } else {
                    input.ends_with(&pattern)
                };

                self.emit(MirInst::Copy {
                    dst: result_vreg,
                    src: MirValue::Const(if matched { 1 } else { 0 }),
                });
                self.reset_call_result_metadata(src_dst);
                let out_meta = self.get_or_create_metadata(src_dst);
                out_meta.field_type = Some(MirType::Bool);
                out_meta.constant_value = Some(nu_protocol::Value::bool(
                    matched,
                    nu_protocol::Span::unknown(),
                ));
                self.vreg_type_hints.insert(result_vreg, MirType::Bool);
            }

            "bytes index-of" => {
                let input_reg = self
                    .pipeline_input_reg
                    .or(src_dst_had_value.then_some(src_dst));
                let result_vreg = if src_dst_had_value {
                    self.assign_fresh_vreg(src_dst)
                } else {
                    dst_vreg
                };

                let mut return_all = false;
                let mut search_from_end = false;
                for flag in &self.named_flags {
                    match flag.as_str() {
                        "all" => return_all = true,
                        "end" => search_from_end = true,
                        _ => {
                            return Err(CompileError::UnsupportedInstruction(
                                "bytes index-of currently supports only --all and --end as flags in eBPF"
                                    .into(),
                            ));
                        }
                    }
                }
                if !self.named_args.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes index-of does not accept named arguments in eBPF".into(),
                    ));
                }
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes index-of accepts exactly one binary pattern argument in eBPF".into(),
                    ));
                }

                let input = input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .and_then(|meta| match meta.constant_value.as_ref() {
                        Some(nu_protocol::Value::Binary { val, .. }) => Some(val.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "bytes index-of requires compile-time known binary input in eBPF"
                                .into(),
                        )
                    })?;
                let (_, pattern_reg) = self.positional_args[0];
                let pattern = self
                    .get_metadata(pattern_reg)
                    .and_then(|meta| match meta.constant_value.as_ref() {
                        Some(nu_protocol::Value::Binary { val, .. }) => Some(val.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "bytes index-of requires a compile-time known binary pattern in eBPF"
                                .into(),
                        )
                    })?;
                if pattern.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes index-of requires a non-empty binary pattern in eBPF".into(),
                    ));
                }

                if return_all {
                    const MAX_BYTES_INDEX_OF_ALL_MATCHES: usize = 60;
                    let offsets =
                        Self::bytes_index_of_all_offsets(&input, &pattern, search_from_end);
                    if offsets.len() > MAX_BYTES_INDEX_OF_ALL_MATCHES {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "bytes index-of --all result exceeds eBPF numeric list capacity {MAX_BYTES_INDEX_OF_ALL_MATCHES}"
                        )));
                    }

                    let values = offsets
                        .into_iter()
                        .map(|offset| nu_protocol::Value::int(offset, nu_protocol::Span::unknown()))
                        .collect();
                    self.reset_call_result_metadata(src_dst);
                    self.lower_constant_value(
                        src_dst,
                        &nu_protocol::Value::list(values, nu_protocol::Span::unknown()),
                    )?;
                } else {
                    let index = if pattern.len() > input.len() {
                        -1
                    } else {
                        let mut matches = input.windows(pattern.len());
                        let found = if search_from_end {
                            matches.rposition(|candidate| candidate == pattern.as_slice())
                        } else {
                            matches.position(|candidate| candidate == pattern.as_slice())
                        };
                        found.map(|idx| idx as i64).unwrap_or(-1)
                    };

                    self.emit(MirInst::Copy {
                        dst: result_vreg,
                        src: MirValue::Const(index),
                    });
                    self.reset_call_result_metadata(src_dst);
                    let out_meta = self.get_or_create_metadata(src_dst);
                    out_meta.field_type = Some(MirType::I64);
                    out_meta.constant_value =
                        Some(nu_protocol::Value::int(index, nu_protocol::Span::unknown()));
                    self.vreg_type_hints.insert(result_vreg, MirType::I64);
                }
            }

            "bytes reverse" => {
                let input_reg = self
                    .pipeline_input_reg
                    .or(src_dst_had_value.then_some(src_dst));

                if !self.named_flags.is_empty()
                    || !self.named_args.is_empty()
                    || !self.positional_args.is_empty()
                {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes reverse does not accept arguments in eBPF".into(),
                    ));
                }

                let mut output = input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .and_then(|meta| match meta.constant_value.as_ref() {
                        Some(nu_protocol::Value::Binary { val, .. }) => Some(val.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "bytes reverse requires compile-time known binary input in eBPF".into(),
                        )
                    })?;
                output.reverse();

                self.reset_call_result_metadata(src_dst);
                self.lower_constant_value(
                    src_dst,
                    &nu_protocol::Value::binary(output, nu_protocol::Span::unknown()),
                )?;
            }

            "bytes build" => {
                if self.pipeline_input_reg.is_some()
                    || src_dst_had_value
                    || !self.named_flags.is_empty()
                    || !self.named_args.is_empty()
                {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes build does not accept pipeline input, named flags, or named arguments in eBPF"
                            .into(),
                    ));
                }

                let mut output = Vec::new();
                for (_, arg_reg) in &self.positional_args {
                    let value = self
                        .get_metadata(*arg_reg)
                        .and_then(|meta| meta.constant_value.as_ref())
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "bytes build requires compile-time known arguments in eBPF".into(),
                            )
                        })?;
                    match value {
                        nu_protocol::Value::Binary { val, .. } => {
                            output.extend_from_slice(val);
                        }
                        nu_protocol::Value::Int { val, .. } if (0..=255).contains(val) => {
                            output.push(*val as u8);
                        }
                        nu_protocol::Value::Int { .. } => {
                            return Err(CompileError::UnsupportedInstruction(
                                "bytes build integer arguments must be in 0..=255 in eBPF".into(),
                            ));
                        }
                        _ => {
                            return Err(CompileError::UnsupportedInstruction(
                                "bytes build supports only binary and integer byte arguments in eBPF"
                                    .into(),
                            ));
                        }
                    }
                }

                self.reset_call_result_metadata(src_dst);
                self.lower_constant_value(
                    src_dst,
                    &nu_protocol::Value::binary(output, nu_protocol::Span::unknown()),
                )?;
            }

            "bytes at" => {
                let input_reg = self
                    .pipeline_input_reg
                    .or(src_dst_had_value.then_some(src_dst));

                if !self.named_flags.is_empty() || !self.named_args.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes at does not accept named flags or arguments in eBPF".into(),
                    ));
                }
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes at accepts exactly one range argument in eBPF".into(),
                    ));
                }

                let input = input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .and_then(|meta| meta.constant_value.as_ref().cloned())
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "bytes at requires compile-time known binary or list<binary> input in eBPF"
                                .into(),
                        )
                    })?;
                let (_, range_reg) = self.positional_args[0];
                let range = self
                    .get_metadata(range_reg)
                    .and_then(|meta| meta.maybe_open_range)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "bytes at requires a compile-time known range in eBPF".into(),
                        )
                    })?;
                match input {
                    nu_protocol::Value::Binary { val, .. } => {
                        let output = Self::bytes_at_output(&val, range);
                        self.reset_call_result_metadata(src_dst);
                        self.lower_constant_value(
                            src_dst,
                            &nu_protocol::Value::binary(output, nu_protocol::Span::unknown()),
                        )?;
                    }
                    nu_protocol::Value::List { vals, .. } => {
                        if vals.is_empty() && !self.current_call_result_metadata_only {
                            return Err(CompileError::UnsupportedInstruction(
                                "bytes at requires a non-empty list<binary> result in eBPF".into(),
                            ));
                        }
                        let mut expected_len = None;
                        let mut has_empty_output = false;
                        let mut has_unequal_output_len = false;
                        let mut values = Vec::with_capacity(vals.len());
                        for (index, item) in vals.iter().enumerate() {
                            let nu_protocol::Value::Binary { val, .. } = item else {
                                return Err(CompileError::UnsupportedInstruction(format!(
                                    "bytes at requires binary list items in eBPF; item {index} has type {}",
                                    item.get_type()
                                )));
                            };
                            let output = Self::bytes_at_output(val, range);
                            if output.is_empty() {
                                has_empty_output = true;
                            }
                            if let Some(expected_len) = expected_len {
                                if output.len() != expected_len {
                                    has_unequal_output_len = true;
                                }
                            } else {
                                expected_len = Some(output.len());
                            }
                            values.push(nu_protocol::Value::binary(
                                output,
                                nu_protocol::Span::unknown(),
                            ));
                        }
                        if has_empty_output && !self.current_call_result_metadata_only {
                            return Err(CompileError::UnsupportedInstruction(
                                "bytes at requires non-empty binary list results in eBPF".into(),
                            ));
                        }
                        if has_unequal_output_len && !self.current_call_result_metadata_only {
                            return Err(CompileError::UnsupportedInstruction(
                                "bytes at requires equal-length binary list results in eBPF".into(),
                            ));
                        }

                        self.reset_call_result_metadata(src_dst);
                        let value = nu_protocol::Value::list(values, nu_protocol::Span::unknown());
                        if vals.is_empty() || has_empty_output || has_unequal_output_len {
                            self.lower_compile_time_only_constant_value(src_dst, &value);
                        } else {
                            self.lower_constant_value(src_dst, &value)?;
                        }
                    }
                    other => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "bytes at requires binary or list<binary> input in eBPF, got {}",
                            other.get_type()
                        )));
                    }
                }
            }

            "bytes add" => {
                let input_reg = self
                    .pipeline_input_reg
                    .or(src_dst_had_value.then_some(src_dst));

                let mut from_end = false;
                for flag in &self.named_flags {
                    match flag.as_str() {
                        "end" => from_end = true,
                        _ => {
                            return Err(CompileError::UnsupportedInstruction(
                                "bytes add currently supports only --end as a flag in eBPF".into(),
                            ));
                        }
                    }
                }
                for key in self.named_args.keys() {
                    if key != "index" {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "bytes add does not support named argument --{key} in eBPF"
                        )));
                    }
                }
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes add accepts exactly one binary data argument in eBPF".into(),
                    ));
                }

                let input = input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .and_then(|meta| meta.constant_value.as_ref().cloned())
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "bytes add requires compile-time known binary or list<binary> input in eBPF"
                                .into(),
                        )
                    })?;
                let (_, data_reg) = self.positional_args[0];
                let data = self
                    .get_metadata(data_reg)
                    .and_then(|meta| match meta.constant_value.as_ref() {
                        Some(nu_protocol::Value::Binary { val, .. }) => Some(val.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "bytes add requires compile-time known binary data in eBPF".into(),
                        )
                    })?;

                let index = if let Some((_, index_reg)) = self.named_args.get("index").copied() {
                    self.get_metadata(index_reg)
                        .and_then(|meta| {
                            meta.literal_int
                                .or_else(|| match meta.constant_value.as_ref() {
                                    Some(nu_protocol::Value::Int { val, .. }) => Some(*val),
                                    _ => None,
                                })
                        })
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "bytes add --index requires a compile-time known integer in eBPF"
                                    .into(),
                            )
                        })?
                } else {
                    0
                };
                if index < 0 {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes add --index requires a non-negative integer in eBPF".into(),
                    ));
                }

                match input {
                    nu_protocol::Value::Binary { val, .. } => {
                        let output = Self::bytes_add_output(&val, &data, index, from_end);
                        self.reset_call_result_metadata(src_dst);
                        self.lower_constant_value(
                            src_dst,
                            &nu_protocol::Value::binary(output, nu_protocol::Span::unknown()),
                        )?;
                    }
                    nu_protocol::Value::List { vals, .. } => {
                        if vals.is_empty() && !self.current_call_result_metadata_only {
                            return Err(CompileError::UnsupportedInstruction(
                                "bytes add requires a non-empty list<binary> result in eBPF".into(),
                            ));
                        }
                        let mut expected_len = None;
                        let mut has_empty_output = false;
                        let mut has_unequal_output_len = false;
                        let mut values = Vec::with_capacity(vals.len());
                        for (item_index, item) in vals.iter().enumerate() {
                            let nu_protocol::Value::Binary { val, .. } = item else {
                                return Err(CompileError::UnsupportedInstruction(format!(
                                    "bytes add requires binary list items in eBPF; item {item_index} has type {}",
                                    item.get_type()
                                )));
                            };
                            let output = Self::bytes_add_output(val, &data, index, from_end);
                            if output.is_empty() {
                                has_empty_output = true;
                            }
                            if let Some(expected_len) = expected_len {
                                if output.len() != expected_len {
                                    has_unequal_output_len = true;
                                }
                            } else {
                                expected_len = Some(output.len());
                            }
                            values.push(nu_protocol::Value::binary(
                                output,
                                nu_protocol::Span::unknown(),
                            ));
                        }
                        if has_empty_output && !self.current_call_result_metadata_only {
                            return Err(CompileError::UnsupportedInstruction(
                                "bytes add requires non-empty binary list results in eBPF".into(),
                            ));
                        }
                        if has_unequal_output_len && !self.current_call_result_metadata_only {
                            return Err(CompileError::UnsupportedInstruction(
                                "bytes add requires equal-length binary list results in eBPF"
                                    .into(),
                            ));
                        }

                        self.reset_call_result_metadata(src_dst);
                        let value = nu_protocol::Value::list(values, nu_protocol::Span::unknown());
                        if vals.is_empty() || has_empty_output || has_unequal_output_len {
                            self.lower_compile_time_only_constant_value(src_dst, &value);
                        } else {
                            self.lower_constant_value(src_dst, &value)?;
                        }
                    }
                    other => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "bytes add requires binary or list<binary> input in eBPF, got {}",
                            other.get_type()
                        )));
                    }
                }
            }

            "bytes remove" | "bytes replace" => {
                let input_reg = self
                    .pipeline_input_reg
                    .or(src_dst_had_value.then_some(src_dst));

                let mut apply_all = false;
                let mut from_end = false;
                for flag in &self.named_flags {
                    match flag.as_str() {
                        "all" => apply_all = true,
                        "end" if cmd_name == "bytes remove" => from_end = true,
                        "end" => {
                            return Err(CompileError::UnsupportedInstruction(
                                "bytes replace does not support --end in eBPF".into(),
                            ));
                        }
                        _ => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "{cmd_name} currently supports only --all{} as flags in eBPF",
                                if cmd_name == "bytes remove" {
                                    " and --end"
                                } else {
                                    ""
                                }
                            )));
                        }
                    }
                }
                if !self.named_args.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} does not accept named arguments in eBPF"
                    )));
                }

                let expected_args = if cmd_name == "bytes remove" { 1 } else { 2 };
                if self.positional_args.len() != expected_args {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} accepts exactly {expected_args} binary positional argument{} in eBPF",
                        if expected_args == 1 { "" } else { "s" }
                    )));
                }

                let input = input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .and_then(|meta| match meta.constant_value.as_ref() {
                        Some(nu_protocol::Value::Binary { val, .. }) => Some(val.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "{cmd_name} requires compile-time known binary input in eBPF"
                        ))
                    })?;
                let (_, pattern_reg) = self.positional_args[0];
                let pattern = self
                    .get_metadata(pattern_reg)
                    .and_then(|meta| match meta.constant_value.as_ref() {
                        Some(nu_protocol::Value::Binary { val, .. }) => Some(val.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "{cmd_name} requires a compile-time known binary pattern in eBPF"
                        ))
                    })?;
                if pattern.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} requires a non-empty binary pattern in eBPF"
                    )));
                }

                let replacement = if cmd_name == "bytes replace" {
                    let (_, replacement_reg) = self.positional_args[1];
                    self.get_metadata(replacement_reg)
                        .and_then(|meta| match meta.constant_value.as_ref() {
                            Some(nu_protocol::Value::Binary { val, .. }) => Some(val.clone()),
                            _ => None,
                        })
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "bytes replace requires compile-time known binary replacement in eBPF"
                                    .into(),
                            )
                        })?
                } else {
                    Vec::new()
                };

                let mut output = Vec::new();
                if apply_all {
                    let mut index = 0;
                    while index < input.len() {
                        if input[index..].starts_with(&pattern) {
                            output.extend_from_slice(&replacement);
                            index += pattern.len();
                        } else {
                            output.push(input[index]);
                            index += 1;
                        }
                    }
                } else {
                    let found = if pattern.len() > input.len() {
                        None
                    } else if from_end {
                        input
                            .windows(pattern.len())
                            .rposition(|candidate| candidate == pattern.as_slice())
                    } else {
                        input
                            .windows(pattern.len())
                            .position(|candidate| candidate == pattern.as_slice())
                    };

                    if let Some(found) = found {
                        output.extend_from_slice(&input[..found]);
                        output.extend_from_slice(&replacement);
                        output.extend_from_slice(&input[found + pattern.len()..]);
                    } else {
                        output.extend_from_slice(&input);
                    }
                }

                self.reset_call_result_metadata(src_dst);
                self.lower_constant_value(
                    src_dst,
                    &nu_protocol::Value::binary(output, nu_protocol::Span::unknown()),
                )?;
            }

            "bytes collect" => {
                let input_reg = self
                    .pipeline_input_reg
                    .or(src_dst_had_value.then_some(src_dst));

                if !self.named_flags.is_empty() || !self.named_args.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes collect does not accept named flags or arguments in eBPF".into(),
                    ));
                }
                if self.positional_args.len() > 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes collect accepts at most one binary separator argument in eBPF"
                            .into(),
                    ));
                }

                let items = input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .and_then(|meta| match meta.constant_value.as_ref() {
                        Some(nu_protocol::Value::List { vals, .. }) => Some(vals.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "bytes collect requires compile-time known list<binary> input in eBPF"
                                .into(),
                        )
                    })?;
                let separator = if let Some((_, separator_reg)) =
                    self.positional_args.first().copied()
                {
                    self.get_metadata(separator_reg)
                        .and_then(|meta| match meta.constant_value.as_ref() {
                            Some(nu_protocol::Value::Binary { val, .. }) => Some(val.clone()),
                            _ => None,
                        })
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "bytes collect requires a compile-time known binary separator in eBPF"
                                    .into(),
                            )
                        })?
                } else {
                    Vec::new()
                };

                let mut output = Vec::new();
                for (index, item) in items.iter().enumerate() {
                    let nu_protocol::Value::Binary { val, .. } = item else {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "bytes collect requires binary list items in eBPF; item {index} has type {}",
                            item.get_type()
                        )));
                    };
                    if index > 0 {
                        output.extend_from_slice(&separator);
                    }
                    output.extend_from_slice(val);
                }
                self.reset_call_result_metadata(src_dst);
                self.lower_constant_value(
                    src_dst,
                    &nu_protocol::Value::binary(output, nu_protocol::Span::unknown()),
                )?;
            }

            "bytes split" => {
                let input_reg = self
                    .pipeline_input_reg
                    .or(src_dst_had_value.then_some(src_dst));

                if !self.named_flags.is_empty() || !self.named_args.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes split does not accept named flags or arguments in eBPF".into(),
                    ));
                }
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes split accepts exactly one binary or string separator argument in eBPF"
                            .into(),
                    ));
                }

                let input = input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .and_then(|meta| match meta.constant_value.as_ref() {
                        Some(nu_protocol::Value::Binary { val, .. }) => Some(val.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "bytes split requires compile-time known binary input in eBPF".into(),
                        )
                    })?;
                let (_, separator_reg) = self.positional_args[0];
                let separator = self
                    .get_metadata(separator_reg)
                    .and_then(|meta| match meta.constant_value.as_ref() {
                        Some(nu_protocol::Value::Binary { val, .. }) => Some(val.clone()),
                        Some(nu_protocol::Value::String { val, .. })
                        | Some(nu_protocol::Value::Glob { val, .. }) => {
                            Some(val.as_bytes().to_vec())
                        }
                        _ => None,
                    })
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "bytes split requires a compile-time known binary or string separator in eBPF"
                                .into(),
                        )
                    })?;
                if separator.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes split requires a non-empty separator in eBPF".into(),
                    ));
                }

                let mut parts = Vec::new();
                let mut offset = 0usize;
                loop {
                    let found = if separator.len() > input[offset..].len() {
                        None
                    } else {
                        input[offset..]
                            .windows(separator.len())
                            .position(|candidate| candidate == separator.as_slice())
                    };
                    if let Some(relative_index) = found {
                        let end = offset + relative_index;
                        parts.push(input[offset..end].to_vec());
                        offset = end + separator.len();
                    } else {
                        parts.push(input[offset..].to_vec());
                        break;
                    }
                }

                let Some(first_part_len) = parts.first().map(Vec::len) else {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes split requires at least one binary part in eBPF".into(),
                    ));
                };
                let has_empty_part = first_part_len == 0 || parts.iter().any(Vec::is_empty);
                let has_unequal_part_len = parts.iter().any(|part| part.len() != first_part_len);
                if has_empty_part && !self.current_call_result_metadata_only {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes split requires non-empty binary parts in eBPF".into(),
                    ));
                }
                if has_unequal_part_len && !self.current_call_result_metadata_only {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes split requires equal-length binary parts in eBPF".into(),
                    ));
                }

                let values = parts
                    .into_iter()
                    .map(|part| nu_protocol::Value::binary(part, nu_protocol::Span::unknown()))
                    .collect();
                self.reset_call_result_metadata(src_dst);
                let value = nu_protocol::Value::list(values, nu_protocol::Span::unknown());
                if has_empty_part || has_unequal_part_len {
                    self.lower_compile_time_only_constant_value(src_dst, &value);
                } else {
                    self.lower_constant_value(src_dst, &value)?;
                }
            }

            "str length" => {
                self.lower_string_length(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "str starts-with" => {
                self.lower_string_starts_with(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "str ends-with" => {
                self.lower_string_ends_with(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "str contains" => {
                self.lower_string_contains(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "str distance" => {
                self.lower_string_distance(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "str join" => {
                self.lower_string_join(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "split row" => {
                self.lower_split_row(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "split chars" => {
                self.lower_split_chars(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "split words" => {
                self.lower_split_words(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "str stats" => {
                self.lower_string_stats(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "str expand" => {
                self.lower_string_expand(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "str index-of" => {
                self.lower_string_index_of(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "str substring" => {
                self.lower_string_substring(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "str replace" => {
                self.lower_string_replace(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "str trim" => {
                self.lower_string_trim(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "char" => {
                self.lower_char(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "fill" => {
                self.lower_fill(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "str downcase"
            | "str upcase"
            | "str reverse"
            | "str capitalize"
            | "str camel-case"
            | "str kebab-case"
            | "str pascal-case"
            | "str screaming-snake-case"
            | "str snake-case"
            | "str title-case" => {
                self.lower_known_string_transform(&cmd_name, src_dst, dst_vreg, src_dst_had_value)?;
            }

            "math max" | "math min" | "math product" | "math sum" => {
                self.lower_stack_list_math_reduce(&cmd_name, src_dst, dst_vreg, src_dst_had_value)?;
            }

            "math avg" => {
                self.lower_compile_time_math_avg(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "math stddev" | "math variance" => {
                self.lower_compile_time_math_variance_stddev(
                    &cmd_name,
                    src_dst,
                    src_dst_had_value,
                )?;
            }

            "math arccos" | "math arccosh" | "math arcsin" | "math arcsinh" | "math arctan"
            | "math arctanh" | "math cos" | "math cosh" | "math exp" | "math ln" | "math sin"
            | "math sinh" | "math sqrt" | "math tan" | "math tanh" => {
                self.lower_compile_time_math_float_unary(&cmd_name, src_dst, src_dst_had_value)?;
            }

            "math log" => {
                self.lower_compile_time_math_log(src_dst, src_dst_had_value)?;
            }

            "math ceil" | "math floor" | "math round" => {
                self.lower_integer_identity_math(&cmd_name, src_dst, dst_vreg, src_dst_had_value)?;
            }

            "bits and" | "bits or" | "bits xor" => {
                self.lower_bits_binary(&cmd_name, src_dst, dst_vreg, src_dst_had_value)?;
            }

            "bits not" => {
                self.lower_bits_not(&cmd_name, src_dst, dst_vreg, src_dst_had_value)?;
            }

            "bits shl" | "bits shr" => {
                self.lower_bits_shift(&cmd_name, src_dst, dst_vreg, src_dst_had_value)?;
            }

            "bits rol" | "bits ror" => {
                self.lower_bits_rotate(&cmd_name, src_dst, dst_vreg, src_dst_had_value)?;
            }

            "math median" => {
                self.lower_math_median(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "math mode" => {
                self.lower_math_mode(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "math abs" => {
                self.lower_math_abs(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "select" | "reject" => {
                self.lower_metadata_record_select_or_reject(
                    &cmd_name,
                    src_dst,
                    dst_vreg,
                    src_dst_had_value,
                )?;
            }

            "rename" => {
                self.lower_metadata_record_rename(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "merge" => {
                self.lower_metadata_record_merge(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "columns" => {
                self.lower_metadata_record_columns(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "transpose" => {
                self.lower_metadata_record_transpose(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "values" => {
                self.lower_metadata_record_values(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "insert" | "update" | "upsert" => {
                self.lower_metadata_record_insert_update_or_upsert(
                    &cmd_name,
                    src_dst,
                    dst_vreg,
                    src_dst_had_value,
                )?;
            }

            "default" => {
                self.lower_default(src_dst, dst_vreg, src_dst_had_value)?;
            }

            "get" => {
                if !self.named_flags.is_empty() || !self.named_args.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(
                        "get does not accept named flags or arguments in eBPF".into(),
                    ));
                }
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        "get accepts exactly one positional argument in eBPF".into(),
                    ));
                }

                let input_reg = self
                    .pipeline_input_reg
                    .or(src_dst_had_value.then_some(src_dst));
                let input_meta = input_reg.and_then(|reg| self.get_metadata(reg).cloned());
                if input_meta
                    .as_ref()
                    .is_some_and(|meta| !meta.record_fields.is_empty())
                {
                    self.lower_metadata_record_get(src_dst, dst_vreg, src_dst_had_value)?;
                } else {
                    let (_, arg_reg) = self.positional_args[0];
                    if let Some(path) = self.field_path_arg(arg_reg, "get")? {
                        if let Some(meta) = input_meta.as_ref()
                            && let Some(value) = meta.constant_value.as_ref()
                            && matches!(value, nu_protocol::Value::Record { .. })
                        {
                            let projected = Self::constant_follow_cell_path(value, &path)
                                .ok_or_else(|| {
                                    CompileError::UnsupportedInstruction(format!(
                                        "get field path '{}' was not found in compile-time known record in eBPF",
                                        Self::typed_value_path_desc(&path.members)
                                    ))
                                })?;
                            self.lower_compile_time_list_transform_result(src_dst, &projected)?;
                            return Ok(());
                        }
                        let input_reg = input_reg.ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "get FIELD requires record, context, or typed pointer input in eBPF"
                                    .into(),
                            )
                        })?;
                        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                        self.lower_field_path_get(
                            src_dst,
                            dst_vreg,
                            src_dst_had_value,
                            input_reg,
                            input_vreg,
                            input_meta,
                            path,
                        )?;
                        return Ok(());
                    }

                    let mut input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
                    let result_vreg = if src_dst_had_value {
                        self.assign_fresh_vreg(src_dst)
                    } else {
                        dst_vreg
                    };
                    let (idx_vreg, idx_reg) =
                        self.positional_args.first().copied().ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "get requires a numeric positional index argument".into(),
                            )
                        })?;

                    let idx = self
                        .get_metadata(idx_reg)
                        .and_then(|meta| {
                            meta.literal_int.or_else(|| {
                                meta.cell_path.as_ref().and_then(|path| {
                                    match path.members.as_slice() {
                                        [PathMember::Int { val, .. }] => Some(*val as i64),
                                        _ => None,
                                    }
                                })
                            })
                        })
                        .map(MirValue::Const)
                        .unwrap_or(MirValue::VReg(idx_vreg));
                    let mut handled_list_get = false;
                    if let Some(meta) = input_meta {
                        if let Some(values) = input_reg.and_then(|reg| {
                            self.compile_time_only_list_builder_values(reg, input_vreg)
                        }) {
                            let MirValue::Const(raw_idx) = idx else {
                                return Err(CompileError::UnsupportedInstruction(
                                    "get index must be compile-time constant for compile-time known fixed lists in eBPF"
                                        .into(),
                                ));
                            };
                            if raw_idx < 0 {
                                return Err(CompileError::UnsupportedInstruction(
                                    "get index must be non-negative for compile-time known fixed lists in eBPF"
                                        .into(),
                                ));
                            }
                            let idx_usize = usize::try_from(raw_idx).map_err(|_| {
                                CompileError::UnsupportedInstruction(
                                    "get index is too large for compile-time known fixed-list lowering"
                                        .into(),
                                )
                            })?;
                            let projected = values.get(idx_usize).cloned().ok_or_else(|| {
                                CompileError::UnsupportedInstruction(format!(
                                    "get index {raw_idx} is out of bounds for compile-time known fixed list with length {} in eBPF",
                                    values.len()
                                ))
                            })?;

                            self.lower_compile_time_list_transform_result(src_dst, &projected)?;
                            handled_list_get = true;
                        } else if let Some((_slot, max_len)) = meta.list_buffer {
                            if let MirValue::Const(raw_idx) = &idx {
                                let raw_idx = *raw_idx;
                                if raw_idx < 0 {
                                    return Err(CompileError::UnsupportedInstruction(
                                    "get index must be non-negative for stack-backed numeric lists in eBPF"
                                        .into(),
                                ));
                                }
                                let idx_usize = usize::try_from(raw_idx).map_err(|_| {
                                    CompileError::UnsupportedInstruction(
                                    "get index is too large for stack-backed numeric list lowering"
                                        .into(),
                                )
                                })?;
                                let known_len = if meta.mutable_global_runtime
                                    && meta.constant_value.is_none()
                                {
                                    None
                                } else {
                                    Self::numeric_list_known_len(&meta)
                                };
                                if let Some(known_len) = known_len {
                                    if idx_usize >= known_len {
                                        return Err(CompileError::UnsupportedInstruction(format!(
                                            "get index {raw_idx} is out of bounds for stack-backed numeric list with known length {known_len} in eBPF"
                                        )));
                                    }
                                } else if idx_usize >= max_len {
                                    return Err(CompileError::UnsupportedInstruction(format!(
                                        "get index {raw_idx} is out of bounds for stack-backed numeric list capacity {max_len} in eBPF"
                                    )));
                                }
                            }

                            self.emit(MirInst::ListGet {
                                dst: result_vreg,
                                list: input_vreg,
                                idx: idx.clone(),
                            });

                            self.reset_call_result_metadata(src_dst);
                            let out_meta = self.get_or_create_metadata(src_dst);
                            out_meta.field_type = Some(MirType::I64);
                            out_meta.constant_value = match (&meta.constant_value, &idx) {
                                (
                                    Some(nu_protocol::Value::List { vals, .. }),
                                    MirValue::Const(raw_idx),
                                ) if *raw_idx >= 0 => vals.get(*raw_idx as usize).cloned(),
                                _ => None,
                            };
                            handled_list_get = true;
                        }
                    }

                    if handled_list_get {
                        // Metadata is already updated for stack-backed list access.
                    } else {
                        let input_reg = input_reg.ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "get requires a list value or typed kernel/user pointer input"
                                    .into(),
                            )
                        })?;
                        let mut base_runtime_ty = self
                            .typed_value_runtime_type(input_reg, input_vreg)
                            .ok_or_else(|| {
                                CompileError::UnsupportedInstruction(
                                    "get requires a list value or typed kernel/user pointer input"
                                        .into(),
                                )
                            })?;
                        if !matches!(base_runtime_ty, MirType::Ptr { .. })
                            && Self::aggregate_call_value_type(&base_runtime_ty).is_some()
                        {
                            input_vreg =
                                self.materialized_metadata_aggregate_vreg(input_reg, input_vreg)?;
                            base_runtime_ty = self
                                .typed_value_runtime_type(input_reg, input_vreg)
                                .ok_or_else(|| {
                                    CompileError::UnsupportedInstruction(
                                    "get requires a list value or typed kernel/user pointer input"
                                        .into(),
                                )
                                })?;
                        }

                        match &base_runtime_ty {
                            MirType::Ptr { .. } => {
                                let root_ctx_field = self
                                    .get_metadata(input_reg)
                                    .and_then(|meta| meta.root_ctx_field.clone());
                                let projected_constant = match (self.get_metadata(input_reg), &idx)
                                {
                                    (
                                        Some(RegMetadata {
                                            constant_value:
                                                Some(nu_protocol::Value::List { vals, .. }),
                                            ..
                                        }),
                                        MirValue::Const(raw_idx),
                                    ) if *raw_idx >= 0 => vals.get(*raw_idx as usize).cloned(),
                                    _ => None,
                                };
                                let projected_semantics =
                                    self.get_metadata(input_reg).and_then(|meta| {
                                        match &meta.annotated_semantics {
                                            Some(AnnotatedValueSemantics::FixedArray {
                                                elem,
                                                ..
                                            }) => Some((**elem).clone()),
                                            _ => None,
                                        }
                                    });
                                let projected_string_bytes = match projected_constant.as_ref() {
                                    Some(nu_protocol::Value::String { val, .. })
                                    | Some(nu_protocol::Value::Glob { val, .. })
                                        if matches!(
                                            projected_semantics,
                                            Some(AnnotatedValueSemantics::String { .. })
                                        ) =>
                                    {
                                        Some(val.as_bytes().to_vec())
                                    }
                                    _ => None,
                                };
                                if let Some(bytes) = projected_string_bytes {
                                    self.reset_call_result_metadata(src_dst);
                                    self.lower_string_like_literal(src_dst, result_vreg, &bytes)?;
                                    self.set_reg_constant_value(src_dst, projected_constant);
                                } else {
                                    self.lower_dynamic_typed_numeric_get(
                                        src_dst,
                                        input_vreg,
                                        &base_runtime_ty,
                                        idx,
                                        root_ctx_field.as_ref(),
                                    )?;
                                    let out_meta = self.get_or_create_metadata(src_dst);
                                    out_meta.constant_value = projected_constant;
                                    out_meta.annotated_semantics = projected_semantics;
                                }
                            }
                            _ => {
                                return Err(CompileError::UnsupportedInstruction(format!(
                                    "get requires a list value or typed pointer input, got {:?}",
                                    base_runtime_ty
                                )));
                            }
                        }
                    }
                }
            }

            "first" | "last" => {
                if !self.named_flags.is_empty() || !self.named_args.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} does not accept named flags or arguments in eBPF"
                    )));
                }

                if !self.positional_args.is_empty() {
                    if cmd_name == "first" {
                        self.lower_stack_list_take_skip_or_drop(
                            &cmd_name,
                            src_dst,
                            dst_vreg,
                            src_dst_had_value,
                        )?;
                    } else {
                        self.lower_stack_list_last_count(src_dst, dst_vreg, src_dst_had_value)?;
                    }
                    self.clear_call_state();
                    return Ok(());
                }

                self.lower_stack_list_first_or_last_scalar(
                    &cmd_name,
                    src_dst,
                    dst_vreg,
                    src_dst_had_value,
                )?;
            }

            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Command '{}' not supported in eBPF",
                    cmd_name
                )));
            }
        }

        self.clear_call_state();
        Ok(())
    }

    fn validate_declared_map_key_type(
        &self,
        map_ref: &MapRef,
        key_ty: &MirType,
        context: &str,
    ) -> Result<(), CompileError> {
        if map_ref.kind.is_keyless_map() || map_ref.kind.is_local_storage() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} --key-type is not supported for keyless or object-keyed map kind {}",
                map_ref.kind
            )));
        }
        if map_ref.kind.is_array_index_map() && key_ty != &MirType::U32 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} --key-type for {} maps must be u32",
                map_ref.kind
            )));
        }
        if matches!(key_ty, MirType::Unknown) || key_ty.size() == 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} --key-type must describe a fixed-size map key"
            )));
        }
        Ok(())
    }

    fn map_key_vreg_for_named_schema(
        &mut self,
        map_ref: &MapRef,
        key_vreg: VReg,
        key_reg: Option<RegId>,
        context: &str,
    ) -> Result<VReg, CompileError> {
        let key_context = format!("{context} key");
        self.reject_context_pointer_payload(key_reg, &key_context)?;

        let mut observed_ty = None;
        let mut observed_fixed_aggregate = None;
        if let Some(meta) = key_reg.and_then(|reg| self.get_metadata(reg)) {
            let fixed_array = Self::metadata_fixed_array_layout(meta)?;
            let record = Self::metadata_record_layout(meta);
            observed_fixed_aggregate = fixed_array.clone().or_else(|| record.clone());
            observed_ty = fixed_array
                .or_else(|| meta.field_type.clone())
                .or_else(|| record.clone());
        }
        let observed_ty = observed_ty.or_else(|| self.vreg_type_hints.get(&key_vreg).cloned());

        let Some(key_ty) = self.named_map_key_type(map_ref).cloned() else {
            if observed_fixed_aggregate.is_some() {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} aggregate key for '{}' requires a prior map-define --key-type declaration",
                    map_ref.name
                )));
            }
            return Ok(key_vreg);
        };
        self.validate_declared_map_key_type(map_ref, &key_ty, context)?;

        match key_ty {
            MirType::Array { .. } | MirType::Struct { .. } => match observed_ty.as_ref() {
                Some(MirType::Ptr {
                    pointee,
                    address_space: AddressSpace::Stack | AddressSpace::Map,
                }) if pointee.as_ref() == &key_ty => Ok(key_vreg),
                Some(observed) if self.stored_generic_map_value_type(observed) == key_ty => {
                    let Some(key_reg) = key_reg else {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "{context} key for '{}' matches the declared aggregate schema but is not materializable",
                            map_ref.name
                        )));
                    };
                    let ptr_vreg = self.materialized_metadata_aggregate_vreg(key_reg, key_vreg)?;
                    self.vreg_type_hints.insert(
                        ptr_vreg,
                        MirType::Ptr {
                            pointee: Box::new(key_ty),
                            address_space: AddressSpace::Stack,
                        },
                    );
                    Ok(ptr_vreg)
                }
                Some(observed) => Err(CompileError::UnsupportedInstruction(format!(
                    "{context} key for '{}' has type {:?}, expected declared key type {:?}",
                    map_ref.name, observed, key_ty
                ))),
                None => Err(CompileError::UnsupportedInstruction(format!(
                    "{context} key for '{}' requires a typed aggregate matching --key-type",
                    map_ref.name
                ))),
            },
            scalar_ty => match observed_ty.as_ref() {
                Some(MirType::Ptr { pointee, .. }) if pointee.as_ref() == &scalar_ty => {
                    Ok(key_vreg)
                }
                Some(MirType::Array { .. } | MirType::Struct { .. })
                | Some(MirType::Ptr { .. }) => Err(CompileError::UnsupportedInstruction(format!(
                    "{context} key for '{}' is aggregate/pointer typed, expected declared scalar key type {:?}",
                    map_ref.name, scalar_ty
                ))),
                _ => {
                    let slot = self.func.alloc_stack_slot(
                        align_to_eight(scalar_ty.size().max(1)),
                        8,
                        StackSlotKind::Local,
                    );
                    self.record_stack_slot_type(slot, scalar_ty.clone());
                    self.emit(MirInst::StoreSlot {
                        slot,
                        offset: 0,
                        val: MirValue::VReg(key_vreg),
                        ty: scalar_ty.clone(),
                    });
                    let key_ptr_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::Copy {
                        dst: key_ptr_vreg,
                        src: MirValue::StackSlot(slot),
                    });
                    self.vreg_type_hints.insert(
                        key_ptr_vreg,
                        MirType::Ptr {
                            pointee: Box::new(scalar_ty),
                            address_space: AddressSpace::Stack,
                        },
                    );
                    Ok(key_ptr_vreg)
                }
            },
        }
    }

    fn map_in_map_inner_template(
        &self,
        map_ref: &MapRef,
        context: &str,
    ) -> Result<MapRef, CompileError> {
        self.map_inner_templates
            .get(map_ref)
            .cloned()
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{context} map '{}' uses {} and requires a prior map-define --inner-map declaration",
                    map_ref.name, map_ref.kind
                ))
            })
    }

    fn record_map_value_lookup_result(
        &mut self,
        src_dst: RegId,
        lookup_vreg: VReg,
        result_vreg: VReg,
        map_ref: &MapRef,
        key_vreg: VReg,
        stored_ty: Option<MirType>,
    ) {
        let runtime_ty = MirType::Ptr {
            pointee: Box::new(stored_ty.clone().unwrap_or(MirType::U8)),
            address_space: AddressSpace::Map,
        };
        self.vreg_type_hints.insert(lookup_vreg, runtime_ty.clone());
        self.vreg_type_hints.insert(result_vreg, runtime_ty);

        self.reset_call_result_metadata(src_dst);
        if let Some(value_ty @ (MirType::Array { .. } | MirType::Struct { .. })) = stored_ty {
            let semantics = self.named_map_value_semantics(map_ref).cloned();
            let key_ty = if map_ref.kind.is_array_index_map() {
                MirType::U32
            } else {
                self.named_map_key_type(map_ref)
                    .cloned()
                    .or_else(|| {
                        self.vreg_type_hints
                            .get(&key_vreg)
                            .map(|ty| self.stored_generic_map_value_type(ty))
                    })
                    .unwrap_or(MirType::Unknown)
            };
            let meta = self.get_or_create_metadata(src_dst);
            meta.field_type = Some(MirType::Ptr {
                pointee: Box::new(value_ty.clone()),
                address_space: AddressSpace::Map,
            });
            meta.map_value_origin = Some(MapValueOrigin {
                map_ref: map_ref.clone(),
                key_ty,
                value_ty,
            });
            if let Some(semantics) = semantics {
                meta.annotated_semantics = Some(semantics);
            }
        }
    }

    fn record_named_map_value_schema_from_reg(
        &mut self,
        map_ref: &MapRef,
        value_reg: Option<RegId>,
        context: &str,
    ) -> Result<(), CompileError> {
        self.reject_context_pointer_payload(value_reg, context)?;
        let value_ty = if let Some(meta) = value_reg.and_then(|reg| self.get_metadata(reg)) {
            Self::metadata_fixed_array_layout(meta)?
                .or_else(|| meta.field_type.clone())
                .or_else(|| Self::metadata_record_layout(meta))
        } else {
            None
        };
        let value_constant = value_reg
            .and_then(|reg| self.get_metadata(reg))
            .and_then(|m| m.constant_value.clone());
        let value_semantics = value_reg
            .map(|reg| self.tracked_value_semantics(reg, value_constant.as_ref()))
            .transpose()?
            .flatten();
        if let Some(value_ty) = value_ty {
            let stored_value_ty = self.stored_generic_map_value_type(&value_ty);
            let explicit_schema = self.declared_map_value_types.contains(map_ref);
            if (self.externally_seeded_map_value_types.contains(map_ref) || explicit_schema)
                && let Some(existing) = self.named_map_value_type(map_ref)
                && existing != &stored_value_ty
            {
                let schema_source = if explicit_schema {
                    "declared"
                } else {
                    "pinned"
                };
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} value type for '{}' conflicts with {schema_source} map schema",
                    map_ref.name,
                )));
            }
            self.register_named_map_value_type(map_ref, &stored_value_ty);
        }
        if let Some(value_semantics) = value_semantics {
            let explicit_schema = self.declared_map_value_types.contains(map_ref);
            if (self.externally_seeded_map_value_semantics.contains(map_ref) || explicit_schema)
                && let Some(existing) = self.named_map_value_semantics(map_ref)
                && existing != &value_semantics
            {
                let schema_source = if explicit_schema {
                    "declared"
                } else {
                    "pinned"
                };
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{context} value semantics for '{}' conflicts with {schema_source} map schema",
                    map_ref.name,
                )));
            }
            self.register_named_map_value_semantics(map_ref, &value_semantics);
        }
        Ok(())
    }

    fn lower_socket_map_put(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        map_ref: MapRef,
        key_vreg: VReg,
        key_reg: RegId,
        flags: u64,
    ) -> Result<(), CompileError> {
        let helper = BpfHelper::socket_map_update_for_map_kind(map_ref.kind).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "map-put does not support socket map kind {}",
                map_ref.kind
            ))
        })?;
        let probe_ctx = self.probe_ctx.ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "map-put --kind sockmap/sockhash requires a sock_ops program context".into(),
            )
        })?;
        if let Some(message) = probe_ctx.helper_call_error(helper) {
            return Err(CompileError::UnsupportedInstruction(message));
        }
        let ctx_vreg = self.pipeline_input.ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "map-put --kind sockmap/sockhash requires a sock_ops context from pipeline input"
                    .into(),
            )
        })?;
        let ctx_reg = self.pipeline_input_reg;
        let ctx_vreg = if ctx_reg.is_some_and(|reg| self.is_context_reg(reg)) {
            self.materialize_context_pointer_arg()
        } else {
            ctx_vreg
        };

        let (key_ptr_vreg, _key_ty) =
            self.materialize_map_value_probe_pointer(Some(key_reg), key_vreg, "map-put key")?;
        let map_key_ty = if matches!(map_ref.kind, MapKind::SockMap) {
            MirType::U32
        } else {
            // Sockhash key layout is inferred from the helper key pointer.
            // Seeding it here can conflict with path-specific pointer metadata.
            MirType::Unknown
        };
        let map_vreg = self.emit_typed_map_fd_load(map_ref.name, map_ref.kind);
        self.vreg_type_hints.insert(
            map_vreg,
            MirType::MapRef {
                key_ty: Box::new(map_key_ty),
                val_ty: Box::new(MirType::U32),
            },
        );

        let status_vreg = self.func.alloc_vreg();
        self.emit(MirInst::CallHelper {
            dst: status_vreg,
            helper: helper as u32,
            args: vec![
                MirValue::VReg(ctx_vreg),
                MirValue::VReg(map_vreg),
                MirValue::VReg(key_ptr_vreg),
                MirValue::Const(flags as i64),
            ],
        });
        self.vreg_type_hints.insert(status_vreg, MirType::I64);
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::Const(0),
        });
        self.reset_call_result_metadata(src_dst);
        Ok(())
    }

    fn local_storage_object_vreg(&mut self, object_vreg: VReg, object_reg: Option<RegId>) -> VReg {
        if object_reg.is_some_and(|reg| self.is_context_reg(reg)) {
            self.materialize_context_pointer_arg()
        } else {
            object_vreg
        }
    }

    fn local_storage_map_value_hint(&self, map_ref: &MapRef) -> Result<MirType, CompileError> {
        Ok(self
            .validated_named_map_value_type(map_ref, "map-get local-storage value schema")?
            .unwrap_or(MirType::Unknown))
    }

    fn lower_local_storage_map_get(
        &mut self,
        src_dst: RegId,
        src_dst_value_vreg: VReg,
        result_vreg: VReg,
        src_dst_had_value: bool,
        map_ref: MapRef,
    ) -> Result<(), CompileError> {
        let helper = BpfHelper::local_storage_get_for_map_kind(map_ref.kind).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "map-get does not support local-storage map kind {}",
                map_ref.kind
            ))
        })?;
        let object_vreg = self
            .positional_args
            .get(1)
            .map(|(vreg, _)| *vreg)
            .or(self.pipeline_input)
            .or_else(|| src_dst_had_value.then_some(src_dst_value_vreg))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "map-get local-storage requires an object pointer from pipeline input or a second positional argument"
                        .into(),
                )
            })?;
        let object_reg = self
            .positional_args
            .get(1)
            .map(|(_, reg)| *reg)
            .or(self.pipeline_input_reg)
            .or_else(|| src_dst_had_value.then_some(src_dst));
        let object_vreg = self.local_storage_object_vreg(object_vreg, object_reg);

        let init_arg = if let Some((init_vreg, init_reg)) = self.named_args.get("init").copied() {
            self.reject_context_pointer_payload(Some(init_reg), "map-get init value")?;
            let init_vreg = self.materialized_metadata_aggregate_vreg(init_reg, init_vreg)?;
            let (init_ptr_vreg, _) =
                self.materialize_map_value_probe_pointer(Some(init_reg), init_vreg, "map-get")?;
            self.record_named_map_value_schema_from_reg(&map_ref, Some(init_reg), "map-get")?;
            MirValue::VReg(init_ptr_vreg)
        } else {
            MirValue::Const(0)
        };
        let default_flags = if self.named_args.contains_key("init") {
            1
        } else {
            0
        };
        let flags = self
            .optional_nonnegative_named_u64_arg("map-get", "flags")?
            .unwrap_or(default_flags);

        let map_vreg = self.emit_typed_map_fd_load(map_ref.name.clone(), map_ref.kind);
        let value_ty = self.local_storage_map_value_hint(&map_ref)?;
        self.vreg_type_hints.insert(
            map_vreg,
            MirType::MapRef {
                key_ty: Box::new(MirType::U32),
                val_ty: Box::new(value_ty.clone()),
            },
        );

        self.emit(MirInst::CallHelper {
            dst: result_vreg,
            helper: helper as u32,
            args: vec![
                MirValue::VReg(map_vreg),
                MirValue::VReg(object_vreg),
                init_arg,
                MirValue::Const(flags as i64),
            ],
        });

        let result_pointee = if matches!(value_ty, MirType::Unknown) {
            MirType::U8
        } else {
            value_ty
        };
        let result_ty = MirType::Ptr {
            pointee: Box::new(result_pointee.clone()),
            address_space: AddressSpace::Map,
        };
        self.vreg_type_hints.insert(result_vreg, result_ty.clone());

        self.reset_call_result_metadata(src_dst);
        if !matches!(result_pointee, MirType::U8) {
            let semantics = self.named_map_value_semantics(&map_ref).cloned();
            let meta = self.get_or_create_metadata(src_dst);
            meta.field_type = Some(result_ty);
            if let Some(semantics) = semantics {
                meta.annotated_semantics = Some(semantics);
            }
        }
        Ok(())
    }

    fn lower_local_storage_map_delete(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        map_ref: MapRef,
    ) -> Result<(), CompileError> {
        let helper =
            BpfHelper::local_storage_delete_for_map_kind(map_ref.kind).ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "map-delete does not support local-storage map kind {}",
                    map_ref.kind
                ))
            })?;
        let object_vreg = self
            .positional_args
            .get(1)
            .map(|(vreg, _)| *vreg)
            .or(self.pipeline_input)
            .or_else(|| src_dst_had_value.then_some(dst_vreg))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "map-delete local-storage requires an object pointer from pipeline input or a second positional argument"
                        .into(),
                )
            })?;
        let object_reg = self
            .positional_args
            .get(1)
            .map(|(_, reg)| *reg)
            .or(self.pipeline_input_reg)
            .or_else(|| src_dst_had_value.then_some(src_dst));
        let object_vreg = self.local_storage_object_vreg(object_vreg, object_reg);

        let map_vreg = self.emit_typed_map_fd_load(map_ref.name, map_ref.kind);
        self.emit(MirInst::CallHelper {
            dst: dst_vreg,
            helper: helper as u32,
            args: vec![MirValue::VReg(map_vreg), MirValue::VReg(object_vreg)],
        });
        self.vreg_type_hints.insert(dst_vreg, MirType::I64);
        self.reset_call_result_metadata(src_dst);
        Ok(())
    }

    fn lower_queue_stack_map_take(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        context: &str,
        helper: BpfHelper,
    ) -> Result<(), CompileError> {
        if !self.named_flags.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} does not accept flags"
            )));
        }
        if self.pipeline_input.is_some() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} does not accept pipeline input"
            )));
        }
        self.require_only_named_args(context, &["kind"])?;

        let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{context} requires a literal map name as the first positional argument"
            ))
        })?;
        if self.positional_args.len() > 1 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{context} only accepts a map name positional argument"
            )));
        }

        let map_name = self.literal_string_arg(map_reg, context)?;
        self.validate_generic_map_name(&map_name, context)?;
        let map_kind = self.required_queue_stack_map_kind_arg(context, &map_name)?;
        let map_ref = MapRef {
            name: map_name,
            kind: map_kind,
        };
        let stored_ty = self
            .validated_named_map_value_type(&map_ref, context)?
            .filter(|ty| !matches!(ty, MirType::Unknown))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{context} requires known value layout for '{}'; establish it with a prior typed map-push or pinned schema",
                    map_ref.name
                ))
            })?;
        let stored_semantics = self.named_map_value_semantics(&map_ref).cloned();

        let map_vreg = self.func.alloc_vreg();
        self.emit(MirInst::LoadMapFd {
            dst: map_vreg,
            map: map_ref,
        });
        self.vreg_type_hints.insert(
            map_vreg,
            MirType::MapRef {
                key_ty: Box::new(MirType::Unknown),
                val_ty: Box::new(stored_ty.clone()),
            },
        );

        let out_slot = self.func.alloc_stack_slot(
            align_to_eight(stored_ty.size().max(1)),
            stored_ty.align().max(1),
            StackSlotKind::Local,
        );
        self.record_stack_slot_type(out_slot, stored_ty.clone());

        let out_ptr_ty = MirType::Ptr {
            pointee: Box::new(stored_ty.clone()),
            address_space: AddressSpace::Stack,
        };
        let out_ptr_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Copy {
            dst: out_ptr_vreg,
            src: MirValue::StackSlot(out_slot),
        });
        self.vreg_type_hints
            .insert(out_ptr_vreg, out_ptr_ty.clone());

        let status_vreg = self.func.alloc_vreg();
        self.emit(MirInst::CallHelper {
            dst: status_vreg,
            helper: helper as u32,
            args: vec![MirValue::VReg(map_vreg), MirValue::VReg(out_ptr_vreg)],
        });
        self.vreg_type_hints.insert(status_vreg, MirType::I64);

        let has_value_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: has_value_vreg,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(status_vreg),
            rhs: MirValue::Const(0),
        });
        self.vreg_type_hints.insert(has_value_vreg, MirType::Bool);

        let success_block = self.func.alloc_block();
        let empty_block = self.func.alloc_block();
        let continue_block = self.func.alloc_block();
        self.terminate(MirInst::Branch {
            cond: has_value_vreg,
            if_true: success_block,
            if_false: empty_block,
        });

        self.current_block = success_block;
        if matches!(stored_ty, MirType::Array { .. } | MirType::Struct { .. }) {
            self.emit(MirInst::Copy {
                dst: dst_vreg,
                src: MirValue::StackSlot(out_slot),
            });
        } else {
            self.emit(MirInst::LoadSlot {
                dst: dst_vreg,
                slot: out_slot,
                offset: 0,
                ty: stored_ty.clone(),
            });
        }
        self.terminate(MirInst::Jump {
            target: continue_block,
        });

        self.current_block = empty_block;
        self.emit(MirInst::Copy {
            dst: dst_vreg,
            src: MirValue::Const(0),
        });
        self.terminate(MirInst::Jump {
            target: continue_block,
        });

        self.current_block = continue_block;
        self.reset_call_result_metadata(src_dst);
        if matches!(stored_ty, MirType::Array { .. } | MirType::Struct { .. }) {
            self.vreg_type_hints.insert(dst_vreg, out_ptr_ty.clone());
            let meta = self.get_or_create_metadata(src_dst);
            meta.field_type = Some(out_ptr_ty);
            if let Some(semantics) = stored_semantics {
                meta.annotated_semantics = Some(semantics);
            }
        } else {
            self.vreg_type_hints.insert(dst_vreg, stored_ty);
        }

        Ok(())
    }

    fn lower_map_contains(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const CONTEXT: &str = "map-contains";

        if !self.named_flags.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "map-contains does not accept flags".into(),
            ));
        }
        self.require_only_named_args(CONTEXT, &["kind"])?;

        let (map_arg_vreg, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "map-contains requires a literal map name or map-in-map lookup result as the first positional argument"
                    .into(),
            )
        })?;
        if let Some(inner_map) = self
            .get_metadata(map_reg)
            .and_then(|meta| meta.dynamic_map_ref.clone())
        {
            if !self.named_args.is_empty() {
                return Err(CompileError::UnsupportedInstruction(
                    "map-contains on a dynamic inner-map pointer does not accept named arguments"
                        .into(),
                ));
            }
            return self.lower_dynamic_map_contains(
                src_dst,
                dst_vreg,
                src_dst_had_value,
                map_arg_vreg,
                inner_map,
            );
        }

        let map_name = self.literal_string_arg(map_reg, CONTEXT)?;
        self.validate_generic_map_name(&map_name, CONTEXT)?;

        match self.map_contains_kind_arg(CONTEXT, &map_name)? {
            MapKind::BloomFilter => {
                self.lower_bloom_filter_map_contains(src_dst, dst_vreg, src_dst_had_value)
            }
            MapKind::CgroupArray => {
                self.lower_cgroup_array_map_contains(src_dst, dst_vreg, src_dst_had_value)
            }
            map_kind if map_kind.supports_generic_map_op(MapOpKind::Lookup) => {
                self.lower_generic_map_contains(src_dst, dst_vreg, src_dst_had_value, map_kind)
            }
            map_kind if map_kind.is_local_storage() => self.lower_local_storage_map_contains(
                src_dst,
                dst_vreg,
                src_dst_had_value,
                map_kind,
            ),
            other => Err(CompileError::UnsupportedInstruction(format!(
                "{CONTEXT} does not support map kind {}",
                other
            ))),
        }
    }

    fn lower_bloom_filter_map_contains(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const CONTEXT: &str = "map-contains";

        if !self.named_flags.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "map-contains does not accept flags".into(),
            ));
        }
        self.require_only_named_args(CONTEXT, &["kind"])?;

        let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "map-contains requires a literal map name as the first positional argument".into(),
            )
        })?;
        let map_name = self.literal_string_arg(map_reg, CONTEXT)?;
        self.validate_generic_map_name(&map_name, CONTEXT)?;
        let map_kind = self.required_bloom_filter_map_kind_arg(CONTEXT, &map_name)?;
        let map_ref = MapRef {
            name: map_name,
            kind: map_kind,
        };
        let value_vreg = self
            .positional_args
            .get(1)
            .map(|(vreg, _)| *vreg)
            .or(self.pipeline_input)
            .or_else(|| src_dst_had_value.then_some(dst_vreg))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "map-contains requires a probe value from pipeline input or a second positional argument"
                        .into(),
                )
            })?;
        let value_reg = self
            .positional_args
            .get(1)
            .map(|(_, reg)| *reg)
            .or(self.pipeline_input_reg)
            .or_else(|| src_dst_had_value.then_some(src_dst));
        let stored_value_vreg = if let Some(value_reg) = value_reg {
            self.materialized_metadata_aggregate_vreg(value_reg, value_vreg)?
        } else {
            value_vreg
        };
        self.record_named_map_value_schema_from_reg(&map_ref, value_reg, CONTEXT)?;

        let (value_ptr_vreg, value_ty) =
            self.materialize_map_value_probe_pointer(value_reg, stored_value_vreg, CONTEXT)?;

        let map_vreg = self.func.alloc_vreg();
        self.emit(MirInst::LoadMapFd {
            dst: map_vreg,
            map: map_ref,
        });
        self.vreg_type_hints.insert(
            map_vreg,
            MirType::MapRef {
                key_ty: Box::new(MirType::Unknown),
                val_ty: Box::new(value_ty),
            },
        );

        let status_vreg = self.func.alloc_vreg();
        self.emit(MirInst::CallHelper {
            dst: status_vreg,
            helper: BpfHelper::MapPeekElem as u32,
            args: vec![MirValue::VReg(map_vreg), MirValue::VReg(value_ptr_vreg)],
        });
        self.vreg_type_hints.insert(status_vreg, MirType::I64);

        self.emit(MirInst::BinOp {
            dst: dst_vreg,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(status_vreg),
            rhs: MirValue::Const(0),
        });
        self.vreg_type_hints.insert(dst_vreg, MirType::Bool);
        self.reset_call_result_metadata(src_dst);
        Ok(())
    }

    fn lower_generic_map_contains(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        map_kind: MapKind,
    ) -> Result<(), CompileError> {
        const CONTEXT: &str = "map-contains";

        let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "map-contains requires a literal map name as the first positional argument".into(),
            )
        })?;
        let map_name = self.literal_string_arg(map_reg, CONTEXT)?;
        self.validate_generic_map_name(&map_name, CONTEXT)?;
        self.validate_generic_map_lookup_kind(map_kind, &map_name)?;

        let map_ref = MapRef {
            name: map_name,
            kind: map_kind,
        };
        let key_vreg = self
            .positional_args
            .get(1)
            .map(|(vreg, _)| *vreg)
            .or(self.pipeline_input)
            .or_else(|| src_dst_had_value.then_some(dst_vreg))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "map-contains requires a key from pipeline input or a second positional argument"
                        .into(),
                )
            })?;
        let key_reg = self
            .positional_args
            .get(1)
            .map(|(_, reg)| *reg)
            .or(self.pipeline_input_reg)
            .or_else(|| src_dst_had_value.then_some(src_dst));
        let key_vreg = self.map_key_vreg_for_named_schema(&map_ref, key_vreg, key_reg, CONTEXT)?;
        let lookup_vreg = self.func.alloc_vreg();

        self.emit(MirInst::MapLookup {
            dst: lookup_vreg,
            map: map_ref.clone(),
            key: key_vreg,
        });
        let lookup_ty = if map_ref.kind.is_map_in_map() {
            let _ = self.map_in_map_inner_template(&map_ref, CONTEXT)?;
            MirType::named_kernel_struct_ptr("bpf_map")
        } else {
            let stored_ty =
                self.validated_named_map_value_type(&map_ref, "map-contains value schema")?;
            MirType::Ptr {
                pointee: Box::new(stored_ty.unwrap_or(MirType::U8)),
                address_space: AddressSpace::Map,
            }
        };
        self.vreg_type_hints.insert(lookup_vreg, lookup_ty);
        self.emit(MirInst::BinOp {
            dst: dst_vreg,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(lookup_vreg),
            rhs: MirValue::Const(0),
        });
        self.vreg_type_hints.insert(dst_vreg, MirType::Bool);
        self.reset_call_result_metadata(src_dst);
        Ok(())
    }

    fn lower_dynamic_map_contains(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        map_ptr: VReg,
        inner_map: MapRef,
    ) -> Result<(), CompileError> {
        const CONTEXT: &str = "map-contains";

        self.validate_generic_map_lookup_kind(inner_map.kind, &inner_map.name)?;
        let key_vreg = self
            .positional_args
            .get(1)
            .map(|(vreg, _)| *vreg)
            .or(self.pipeline_input)
            .or_else(|| src_dst_had_value.then_some(dst_vreg))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "map-contains requires a key from pipeline input or a second positional argument"
                        .into(),
                )
            })?;
        let key_reg = self
            .positional_args
            .get(1)
            .map(|(_, reg)| *reg)
            .or(self.pipeline_input_reg)
            .or_else(|| src_dst_had_value.then_some(src_dst));
        let key_vreg =
            self.map_key_vreg_for_named_schema(&inner_map, key_vreg, key_reg, CONTEXT)?;
        let lookup_vreg = self.func.alloc_vreg();

        self.emit(MirInst::MapLookupDynamic {
            dst: lookup_vreg,
            map_ptr,
            inner_map: inner_map.clone(),
            key: key_vreg,
        });
        let stored_ty =
            self.validated_named_map_value_type(&inner_map, "map-contains value schema")?;
        self.vreg_type_hints.insert(
            lookup_vreg,
            MirType::Ptr {
                pointee: Box::new(stored_ty.unwrap_or(MirType::U8)),
                address_space: AddressSpace::Map,
            },
        );
        self.emit(MirInst::BinOp {
            dst: dst_vreg,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(lookup_vreg),
            rhs: MirValue::Const(0),
        });
        self.vreg_type_hints.insert(dst_vreg, MirType::Bool);
        self.reset_call_result_metadata(src_dst);
        Ok(())
    }

    fn lower_local_storage_map_contains(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        map_kind: MapKind,
    ) -> Result<(), CompileError> {
        const CONTEXT: &str = "map-contains";

        let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "map-contains requires a literal map name as the first positional argument".into(),
            )
        })?;
        let map_name = self.literal_string_arg(map_reg, CONTEXT)?;
        self.validate_generic_map_name(&map_name, CONTEXT)?;

        let map_ref = MapRef {
            name: map_name,
            kind: map_kind,
        };
        let lookup_vreg = self.func.alloc_vreg();
        self.lower_local_storage_map_get(
            src_dst,
            dst_vreg,
            lookup_vreg,
            src_dst_had_value,
            map_ref,
        )?;
        self.emit(MirInst::BinOp {
            dst: dst_vreg,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(lookup_vreg),
            rhs: MirValue::Const(0),
        });
        self.vreg_type_hints.insert(dst_vreg, MirType::Bool);
        self.reset_call_result_metadata(src_dst);
        Ok(())
    }

    fn lower_cgroup_array_map_contains(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const CONTEXT: &str = "map-contains";

        let (_, map_reg) = self.positional_args.first().copied().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "map-contains requires a literal map name as the first positional argument".into(),
            )
        })?;
        if self.positional_args.len() > 2 {
            return Err(CompileError::UnsupportedInstruction(
                "map-contains --kind cgroup-array accepts at most a map name and cgroup index"
                    .into(),
            ));
        }

        let map_name = self.literal_string_arg(map_reg, CONTEXT)?;
        self.validate_generic_map_name(&map_name, CONTEXT)?;
        let map_kind = self.map_contains_kind_arg(CONTEXT, &map_name)?;
        if map_kind != MapKind::CgroupArray {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{CONTEXT} requires --kind cgroup-array for cgroup membership probes"
            )));
        }

        if self
            .positional_args
            .get(1)
            .is_some_and(|(_, reg)| self.is_context_reg(*reg))
        {
            return Err(CompileError::UnsupportedInstruction(
                "map-contains --kind cgroup-array requires a scalar cgroup index, got context"
                    .into(),
            ));
        }
        let index_reg = self
            .positional_args
            .get(1)
            .map(|(_, reg)| *reg)
            .or(self.pipeline_input_reg)
            .or_else(|| src_dst_had_value.then_some(src_dst));
        self.reject_context_pointer_payload(index_reg, "map-contains --kind cgroup-array index")?;
        let pipeline_index = match (self.pipeline_input, self.pipeline_input_reg) {
            (Some(vreg), Some(reg)) if !self.is_context_reg(reg) => Some(vreg),
            (Some(vreg), None) => Some(vreg),
            _ => None,
        };
        let src_dst_index = if src_dst_had_value && !self.is_context_reg(src_dst) {
            Some(dst_vreg)
        } else {
            None
        };
        let index_vreg = self
            .positional_args
            .get(1)
            .map(|(vreg, _)| *vreg)
            .or(pipeline_index)
            .or(src_dst_index)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "map-contains --kind cgroup-array requires a cgroup index from pipeline input or a second positional argument"
                        .into(),
                )
            })?;

        let helper = self
            .probe_ctx
            .map_or(BpfHelper::CurrentTaskUnderCgroup, |ctx| {
                ctx.program_type().cgroup_array_membership_helper()
            });
        if let Some(message) = self.probe_ctx.and_then(|ctx| ctx.helper_call_error(helper)) {
            return Err(CompileError::UnsupportedInstruction(message));
        }

        let map_vreg = self.emit_typed_map_fd_load(map_name, MapKind::CgroupArray);
        let mut args = Vec::new();
        if matches!(helper, BpfHelper::SkbUnderCgroup) {
            let ctx_vreg = self.materialize_context_pointer_arg();
            args.push(MirValue::VReg(ctx_vreg));
        }
        args.push(MirValue::VReg(map_vreg));
        args.push(MirValue::VReg(index_vreg));

        let status_vreg = self.func.alloc_vreg();
        self.emit(MirInst::CallHelper {
            dst: status_vreg,
            helper: helper as u32,
            args,
        });
        self.vreg_type_hints.insert(status_vreg, MirType::I64);
        self.emit(MirInst::BinOp {
            dst: dst_vreg,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(status_vreg),
            rhs: MirValue::Const(1),
        });
        self.vreg_type_hints.insert(dst_vreg, MirType::Bool);
        self.reset_call_result_metadata(src_dst);
        Ok(())
    }

    fn materialize_map_value_probe_pointer(
        &mut self,
        value_reg: Option<RegId>,
        value_vreg: VReg,
        context: &str,
    ) -> Result<(VReg, MirType), CompileError> {
        self.reject_context_pointer_payload(value_reg, context)?;
        let value_ty = value_reg
            .and_then(|reg| self.get_metadata(reg))
            .and_then(|meta| {
                meta.field_type
                    .clone()
                    .or_else(|| Self::metadata_record_layout(meta))
            })
            .or_else(|| self.vreg_type_hints.get(&value_vreg).cloned())
            .unwrap_or(MirType::U64);

        match value_ty {
            MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack | AddressSpace::Map,
            } => Ok((value_vreg, pointee.as_ref().clone())),
            MirType::Ptr { address_space, .. } => Err(CompileError::UnsupportedInstruction(
                format!("{context} value pointer must be stack/map backed, got {address_space:?}"),
            )),
            value_ty @ (MirType::Array { .. } | MirType::Struct { .. }) => {
                let Some(value_reg) = value_reg else {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{context} aggregate values must come from a typed stack/map-backed value"
                    )));
                };
                let ptr_vreg = self.materialized_metadata_aggregate_vreg(value_reg, value_vreg)?;
                Ok((ptr_vreg, self.stored_generic_map_value_type(&value_ty)))
            }
            value_ty
                if matches!(
                    value_ty,
                    MirType::I8
                        | MirType::I16
                        | MirType::I32
                        | MirType::I64
                        | MirType::U8
                        | MirType::U16
                        | MirType::U32
                        | MirType::U64
                        | MirType::Bool
                        | MirType::Unknown
                ) =>
            {
                let slot = self.func.alloc_stack_slot(
                    align_to_eight(value_ty.size().max(1)),
                    value_ty.align().max(1),
                    StackSlotKind::Local,
                );
                self.record_stack_slot_type(slot, value_ty.clone());
                self.emit(MirInst::StoreSlot {
                    slot,
                    offset: 0,
                    val: MirValue::VReg(value_vreg),
                    ty: value_ty.clone(),
                });
                let ptr_vreg = self.func.alloc_vreg();
                self.emit(MirInst::Copy {
                    dst: ptr_vreg,
                    src: MirValue::StackSlot(slot),
                });
                self.vreg_type_hints.insert(
                    ptr_vreg,
                    MirType::Ptr {
                        pointee: Box::new(value_ty.clone()),
                        address_space: AddressSpace::Stack,
                    },
                );
                Ok((ptr_vreg, value_ty))
            }
            other => Err(CompileError::UnsupportedInstruction(format!(
                "{context} value must be scalar or stack/map-backed aggregate, got {other:?}"
            ))),
        }
    }

    fn materialize_helper_map_fd_arg(
        &mut self,
        helper: BpfHelper,
        arg_idx: usize,
        arg_reg: RegId,
    ) -> Result<(MirValue, MapRef, VReg), CompileError> {
        let map_name = match self.literal_string_arg(arg_reg, "helper-call") {
            Ok(name) => name,
            Err(_) => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "helper-call arg{} for '{}' must be a literal map name",
                    arg_idx,
                    helper.name()
                )));
            }
        };
        let map_kind = if let Some(kind) = helper.helper_map_arg_kind(arg_idx) {
            kind
        } else {
            match helper.helper_explicit_map_kind_family(arg_idx) {
                Some(HelperExplicitMapKindFamily::QueueStack) => {
                    self.required_queue_stack_map_kind_arg("helper-call", &map_name)?
                }
                Some(HelperExplicitMapKindFamily::QueueStackBloom) => {
                    self.required_queue_stack_bloom_map_kind_arg("helper-call", &map_name)?
                }
                Some(HelperExplicitMapKindFamily::RedirectMap) => {
                    self.required_redirect_map_kind_arg("helper-call", &map_name)?
                }
                Some(HelperExplicitMapKindFamily::PerCpuLookupMap) => {
                    self.required_per_cpu_lookup_map_kind_arg("helper-call", &map_name)?
                }
                Some(HelperExplicitMapKindFamily::ForEachMapElem) => {
                    self.for_each_map_elem_kind_arg("helper-call", &map_name)?
                }
                Some(HelperExplicitMapKindFamily::TimerMap) => {
                    self.required_timer_map_kind_arg("helper-call", &map_name)?
                }
                None => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "internal error: helper '{}' arg{} is not a map operand",
                        helper.name(),
                        arg_idx
                    )));
                }
            }
        };
        let map_ref = MapRef {
            name: map_name,
            kind: map_kind,
        };
        let map_vreg = self.emit_typed_map_fd_load(map_ref.name.clone(), map_ref.kind);
        Ok((MirValue::VReg(map_vreg), map_ref, map_vreg))
    }

    fn materialize_kfunc_map_fd_arg(
        &mut self,
        kfunc: &str,
        arg_idx: usize,
        arg_reg: Option<RegId>,
        args: &[(VReg, Option<RegId>)],
    ) -> Result<Option<VReg>, CompileError> {
        if !crate::compiler::instruction::kfunc_supports_local_map_fd(kfunc, arg_idx) {
            return Ok(None);
        }

        let arg_reg = arg_reg.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "kfunc-call '{}' arg{} must be a literal map name",
                kfunc, arg_idx
            ))
        })?;
        let map_name = match self.literal_string_arg(arg_reg, "kfunc-call") {
            Ok(name) => name,
            Err(_) => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "kfunc-call '{}' arg{} must be a literal map name",
                    kfunc, arg_idx
                )));
            }
        };

        match (kfunc, arg_idx) {
            ("bpf_wq_init", 1) => {
                let wq_reg = args.first().and_then(|(_, reg)| *reg).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "kfunc-call 'bpf_wq_init' requires arg0 bpf_wq field".into(),
                    )
                })?;
                let origin = self.bpf_wq_arg_origin(kfunc, 0, wq_reg)?;
                if map_name != origin.map_ref.name {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "kfunc-call 'bpf_wq_init' requires arg1 map '{}' to match the map value containing arg0 '{}' ({})",
                        map_name, origin.map_ref.name, origin.map_ref.kind
                    )));
                }
                Ok(Some(
                    self.emit_typed_map_fd_load(map_name, origin.map_ref.kind),
                ))
            }
            _ => Err(CompileError::UnsupportedInstruction(format!(
                "internal error: kfunc '{}' arg{} is not a map operand",
                kfunc, arg_idx
            ))),
        }
    }

    fn emit_typed_map_fd_load(&mut self, map_name: String, map_kind: MapKind) -> VReg {
        let map_vreg = self.func.alloc_vreg();
        let map_ref = MapRef {
            name: map_name.clone(),
            kind: map_kind,
        };
        self.observed_map_refs.insert(map_ref.clone());
        self.emit(MirInst::LoadMapFd {
            dst: map_vreg,
            map: map_ref.clone(),
        });
        if matches!(map_kind, MapKind::SockMap) {
            self.vreg_type_hints.insert(
                map_vreg,
                MirType::MapRef {
                    key_ty: Box::new(MirType::U32),
                    val_ty: Box::new(MirType::U32),
                },
            );
        } else if matches!(
            map_kind,
            MapKind::CgroupArray | MapKind::PerfEventArray | MapKind::ProgArray
        ) || map_kind.is_array_index_map()
        {
            self.vreg_type_hints.insert(
                map_vreg,
                MirType::MapRef {
                    key_ty: Box::new(MirType::U32),
                    val_ty: Box::new(MirType::U32),
                },
            );
        } else if matches!(
            map_kind,
            MapKind::Hash
                | MapKind::LpmTrie
                | MapKind::LruHash
                | MapKind::PerCpuHash
                | MapKind::LruPerCpuHash
        ) {
            let key_ty = self
                .named_map_key_type(&map_ref)
                .cloned()
                .unwrap_or(MirType::Unknown);
            self.vreg_type_hints.insert(
                map_vreg,
                MirType::MapRef {
                    key_ty: Box::new(key_ty),
                    val_ty: Box::new(MirType::Unknown),
                },
            );
        } else if map_kind.is_redirect_map() {
            self.vreg_type_hints.insert(
                map_vreg,
                MirType::MapRef {
                    key_ty: Box::new(MirType::U32),
                    val_ty: Box::new(MirType::Unknown),
                },
            );
        } else if map_kind.is_keyless_map() {
            self.vreg_type_hints.insert(
                map_vreg,
                MirType::MapRef {
                    key_ty: Box::new(MirType::Unknown),
                    val_ty: Box::new(MirType::Unknown),
                },
            );
        } else if matches!(
            map_kind,
            MapKind::SkStorage
                | MapKind::InodeStorage
                | MapKind::TaskStorage
                | MapKind::CgrpStorage
        ) {
            self.vreg_type_hints.insert(
                map_vreg,
                MirType::MapRef {
                    key_ty: Box::new(MirType::U32),
                    val_ty: Box::new(MirType::Unknown),
                },
            );
        }
        map_vreg
    }

    fn storage_helper_init_arg_idx(helper: BpfHelper) -> Option<usize> {
        match helper {
            BpfHelper::SkStorageGet
            | BpfHelper::TaskStorageGet
            | BpfHelper::InodeStorageGet
            | BpfHelper::CgrpStorageGet => Some(2),
            _ => None,
        }
    }

    fn storage_helper_init_value_type_from_reg(&self, value_reg: RegId) -> Option<MirType> {
        let value_ty = self.get_metadata(value_reg).and_then(|meta| {
            meta.field_type
                .clone()
                .or_else(|| Self::metadata_record_layout(meta))
        })?;
        match value_ty {
            MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack | AddressSpace::Map,
            } => Some(pointee.as_ref().clone()),
            MirType::Array { .. } | MirType::Struct { .. } => Some(value_ty),
            _ => None,
        }
    }

    fn record_storage_helper_value_schema(
        &mut self,
        helper: BpfHelper,
        dst_vreg: VReg,
        helper_map_args: &[(usize, MapRef, VReg)],
        helper_arg_regs: &[(usize, RegId)],
    ) -> Result<(), CompileError> {
        let Some(init_arg_idx) = Self::storage_helper_init_arg_idx(helper) else {
            return Ok(());
        };
        let Some((_, map_ref, map_vreg)) = helper_map_args.iter().find(|(idx, _, _)| *idx == 0)
        else {
            return Ok(());
        };
        let Some((_, init_reg)) = helper_arg_regs.iter().find(|(idx, _)| *idx == init_arg_idx)
        else {
            return Ok(());
        };
        let Some(value_ty) = self.storage_helper_init_value_type_from_reg(*init_reg) else {
            return Ok(());
        };

        let explicit_schema = self.declared_map_value_types.contains(map_ref);
        if (self.externally_seeded_map_value_types.contains(map_ref) || explicit_schema)
            && let Some(existing) = self.named_map_value_type(map_ref)
            && existing != &value_ty
        {
            let schema_source = if explicit_schema {
                "declared"
            } else {
                "pinned"
            };
            return Err(CompileError::UnsupportedInstruction(format!(
                "storage helper init value type for '{}' conflicts with {schema_source} map schema",
                map_ref.name,
            )));
        }

        self.register_named_map_value_type(map_ref, &value_ty);
        self.vreg_type_hints.insert(
            *map_vreg,
            MirType::MapRef {
                key_ty: Box::new(MirType::U32),
                val_ty: Box::new(value_ty.clone()),
            },
        );
        self.vreg_type_hints.insert(
            dst_vreg,
            MirType::Ptr {
                pointee: Box::new(value_ty),
                address_space: AddressSpace::Map,
            },
        );
        Ok(())
    }

    fn helper_arg_runtime_type(
        &self,
        args: &[MirValue],
        helper_arg_regs: &[(usize, RegId)],
        arg_idx: usize,
    ) -> Option<MirType> {
        let MirValue::VReg(vreg) = args.get(arg_idx)? else {
            return None;
        };
        helper_arg_regs
            .iter()
            .find(|(idx, _)| *idx == arg_idx)
            .and_then(|(_, reg)| self.typed_value_runtime_type(*reg, *vreg))
            .or_else(|| self.vreg_type_hints.get(vreg).cloned())
    }

    fn validate_kptr_xchg_helper_call_args(
        &self,
        helper: BpfHelper,
        args: &[MirValue],
        helper_arg_regs: &[(usize, RegId)],
    ) -> Result<(), CompileError> {
        if !matches!(helper, BpfHelper::KptrXchg) {
            return Ok(());
        }

        let Some(dst_ty) = self.helper_arg_runtime_type(args, helper_arg_regs, 0) else {
            return Ok(());
        };
        let MirType::Ptr {
            pointee: dst_pointee,
            address_space: AddressSpace::Map,
        } = dst_ty
        else {
            return Ok(());
        };
        let Some(dst_pointee_name) = dst_pointee.bpf_kptr_pointee_name() else {
            return Err(CompileError::UnsupportedInstruction(
                "helper-call 'bpf_kptr_xchg' requires arg0 to be a kptr field projected from a typed map value"
                    .into(),
            ));
        };

        match args.get(1) {
            Some(MirValue::Const(0)) => Ok(()),
            Some(MirValue::Const(_)) => Ok(()),
            Some(MirValue::VReg(_)) => {
                let Some(src_ty) = self.helper_arg_runtime_type(args, helper_arg_regs, 1) else {
                    return Ok(());
                };
                let Some(src_pointee_name) = src_ty.kernel_struct_ptr_pointee_name() else {
                    return Ok(());
                };
                if src_pointee_name != dst_pointee_name {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "helper-call 'bpf_kptr_xchg' cannot store {src_pointee_name} pointer in kptr:{dst_pointee_name} slot"
                    )));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}
