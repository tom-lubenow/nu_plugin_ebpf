use super::*;
use crate::compiler::mir::AddressSpace;

mod bits;
mod compact;
mod dedupe;
mod find;
mod math;
mod predicates;
mod sort;
mod split;

impl<'a> HirToMirLowering<'a> {
    fn is_stack_list_placeholder_type(ty: &MirType) -> bool {
        matches!(
            ty,
            MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack,
            } if matches!(
                pointee.as_ref(),
                MirType::Array { elem, .. } if matches!(elem.as_ref(), MirType::I64)
            )
        )
    }

    fn is_metadata_only_placeholder_type(ty: &MirType) -> bool {
        matches!(ty, MirType::I64)
    }

    pub(super) fn direct_list_builder_values(
        &self,
        input_reg: RegId,
        input_vreg: VReg,
    ) -> Option<&[nu_protocol::Value]> {
        let meta = self.get_metadata(input_reg)?;
        let nu_protocol::Value::List { vals, .. } = meta.constant_value.as_ref()? else {
            return None;
        };
        if meta.list_buffer.is_some() {
            return None;
        }
        let ty = self.vreg_type_hints.get(&input_vreg)?;
        if !Self::is_stack_list_placeholder_type(ty) {
            return None;
        }
        Some(vals)
    }

    pub(super) fn compile_time_only_list_builder_values(
        &self,
        input_reg: RegId,
        input_vreg: VReg,
    ) -> Option<&[nu_protocol::Value]> {
        let meta = self.get_metadata(input_reg)?;
        let value @ nu_protocol::Value::List { vals, .. } = meta.constant_value.as_ref()? else {
            return None;
        };
        if meta.list_buffer.is_some() {
            return None;
        }
        if crate::compiler::hir::supports_numeric_constant_list(value)
            && matches!(
                meta.annotated_semantics,
                Some(AnnotatedValueSemantics::NumericList { .. })
            )
        {
            return Some(vals);
        }
        if self
            .vreg_type_hints
            .get(&input_vreg)
            .is_some_and(Self::is_metadata_only_placeholder_type)
        {
            return Some(vals);
        }
        self.direct_list_builder_values(input_reg, input_vreg)
    }

    pub(super) fn lower_compile_time_list_transform_result(
        &mut self,
        dst: RegId,
        value: &nu_protocol::Value,
    ) -> Result<(), CompileError> {
        if self.current_call_result_metadata_only {
            self.lower_compile_time_only_constant_value(dst, value);
            Ok(())
        } else {
            self.lower_constant_value(dst, value)
        }
    }

    pub(super) fn create_stack_numeric_list_result(
        &mut self,
        dst_vreg: VReg,
        max_len: usize,
    ) -> (StackSlotId, MirType) {
        let out_ty = MirType::Array {
            elem: Box::new(MirType::I64),
            len: max_len.saturating_add(1),
        };
        let out_slot = self.func.alloc_stack_slot(
            align_to_eight(8 + max_len * 8),
            8,
            StackSlotKind::ListBuffer,
        );
        self.record_list_buffer_slot_type(out_slot, max_len);
        self.emit(MirInst::ListNew {
            dst: dst_vreg,
            buffer: out_slot,
            max_len,
        });
        self.vreg_type_hints.insert(
            dst_vreg,
            MirType::Ptr {
                pointee: Box::new(out_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );
        (out_slot, out_ty)
    }

    pub(super) fn numeric_list_known_len(meta: &RegMetadata) -> Option<usize> {
        match &meta.annotated_semantics {
            Some(AnnotatedValueSemantics::NumericList { known_len, .. }) => *known_len,
            _ => None,
        }
        .or_else(|| match &meta.constant_value {
            Some(nu_protocol::Value::List { vals, .. }) => Some(vals.len()),
            _ => None,
        })
    }

    fn typed_fixed_array_slice_bounds(
        cmd_name: &str,
        count: usize,
        array_len: usize,
    ) -> Result<(usize, usize), CompileError> {
        let (start, len) = match cmd_name {
            "take" | "first" => (0, count.min(array_len)),
            "skip" => {
                let start = count.min(array_len);
                (start, array_len.saturating_sub(start))
            }
            "drop" => (0, array_len.saturating_sub(count.min(array_len))),
            "last" => {
                let len = count.min(array_len);
                (array_len.saturating_sub(len), len)
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "unsupported typed fixed-array slice command '{cmd_name}'"
                )));
            }
        };
        Ok((start, len))
    }

    fn lower_typed_fixed_array_count_slice(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        input_reg: RegId,
        mut input_vreg: VReg,
        input_meta: &RegMetadata,
        count: usize,
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
        let Some((elem_ty, array_len)) = Self::aggregate_call_value_type(&base_runtime_ty)
            .and_then(|ty| match ty {
                MirType::Array { elem, len } => Some((elem.as_ref().clone(), *len)),
                _ => None,
            })
        else {
            return Ok(false);
        };

        let (slice_start, slice_len) =
            Self::typed_fixed_array_slice_bounds(cmd_name, count, array_len)?;
        if slice_len == 0 {
            self.lower_compile_time_list_transform_result(
                src_dst,
                &nu_protocol::Value::list(Vec::new(), Span::unknown()),
            )?;
            return Ok(true);
        }

        if !matches!(base_runtime_ty, MirType::Ptr { .. })
            && Self::aggregate_call_value_type(&base_runtime_ty).is_some()
        {
            input_vreg = self.materialized_metadata_aggregate_vreg(input_reg, input_vreg)?;
            base_runtime_ty = self
                .typed_value_runtime_type(input_reg, input_vreg)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} requires typed fixed-array input in eBPF"
                    ))
                })?;
        }

        let MirType::Ptr { address_space, .. } = base_runtime_ty else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires typed fixed-array pointer input in eBPF"
            )));
        };

        let elem_size = elem_ty.size();
        let byte_offset = slice_start.checked_mul(elem_size).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} typed fixed-array slice offset overflowed in eBPF"
            ))
        })?;
        let byte_offset = i64::try_from(byte_offset).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} typed fixed-array slice offset is too large for eBPF"
            ))
        })?;

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let out_ty = MirType::Array {
            elem: Box::new(elem_ty),
            len: slice_len,
        };
        self.vreg_type_hints.insert(
            result_vreg,
            MirType::Ptr {
                pointee: Box::new(out_ty.clone()),
                address_space,
            },
        );

        if byte_offset == 0 {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::VReg(input_vreg),
            });
        } else {
            self.emit(MirInst::BinOp {
                dst: result_vreg,
                op: BinOpKind::Add,
                lhs: MirValue::VReg(input_vreg),
                rhs: MirValue::Const(byte_offset),
            });
        }

        let constant_value = match &input_meta.constant_value {
            Some(nu_protocol::Value::List { vals, .. }) => Some(nu_protocol::Value::list(
                vals.iter()
                    .skip(slice_start)
                    .take(slice_len)
                    .cloned()
                    .collect(),
                Span::unknown(),
            )),
            _ => None,
        };
        let annotated_semantics = match &input_meta.annotated_semantics {
            Some(AnnotatedValueSemantics::FixedArray { elem, .. }) => {
                Some(AnnotatedValueSemantics::FixedArray {
                    elem: elem.clone(),
                    len: slice_len,
                })
            }
            _ => None,
        };

        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(out_ty);
        out_meta.root_ctx_field = input_meta.root_ctx_field.clone();
        out_meta.constant_value = constant_value;
        out_meta.annotated_semantics = annotated_semantics;
        Ok(true)
    }

    pub(super) fn lower_stack_list_first_or_last_scalar(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let mut input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !matches!(cmd_name, "first" | "last") {
            return Err(CompileError::UnsupportedInstruction(format!(
                "unsupported stack list scalar command '{cmd_name}'"
            )));
        }
        if !self.named_flags.is_empty()
            || !self.named_args.is_empty()
            || !self.positional_args.is_empty()
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} does not accept arguments in scalar eBPF list lowering"
            )));
        }

        let Some(input_reg) = input_reg else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a pipeline input in eBPF"
            )));
        };
        let input_meta = self.get_metadata(input_reg).cloned();

        if let Some(projected) = self
            .compile_time_only_list_builder_values(input_reg, input_vreg)
            .map(|values| {
                if values.is_empty() {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} requires a non-empty compile-time known list in eBPF"
                    )));
                }
                Ok(if cmd_name == "first" {
                    values[0].clone()
                } else {
                    values[values.len() - 1].clone()
                })
            })
            .transpose()?
        {
            self.lower_compile_time_list_transform_result(src_dst, &projected)?;
        } else if input_meta
            .as_ref()
            .and_then(|meta| meta.list_buffer)
            .is_some()
        {
            let input_meta = input_meta.expect("checked stack-list metadata");
            let Some(known_len) = Self::numeric_list_known_len(&input_meta) else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires a stack-backed numeric list with known non-empty length in eBPF"
                )));
            };
            if known_len == 0 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires a non-empty stack-backed numeric list in eBPF"
                )));
            }

            let result_vreg = if src_dst_had_value {
                self.assign_fresh_vreg(src_dst)
            } else {
                dst_vreg
            };

            let idx = if cmd_name == "first" {
                MirValue::Const(0)
            } else {
                let len_vreg = self.func.alloc_vreg();
                let idx_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListLen {
                    dst: len_vreg,
                    list: input_vreg,
                });
                self.vreg_type_hints.insert(len_vreg, MirType::U64);
                self.emit(MirInst::BinOp {
                    dst: idx_vreg,
                    op: BinOpKind::Sub,
                    lhs: MirValue::VReg(len_vreg),
                    rhs: MirValue::Const(1),
                });
                self.vreg_type_hints.insert(idx_vreg, MirType::U64);
                MirValue::VReg(idx_vreg)
            };

            self.emit(MirInst::ListGet {
                dst: result_vreg,
                list: input_vreg,
                idx,
            });
            self.reset_call_result_metadata(src_dst);
            let out_meta = self.get_or_create_metadata(src_dst);
            out_meta.field_type = Some(MirType::I64);
            out_meta.constant_value = match &input_meta.constant_value {
                Some(nu_protocol::Value::List { vals, .. }) => {
                    if cmd_name == "first" {
                        vals.first().cloned()
                    } else {
                        vals.last().cloned()
                    }
                }
                _ => None,
            };
            self.vreg_type_hints.insert(result_vreg, MirType::I64);
        } else if let Some(mut base_runtime_ty) =
            self.typed_value_runtime_type(input_reg, input_vreg)
            && let Some(array_len) =
                Self::aggregate_call_value_type(&base_runtime_ty).and_then(|ty| match ty {
                    MirType::Array { len, .. } => Some(*len),
                    _ => None,
                })
        {
            if array_len == 0 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires a non-empty typed fixed-array input in eBPF"
                )));
            }

            let idx_usize = if cmd_name == "first" {
                0
            } else {
                array_len.saturating_sub(1)
            };
            let idx_i64 = i64::try_from(idx_usize).map_err(|_| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} typed fixed-array index is too large for eBPF"
                ))
            })?;

            let result_vreg = if src_dst_had_value {
                self.assign_fresh_vreg(src_dst)
            } else {
                dst_vreg
            };

            if !matches!(base_runtime_ty, MirType::Ptr { .. })
                && Self::aggregate_call_value_type(&base_runtime_ty).is_some()
            {
                input_vreg = self.materialized_metadata_aggregate_vreg(input_reg, input_vreg)?;
                base_runtime_ty = self
                    .typed_value_runtime_type(input_reg, input_vreg)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "{cmd_name} requires typed fixed-array input in eBPF"
                        ))
                    })?;
            }

            let projected_constant =
                input_meta
                    .as_ref()
                    .and_then(|meta| match &meta.constant_value {
                        Some(nu_protocol::Value::List { vals, .. }) => vals.get(idx_usize).cloned(),
                        _ => None,
                    });
            let projected_semantics =
                input_meta
                    .as_ref()
                    .and_then(|meta| match &meta.annotated_semantics {
                        Some(AnnotatedValueSemantics::FixedArray { elem, .. }) => {
                            Some((**elem).clone())
                        }
                        _ => None,
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
                let root_ctx_field = self
                    .get_metadata(input_reg)
                    .and_then(|meta| meta.root_ctx_field.clone());
                self.lower_dynamic_typed_numeric_get(
                    src_dst,
                    input_vreg,
                    &base_runtime_ty,
                    MirValue::Const(idx_i64),
                    root_ctx_field.as_ref(),
                )?;
                let out_meta = self.get_or_create_metadata(src_dst);
                out_meta.constant_value = projected_constant;
                out_meta.annotated_semantics = projected_semantics;
            }
        } else {
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
        }

        Ok(())
    }

    pub(super) fn lower_stack_list_take_skip_or_drop(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} does not accept named flags or arguments in eBPF"
            )));
        }

        let raw_count = match cmd_name {
            "skip" | "drop" => {
                if self.positional_args.len() > 1 {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} accepts at most one positional count argument in eBPF"
                    )));
                }
                if let Some((_, count_reg)) = self.positional_args.first() {
                    self.get_metadata(*count_reg)
                        .and_then(|m| m.literal_int)
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(format!(
                                "{cmd_name} count must be a compile-time integer literal in eBPF"
                            ))
                        })?
                } else {
                    1
                }
            }
            "take" | "first" => {
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        format!(
                            "{cmd_name} requires exactly one positional count argument in eBPF"
                        )
                        .into(),
                    ));
                }
                let (_, count_reg) = self.positional_args[0];
                self.get_metadata(count_reg)
                    .and_then(|m| m.literal_int)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "{cmd_name} count must be a compile-time integer literal in eBPF"
                        ))
                    })?
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "unsupported stack list slice command '{cmd_name}'"
                )));
            }
        };

        if raw_count < 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} count must be non-negative in eBPF"
            )));
        }
        let count = usize::try_from(raw_count).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} count is too large for eBPF list lowering"
            ))
        })?;

        if let Some(values) = input_reg.and_then(|reg| {
            self.compile_time_only_list_builder_values(reg, input_vreg)
                .map(|values| values.to_vec())
        }) {
            let vals = match cmd_name {
                "take" | "first" => values.into_iter().take(count).collect::<Vec<_>>(),
                "skip" => values.into_iter().skip(count).collect::<Vec<_>>(),
                "drop" => {
                    let keep_len = values.len().saturating_sub(count);
                    values.into_iter().take(keep_len).collect::<Vec<_>>()
                }
                _ => unreachable!("validated stack list slice command"),
            };
            self.lower_compile_time_list_transform_result(
                src_dst,
                &nu_protocol::Value::list(vals, Span::unknown()),
            )?;
            return Ok(());
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires a pipeline input with tracked metadata in eBPF"
                ))
            })?;
        if let Some(input_reg) = input_reg
            && self.lower_typed_fixed_array_count_slice(
                cmd_name,
                src_dst,
                dst_vreg,
                src_dst_had_value,
                input_reg,
                input_vreg,
                &input_meta,
                count,
            )?
        {
            return Ok(());
        }
        let Some((_input_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a stack-backed list input in eBPF"
            )));
        };

        let (source_start, source_end, out_max_len, guard_tail_drop) = match cmd_name {
            "take" | "first" => {
                let take_count = count.min(max_len);
                (0, take_count, take_count, 0)
            }
            "skip" => {
                let skip_count = count.min(max_len);
                (skip_count, max_len, max_len.saturating_sub(skip_count), 0)
            }
            "drop" => {
                let drop_count = count.min(max_len);
                let out_max_len = max_len.saturating_sub(drop_count);
                (0, out_max_len, out_max_len, drop_count)
            }
            _ => unreachable!("validated stack list slice command"),
        };
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, out_max_len);

        if source_start < source_end {
            let len_vreg = self.func.alloc_vreg();
            self.emit(MirInst::ListLen {
                dst: len_vreg,
                list: input_vreg,
            });
            self.vreg_type_hints.insert(len_vreg, MirType::U64);

            let continuation_block = self.func.alloc_block();
            for source_index in source_start..source_end {
                let copy_block = self.func.alloc_block();
                let next_block = if source_index + 1 == source_end {
                    continuation_block
                } else {
                    self.func.alloc_block()
                };

                let cond_vreg = self.func.alloc_vreg();
                let guard_index = source_index.saturating_add(guard_tail_drop);
                self.emit(MirInst::BinOp {
                    dst: cond_vreg,
                    op: BinOpKind::Lt,
                    lhs: MirValue::Const(guard_index as i64),
                    rhs: MirValue::VReg(len_vreg),
                });
                self.vreg_type_hints.insert(cond_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: cond_vreg,
                    if_true: copy_block,
                    if_false: next_block,
                });

                self.current_block = copy_block;
                let item_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListGet {
                    dst: item_vreg,
                    list: input_vreg,
                    idx: MirValue::Const(source_index as i64),
                });
                self.vreg_type_hints.insert(item_vreg, MirType::I64);
                self.emit(MirInst::ListPush {
                    list: result_vreg,
                    item: item_vreg,
                });
                self.terminate(MirInst::Jump { target: next_block });

                self.current_block = next_block;
            }
        }

        let known_len = Self::numeric_list_known_len(&input_meta).map(|known_len| match cmd_name {
            "take" | "first" => known_len.min(count).min(out_max_len),
            "skip" | "drop" => known_len.saturating_sub(count).min(out_max_len),
            _ => unreachable!("validated stack list slice command"),
        });
        let constant_value = match input_meta.constant_value {
            Some(nu_protocol::Value::List { vals, .. }) => {
                let vals = match cmd_name {
                    "take" | "first" => vals.into_iter().take(count).collect::<Vec<_>>(),
                    "skip" => vals.into_iter().skip(count).collect::<Vec<_>>(),
                    "drop" => {
                        let keep_len = vals.len().saturating_sub(count);
                        vals.into_iter().take(keep_len).collect::<Vec<_>>()
                    }
                    _ => unreachable!("validated stack list slice command"),
                };
                Some(nu_protocol::Value::list(vals, Span::unknown()))
            }
            _ => None,
        };

        self.install_stack_numeric_list_result_metadata(
            src_dst,
            out_slot,
            out_ty,
            out_max_len,
            known_len,
        );
        if let Some(value) = constant_value {
            self.get_or_create_metadata(src_dst).constant_value = Some(value);
        }
        Ok(())
    }

    pub(super) fn lower_stack_list_reverse(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !self.named_flags.is_empty()
            || !self.named_args.is_empty()
            || !self.positional_args.is_empty()
        {
            return Err(CompileError::UnsupportedInstruction(
                "reverse does not accept arguments in eBPF".into(),
            ));
        }

        if let Some(mut values) = input_reg.and_then(|reg| {
            self.compile_time_only_list_builder_values(reg, input_vreg)
                .map(|values| values.to_vec())
        }) {
            values.reverse();
            self.lower_compile_time_list_transform_result(
                src_dst,
                &nu_protocol::Value::list(values, Span::unknown()),
            )?;
            return Ok(());
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "reverse requires a pipeline input with tracked metadata in eBPF".into(),
                )
            })?;
        let Some((_input_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(
                "reverse requires a stack-backed list input in eBPF".into(),
            ));
        };

        let result_vreg = if self.pipeline_input.is_none() && src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, max_len);

        if max_len > 0 {
            let len_vreg = self.func.alloc_vreg();
            self.emit(MirInst::ListLen {
                dst: len_vreg,
                list: input_vreg,
            });
            self.vreg_type_hints.insert(len_vreg, MirType::U64);

            let continuation_block = self.func.alloc_block();
            for output_index in 0..max_len {
                let source_index = max_len - 1 - output_index;
                let copy_block = self.func.alloc_block();
                let next_block = if output_index + 1 == max_len {
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
                let item_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListGet {
                    dst: item_vreg,
                    list: input_vreg,
                    idx: MirValue::Const(source_index as i64),
                });
                self.vreg_type_hints.insert(item_vreg, MirType::I64);
                self.emit(MirInst::ListPush {
                    list: result_vreg,
                    item: item_vreg,
                });
                self.terminate(MirInst::Jump { target: next_block });

                self.current_block = next_block;
            }
        }

        let known_len = Self::numeric_list_known_len(&input_meta).map(|len| len.min(max_len));
        let constant_value = match input_meta.constant_value {
            Some(nu_protocol::Value::List { mut vals, .. }) => {
                vals.reverse();
                Some(nu_protocol::Value::list(vals, Span::unknown()))
            }
            _ => None,
        };

        self.install_stack_numeric_list_result_metadata(
            src_dst, out_slot, out_ty, max_len, known_len,
        );
        if let Some(value) = constant_value {
            self.get_or_create_metadata(src_dst).constant_value = Some(value);
        }
        Ok(())
    }

    pub(super) fn lower_stack_list_last_count(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !self.named_flags.is_empty()
            || !self.named_args.is_empty()
            || self.positional_args.len() != 1
        {
            return Err(CompileError::UnsupportedInstruction(
                "last requires exactly one positional count argument in eBPF".into(),
            ));
        }

        let (_, count_reg) = self.positional_args[0];
        let raw_count = self
            .get_metadata(count_reg)
            .and_then(|m| m.literal_int)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "last count must be a compile-time integer literal in eBPF".into(),
                )
            })?;
        if raw_count < 0 {
            return Err(CompileError::UnsupportedInstruction(
                "last count must be non-negative in eBPF".into(),
            ));
        }
        let count = usize::try_from(raw_count).map_err(|_| {
            CompileError::UnsupportedInstruction(
                "last count is too large for eBPF list lowering".into(),
            )
        })?;

        if let Some(values) = input_reg.and_then(|reg| {
            self.compile_time_only_list_builder_values(reg, input_vreg)
                .map(|values| values.to_vec())
        }) {
            let start = values.len().saturating_sub(count);
            self.lower_compile_time_list_transform_result(
                src_dst,
                &nu_protocol::Value::list(
                    values.into_iter().skip(start).collect::<Vec<_>>(),
                    Span::unknown(),
                ),
            )?;
            return Ok(());
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "last requires a stack-backed list input in eBPF".into(),
                )
            })?;
        if let Some(input_reg) = input_reg
            && self.lower_typed_fixed_array_count_slice(
                "last",
                src_dst,
                dst_vreg,
                src_dst_had_value,
                input_reg,
                input_vreg,
                &input_meta,
                count,
            )?
        {
            return Ok(());
        }
        let Some((_input_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(
                "last requires a stack-backed list input in eBPF".into(),
            ));
        };

        let out_max_len = count.min(max_len);
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let temp_vreg = self.func.alloc_vreg();
        let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, out_max_len);
        self.create_stack_numeric_list_result(temp_vreg, out_max_len);

        if max_len > 0 && out_max_len > 0 {
            let input_len_vreg = self.func.alloc_vreg();
            self.emit(MirInst::ListLen {
                dst: input_len_vreg,
                list: input_vreg,
            });
            self.vreg_type_hints.insert(input_len_vreg, MirType::U64);

            let reverse_block = self.func.alloc_block();
            for source_index in (0..max_len).rev() {
                let capacity_block = self.func.alloc_block();
                let push_block = self.func.alloc_block();
                let next_block = if source_index == 0 {
                    reverse_block
                } else {
                    self.func.alloc_block()
                };

                let in_bounds_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: in_bounds_vreg,
                    op: BinOpKind::Lt,
                    lhs: MirValue::Const(source_index as i64),
                    rhs: MirValue::VReg(input_len_vreg),
                });
                self.vreg_type_hints.insert(in_bounds_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: in_bounds_vreg,
                    if_true: capacity_block,
                    if_false: next_block,
                });

                self.current_block = capacity_block;
                let temp_len_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListLen {
                    dst: temp_len_vreg,
                    list: temp_vreg,
                });
                self.vreg_type_hints.insert(temp_len_vreg, MirType::U64);
                let has_capacity_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: has_capacity_vreg,
                    op: BinOpKind::Lt,
                    lhs: MirValue::VReg(temp_len_vreg),
                    rhs: MirValue::Const(out_max_len as i64),
                });
                self.vreg_type_hints
                    .insert(has_capacity_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: has_capacity_vreg,
                    if_true: push_block,
                    if_false: next_block,
                });

                self.current_block = push_block;
                let item_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListGet {
                    dst: item_vreg,
                    list: input_vreg,
                    idx: MirValue::Const(source_index as i64),
                });
                self.vreg_type_hints.insert(item_vreg, MirType::I64);
                self.emit(MirInst::ListPush {
                    list: temp_vreg,
                    item: item_vreg,
                });
                self.terminate(MirInst::Jump { target: next_block });

                self.current_block = next_block;
            }

            let temp_len_vreg = self.func.alloc_vreg();
            self.emit(MirInst::ListLen {
                dst: temp_len_vreg,
                list: temp_vreg,
            });
            self.vreg_type_hints.insert(temp_len_vreg, MirType::U64);

            let continuation_block = self.func.alloc_block();
            for temp_index in (0..out_max_len).rev() {
                let copy_block = self.func.alloc_block();
                let next_block = if temp_index == 0 {
                    continuation_block
                } else {
                    self.func.alloc_block()
                };

                let in_bounds_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: in_bounds_vreg,
                    op: BinOpKind::Lt,
                    lhs: MirValue::Const(temp_index as i64),
                    rhs: MirValue::VReg(temp_len_vreg),
                });
                self.vreg_type_hints.insert(in_bounds_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: in_bounds_vreg,
                    if_true: copy_block,
                    if_false: next_block,
                });

                self.current_block = copy_block;
                let item_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListGet {
                    dst: item_vreg,
                    list: temp_vreg,
                    idx: MirValue::Const(temp_index as i64),
                });
                self.vreg_type_hints.insert(item_vreg, MirType::I64);
                self.emit(MirInst::ListPush {
                    list: result_vreg,
                    item: item_vreg,
                });
                self.terminate(MirInst::Jump { target: next_block });

                self.current_block = next_block;
            }
            self.current_block = continuation_block;
        }

        let known_len = Self::numeric_list_known_len(&input_meta).map(|len| len.min(count));
        let constant_value = match input_meta.constant_value {
            Some(nu_protocol::Value::List { vals, .. }) => {
                let start = vals.len().saturating_sub(count);
                Some(nu_protocol::Value::list(
                    vals.into_iter().skip(start).collect::<Vec<_>>(),
                    Span::unknown(),
                ))
            }
            _ => None,
        };

        self.install_stack_numeric_list_result_metadata(
            src_dst,
            out_slot,
            out_ty,
            out_max_len,
            known_len,
        );
        if let Some(value) = constant_value {
            self.get_or_create_metadata(src_dst).constant_value = Some(value);
        }
        Ok(())
    }

    pub(super) fn install_stack_numeric_list_result_metadata(
        &mut self,
        src_dst: RegId,
        out_slot: StackSlotId,
        out_ty: MirType,
        max_len: usize,
        known_len: Option<usize>,
    ) {
        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.list_buffer = Some((out_slot, max_len));
        out_meta.field_type = Some(out_ty);
        out_meta.annotated_semantics =
            Some(AnnotatedValueSemantics::NumericList { max_len, known_len });
    }
}
