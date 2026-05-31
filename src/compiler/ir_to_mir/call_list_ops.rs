use super::*;
use crate::compiler::mir::AddressSpace;

mod compact;
mod dedupe;
mod math;
mod predicates;
mod sort;

impl<'a> HirToMirLowering<'a> {
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

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "last requires a stack-backed list input in eBPF".into(),
                )
            })?;
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
