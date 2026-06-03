use super::*;
use crate::compiler::mir::UnaryOpKind;
use std::cmp::Ordering;

impl<'a> HirToMirLowering<'a> {
    fn math_integer_result_for_rounding_command(
        cmd_name: &str,
        value: nu_protocol::Value,
        list_index: Option<usize>,
    ) -> Result<nu_protocol::Value, CompileError> {
        match value {
            nu_protocol::Value::Int { .. } => Ok(value),
            nu_protocol::Value::Float { val, .. } => {
                let rounded = match cmd_name {
                    "math ceil" => val.ceil(),
                    "math floor" => val.floor(),
                    "math round" => val.round(),
                    _ => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "unsupported integer rounding command {cmd_name}"
                        )));
                    }
                };
                let val = Self::checked_compile_time_float_to_i64(cmd_name, rounded, list_index)?;
                Ok(nu_protocol::Value::int(val, nu_protocol::Span::unknown()))
            }
            other => Err(CompileError::UnsupportedInstruction(match list_index {
                Some(index) => format!(
                    "{cmd_name} requires integer or compile-time float list items in eBPF; item {index} has type {}",
                    other.get_type()
                ),
                None => format!(
                    "{cmd_name} currently supports integer input and compile-time float input only in eBPF; input has type {}",
                    other.get_type()
                ),
            })),
        }
    }

    fn checked_compile_time_float_to_i64(
        cmd_name: &str,
        value: f64,
        list_index: Option<usize>,
    ) -> Result<i64, CompileError> {
        const I64_MIN_F64: f64 = -9_223_372_036_854_775_808.0;
        const I64_MAX_PLUS_ONE_F64: f64 = 9_223_372_036_854_775_808.0;

        if !value.is_finite() || !(I64_MIN_F64..I64_MAX_PLUS_ONE_F64).contains(&value) {
            return Err(CompileError::UnsupportedInstruction(match list_index {
                Some(index) => format!(
                    "{cmd_name} compile-time float list item {index} result {value} cannot be represented as an i64 in eBPF"
                ),
                None => format!(
                    "{cmd_name} compile-time float result {value} cannot be represented as an i64 in eBPF"
                ),
            }));
        }

        Ok(value as i64)
    }

    pub(super) fn mir_type_is_integer(ty: &MirType) -> bool {
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
        )
    }

    pub(in crate::compiler::ir_to_mir) fn lower_integer_identity_math(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const MAX_IDENTITY_STACK_LIST_CAPACITY: usize = 60;

        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !self.named_flags.is_empty()
            || !self.named_args.is_empty()
            || !self.positional_args.is_empty()
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} does not accept arguments in eBPF"
            )));
        }

        let input_reg = input_reg.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires integer or integer-list input in eBPF"
            ))
        })?;
        let input_meta = self.get_metadata(input_reg).cloned();

        if let Some(nu_protocol::Value::List { vals, .. }) = input_meta
            .as_ref()
            .and_then(|meta| meta.constant_value.clone())
        {
            if vals.len() > MAX_IDENTITY_STACK_LIST_CAPACITY {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} output exceeds stack-backed numeric list capacity {MAX_IDENTITY_STACK_LIST_CAPACITY} in eBPF"
                )));
            }

            let vals = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    Self::math_integer_result_for_rounding_command(cmd_name, value, Some(index))
                })
                .collect::<Result<Vec<_>, _>>()?;

            self.reset_call_result_metadata(src_dst);
            self.lower_constant_value(
                src_dst,
                &nu_protocol::Value::list(vals, nu_protocol::Span::unknown()),
            )?;
            return Ok(());
        }

        if input_meta
            .as_ref()
            .is_some_and(|meta| meta.list_buffer.is_some())
        {
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
            return Ok(());
        }

        if let Some(value) = input_meta
            .as_ref()
            .and_then(|meta| meta.constant_value.clone())
        {
            let value = Self::math_integer_result_for_rounding_command(cmd_name, value, None)?;
            let nu_protocol::Value::Int { val, .. } = value else {
                unreachable!("math rounding helper returns only integer values")
            };

            let result_vreg = if src_dst_had_value {
                self.assign_fresh_vreg(src_dst)
            } else {
                dst_vreg
            };
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(val),
            });
            self.reset_call_result_metadata(src_dst);
            let out_meta = self.get_or_create_metadata(src_dst);
            out_meta.field_type = Some(MirType::I64);
            out_meta.constant_value =
                Some(nu_protocol::Value::int(val, nu_protocol::Span::unknown()));
            out_meta.literal_int = Some(val);
            self.vreg_type_hints.insert(result_vreg, MirType::I64);
            return Ok(());
        }

        let input_ty = input_meta
            .as_ref()
            .and_then(|meta| meta.field_type.as_ref())
            .or_else(|| self.vreg_type_hints.get(&input_vreg))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires compiler-known integer input in eBPF"
                ))
            })?;
        if !Self::mir_type_is_integer(input_ty) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} currently supports integer input only in eBPF; input has MIR type {input_ty:?}"
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
        Ok(())
    }

    pub(in crate::compiler::ir_to_mir) fn lower_math_abs(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const MAX_ABS_STACK_LIST_CAPACITY: usize = 60;

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
                "math abs does not accept arguments in eBPF".into(),
            ));
        }

        let input_meta = input_reg.and_then(|reg| self.get_metadata(reg)).cloned();

        if let Some(nu_protocol::Value::List { vals, .. }) = input_meta
            .as_ref()
            .and_then(|meta| meta.constant_value.clone())
        {
            if vals.len() > MAX_ABS_STACK_LIST_CAPACITY {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "math abs output exceeds stack-backed numeric list capacity {MAX_ABS_STACK_LIST_CAPACITY} in eBPF"
                )));
            }

            let mut output = Vec::with_capacity(vals.len());
            for (index, item) in vals.into_iter().enumerate() {
                let val = match item {
                    nu_protocol::Value::Int { val, .. } => val,
                    other => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "math abs requires integer list items in eBPF; item {index} has type {}",
                            other.get_type()
                        )));
                    }
                };
                output.push(nu_protocol::Value::int(
                    val.wrapping_abs(),
                    nu_protocol::Span::unknown(),
                ));
            }

            self.reset_call_result_metadata(src_dst);
            self.lower_constant_value(
                src_dst,
                &nu_protocol::Value::list(output, nu_protocol::Span::unknown()),
            )?;
            return Ok(());
        }

        if let Some(input_meta) = input_meta.as_ref()
            && let Some((_input_slot, max_len)) = input_meta.list_buffer
        {
            let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, max_len);

            if max_len > 0 {
                let len_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListLen {
                    dst: len_vreg,
                    list: input_vreg,
                });
                self.vreg_type_hints.insert(len_vreg, MirType::U64);

                let continuation_block = self.func.alloc_block();
                for index in 0..max_len {
                    let load_block = self.func.alloc_block();
                    let negative_block = self.func.alloc_block();
                    let non_negative_block = self.func.alloc_block();
                    let next_block = if index + 1 == max_len {
                        continuation_block
                    } else {
                        self.func.alloc_block()
                    };

                    let in_bounds_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::BinOp {
                        dst: in_bounds_vreg,
                        op: BinOpKind::Lt,
                        lhs: MirValue::Const(index as i64),
                        rhs: MirValue::VReg(len_vreg),
                    });
                    self.vreg_type_hints.insert(in_bounds_vreg, MirType::Bool);
                    self.terminate(MirInst::Branch {
                        cond: in_bounds_vreg,
                        if_true: load_block,
                        if_false: next_block,
                    });

                    self.current_block = load_block;
                    let item_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::ListGet {
                        dst: item_vreg,
                        list: input_vreg,
                        idx: MirValue::Const(index as i64),
                    });
                    self.vreg_type_hints.insert(item_vreg, MirType::I64);

                    let is_negative_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::BinOp {
                        dst: is_negative_vreg,
                        op: BinOpKind::Lt,
                        lhs: MirValue::VReg(item_vreg),
                        rhs: MirValue::Const(0),
                    });
                    self.vreg_type_hints.insert(is_negative_vreg, MirType::Bool);
                    self.terminate(MirInst::Branch {
                        cond: is_negative_vreg,
                        if_true: negative_block,
                        if_false: non_negative_block,
                    });

                    self.current_block = negative_block;
                    let abs_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::UnaryOp {
                        dst: abs_vreg,
                        op: UnaryOpKind::Neg,
                        src: MirValue::VReg(item_vreg),
                    });
                    self.vreg_type_hints.insert(abs_vreg, MirType::I64);
                    self.emit(MirInst::ListPush {
                        list: result_vreg,
                        item: abs_vreg,
                    });
                    self.terminate(MirInst::Jump { target: next_block });

                    self.current_block = non_negative_block;
                    self.emit(MirInst::ListPush {
                        list: result_vreg,
                        item: item_vreg,
                    });
                    self.terminate(MirInst::Jump { target: next_block });

                    self.current_block = next_block;
                }
            }

            let known_len = Self::numeric_list_known_len(input_meta).map(|len| len.min(max_len));
            self.install_stack_numeric_list_result_metadata(
                src_dst, out_slot, out_ty, max_len, known_len,
            );
            return Ok(());
        }

        if let Some(input) = input_meta.as_ref().and_then(|meta| {
            meta.literal_int
                .or_else(|| match meta.constant_value.as_ref() {
                    Some(nu_protocol::Value::Int { val, .. }) => Some(*val),
                    _ => None,
                })
        }) {
            let output = input.wrapping_abs();

            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(output),
            });
            self.reset_call_result_metadata(src_dst);
            let out_meta = self.get_or_create_metadata(src_dst);
            out_meta.field_type = Some(MirType::I64);
            out_meta.constant_value = Some(nu_protocol::Value::int(
                output,
                nu_protocol::Span::unknown(),
            ));
            out_meta.literal_int = Some(output);
            self.vreg_type_hints.insert(result_vreg, MirType::I64);
            return Ok(());
        }

        let input_ty = input_meta
            .as_ref()
            .and_then(|meta| meta.field_type.clone())
            .or_else(|| self.vreg_type_hints.get(&input_vreg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "math abs requires integer, integer-list, or stack-backed numeric-list input in eBPF"
                        .into(),
                )
            })?;
        if !Self::mir_type_is_integer(&input_ty) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "math abs currently supports integer input only in eBPF; input has MIR type {input_ty:?}"
            )));
        }

        let unsigned_input = matches!(
            &input_ty,
            MirType::U8 | MirType::U16 | MirType::U32 | MirType::U64
        );
        let output_ty = if unsigned_input {
            input_ty.clone()
        } else {
            MirType::I64
        };

        if unsigned_input {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::VReg(input_vreg),
            });
        } else {
            let negative_block = self.func.alloc_block();
            let non_negative_block = self.func.alloc_block();
            let continuation_block = self.func.alloc_block();
            let is_negative_vreg = self.func.alloc_vreg();
            self.emit(MirInst::BinOp {
                dst: is_negative_vreg,
                op: BinOpKind::Lt,
                lhs: MirValue::VReg(input_vreg),
                rhs: MirValue::Const(0),
            });
            self.vreg_type_hints.insert(is_negative_vreg, MirType::Bool);
            self.terminate(MirInst::Branch {
                cond: is_negative_vreg,
                if_true: negative_block,
                if_false: non_negative_block,
            });

            self.current_block = negative_block;
            self.emit(MirInst::UnaryOp {
                dst: result_vreg,
                op: UnaryOpKind::Neg,
                src: MirValue::VReg(input_vreg),
            });
            self.terminate(MirInst::Jump {
                target: continuation_block,
            });

            self.current_block = non_negative_block;
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::VReg(input_vreg),
            });
            self.terminate(MirInst::Jump {
                target: continuation_block,
            });

            self.current_block = continuation_block;
        }

        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(output_ty.clone());
        self.vreg_type_hints.insert(result_vreg, output_ty);
        Ok(())
    }

    pub(in crate::compiler::ir_to_mir) fn lower_math_mode(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const MAX_MODE_STACK_LIST_CAPACITY: usize = 60;
        const MAX_RUNTIME_MODE_STACK_LIST_CAPACITY: usize = 16;

        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !self.named_flags.is_empty()
            || !self.named_args.is_empty()
            || !self.positional_args.is_empty()
        {
            return Err(CompileError::UnsupportedInstruction(
                "math mode does not accept arguments in eBPF".into(),
            ));
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "math mode requires compile-time known integer-list or stack-backed numeric-list input in eBPF".into(),
                )
            })?;

        if let Some(nu_protocol::Value::List { vals, .. }) = input_meta.constant_value {
            let mut counts = std::collections::BTreeMap::<i64, usize>::new();
            for (index, value) in vals.into_iter().enumerate() {
                let nu_protocol::Value::Int { val, .. } = value else {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "math mode requires integer list items in eBPF; item {index} has type {}",
                        value.get_type()
                    )));
                };
                *counts.entry(val).or_default() += 1;
            }

            let max_count = counts.values().copied().max().unwrap_or(0);
            let modes = counts
                .into_iter()
                .filter_map(|(value, count)| {
                    (count == max_count).then_some(nu_protocol::Value::int(value, Span::unknown()))
                })
                .collect::<Vec<_>>();
            if modes.len() > MAX_MODE_STACK_LIST_CAPACITY {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "math mode output exceeds stack-backed numeric list capacity {MAX_MODE_STACK_LIST_CAPACITY} in eBPF"
                )));
            }

            self.reset_call_result_metadata(src_dst);
            return self
                .lower_constant_value(src_dst, &nu_protocol::Value::list(modes, Span::unknown()));
        }

        let Some((_input_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "math mode requires compile-time known integer-list or stack-backed numeric-list input in eBPF"
            )));
        };
        if max_len > MAX_RUNTIME_MODE_STACK_LIST_CAPACITY {
            return Err(CompileError::UnsupportedInstruction(format!(
                "math mode supports stack-backed numeric lists with capacity <= {MAX_RUNTIME_MODE_STACK_LIST_CAPACITY} in eBPF"
            )));
        }

        self.lower_stack_list_math_mode(
            src_dst,
            dst_vreg,
            src_dst_had_value,
            input_vreg,
            input_meta,
            max_len,
        )
    }

    fn lower_stack_list_math_mode(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        input_vreg: VReg,
        input_meta: RegMetadata,
        max_len: usize,
    ) -> Result<(), CompileError> {
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, max_len);

        if max_len == 0 {
            self.install_stack_numeric_list_result_metadata(
                src_dst,
                out_slot,
                out_ty,
                max_len,
                Some(0),
            );
            return Ok(());
        }

        let sorted_vreg = self.func.alloc_vreg();
        let (sorted_slot, _sorted_ty) = self.create_stack_numeric_list_result(sorted_vreg, max_len);
        let len_vreg = self.func.alloc_vreg();
        self.emit(MirInst::ListLen {
            dst: len_vreg,
            list: input_vreg,
        });
        self.vreg_type_hints.insert(len_vreg, MirType::U64);

        let after_copy_block = self.func.alloc_block();
        for source_index in 0..max_len {
            let copy_block = self.func.alloc_block();
            let next_block = if source_index + 1 == max_len {
                after_copy_block
            } else {
                self.func.alloc_block()
            };

            let in_bounds_vreg = self.func.alloc_vreg();
            self.emit(MirInst::BinOp {
                dst: in_bounds_vreg,
                op: BinOpKind::Lt,
                lhs: MirValue::Const(source_index as i64),
                rhs: MirValue::VReg(len_vreg),
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
                list: input_vreg,
                idx: MirValue::Const(source_index as i64),
            });
            self.vreg_type_hints.insert(item_vreg, MirType::I64);
            self.emit(MirInst::ListPush {
                list: sorted_vreg,
                item: item_vreg,
            });
            self.terminate(MirInst::Jump { target: next_block });

            self.current_block = next_block;
        }
        self.current_block = after_copy_block;

        for pass in 0..max_len {
            for left_index in 0..max_len.saturating_sub(1 + pass) {
                self.emit_stack_list_compare_swap(sorted_slot, left_index, left_index + 1, false);
            }
        }

        let count_slot = self.alloc_u64_math_mode_slot();
        let max_count_slot = self.alloc_u64_math_mode_slot();
        self.emit(MirInst::StoreSlot {
            slot: max_count_slot,
            offset: 0,
            val: MirValue::Const(0),
            ty: MirType::U64,
        });

        let after_max_count_block = self.func.alloc_block();
        for candidate_index in 0..max_len {
            let count_candidate_block = self.func.alloc_block();
            let next_candidate_block = if candidate_index + 1 == max_len {
                after_max_count_block
            } else {
                self.func.alloc_block()
            };

            self.emit_static_index_in_bounds_branch(
                candidate_index,
                len_vreg,
                count_candidate_block,
                next_candidate_block,
            );

            self.current_block = count_candidate_block;
            let candidate_vreg = self.load_sorted_math_mode_item(sorted_slot, candidate_index);
            let after_count_block = self.func.alloc_block();
            self.emit_count_matching_sorted_items(
                sorted_slot,
                max_len,
                len_vreg,
                candidate_vreg,
                count_slot,
                after_count_block,
            );

            let count_vreg = self.load_u64_math_mode_slot(count_slot);
            let max_count_vreg = self.load_u64_math_mode_slot(max_count_slot);
            let is_larger_vreg = self.func.alloc_vreg();
            self.emit(MirInst::BinOp {
                dst: is_larger_vreg,
                op: BinOpKind::Gt,
                lhs: MirValue::VReg(count_vreg),
                rhs: MirValue::VReg(max_count_vreg),
            });
            self.vreg_type_hints.insert(is_larger_vreg, MirType::Bool);
            let update_block = self.func.alloc_block();
            self.terminate(MirInst::Branch {
                cond: is_larger_vreg,
                if_true: update_block,
                if_false: next_candidate_block,
            });

            self.current_block = update_block;
            self.emit(MirInst::StoreSlot {
                slot: max_count_slot,
                offset: 0,
                val: MirValue::VReg(count_vreg),
                ty: MirType::U64,
            });
            self.terminate(MirInst::Jump {
                target: next_candidate_block,
            });

            self.current_block = next_candidate_block;
        }
        self.current_block = after_max_count_block;

        let after_emit_modes_block = self.func.alloc_block();
        for candidate_index in 0..max_len {
            let maybe_unique_block = self.func.alloc_block();
            let next_candidate_block = if candidate_index + 1 == max_len {
                after_emit_modes_block
            } else {
                self.func.alloc_block()
            };

            self.emit_static_index_in_bounds_branch(
                candidate_index,
                len_vreg,
                maybe_unique_block,
                next_candidate_block,
            );

            self.current_block = maybe_unique_block;
            let candidate_vreg = self.load_sorted_math_mode_item(sorted_slot, candidate_index);
            let count_unique_block = self.func.alloc_block();
            if candidate_index == 0 {
                self.terminate(MirInst::Jump {
                    target: count_unique_block,
                });
            } else {
                let previous_vreg =
                    self.load_sorted_math_mode_item(sorted_slot, candidate_index - 1);
                let is_unique_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: is_unique_vreg,
                    op: BinOpKind::Ne,
                    lhs: MirValue::VReg(candidate_vreg),
                    rhs: MirValue::VReg(previous_vreg),
                });
                self.vreg_type_hints.insert(is_unique_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: is_unique_vreg,
                    if_true: count_unique_block,
                    if_false: next_candidate_block,
                });
            }

            self.current_block = count_unique_block;
            let after_count_block = self.func.alloc_block();
            self.emit_count_matching_sorted_items(
                sorted_slot,
                max_len,
                len_vreg,
                candidate_vreg,
                count_slot,
                after_count_block,
            );

            let count_vreg = self.load_u64_math_mode_slot(count_slot);
            let max_count_vreg = self.load_u64_math_mode_slot(max_count_slot);
            let is_mode_vreg = self.func.alloc_vreg();
            self.emit(MirInst::BinOp {
                dst: is_mode_vreg,
                op: BinOpKind::Eq,
                lhs: MirValue::VReg(count_vreg),
                rhs: MirValue::VReg(max_count_vreg),
            });
            self.vreg_type_hints.insert(is_mode_vreg, MirType::Bool);
            let push_block = self.func.alloc_block();
            self.terminate(MirInst::Branch {
                cond: is_mode_vreg,
                if_true: push_block,
                if_false: next_candidate_block,
            });

            self.current_block = push_block;
            self.emit(MirInst::ListPush {
                list: result_vreg,
                item: candidate_vreg,
            });
            self.terminate(MirInst::Jump {
                target: next_candidate_block,
            });

            self.current_block = next_candidate_block;
        }
        self.current_block = after_emit_modes_block;

        let known_len = match Self::numeric_list_known_len(&input_meta) {
            Some(0) => Some(0),
            _ => None,
        };
        self.install_stack_numeric_list_result_metadata(
            src_dst, out_slot, out_ty, max_len, known_len,
        );
        Ok(())
    }

    fn alloc_u64_math_mode_slot(&mut self) -> StackSlotId {
        let slot = self.func.alloc_stack_slot(8, 8, StackSlotKind::Local);
        self.record_stack_slot_type(slot, MirType::U64);
        slot
    }

    fn load_u64_math_mode_slot(&mut self, slot: StackSlotId) -> VReg {
        let value_vreg = self.func.alloc_vreg();
        self.emit(MirInst::LoadSlot {
            dst: value_vreg,
            slot,
            offset: 0,
            ty: MirType::U64,
        });
        self.vreg_type_hints.insert(value_vreg, MirType::U64);
        value_vreg
    }

    fn load_sorted_math_mode_item(&mut self, sorted_slot: StackSlotId, index: usize) -> VReg {
        let item_vreg = self.func.alloc_vreg();
        self.emit(MirInst::LoadSlot {
            dst: item_vreg,
            slot: sorted_slot,
            offset: Self::list_item_offset(index),
            ty: MirType::I64,
        });
        self.vreg_type_hints.insert(item_vreg, MirType::I64);
        item_vreg
    }

    fn emit_static_index_in_bounds_branch(
        &mut self,
        index: usize,
        len_vreg: VReg,
        if_true: BlockId,
        if_false: BlockId,
    ) {
        let in_bounds_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: in_bounds_vreg,
            op: BinOpKind::Lt,
            lhs: MirValue::Const(index as i64),
            rhs: MirValue::VReg(len_vreg),
        });
        self.vreg_type_hints.insert(in_bounds_vreg, MirType::Bool);
        self.terminate(MirInst::Branch {
            cond: in_bounds_vreg,
            if_true,
            if_false,
        });
    }

    fn emit_count_matching_sorted_items(
        &mut self,
        sorted_slot: StackSlotId,
        max_len: usize,
        len_vreg: VReg,
        candidate_vreg: VReg,
        count_slot: StackSlotId,
        continuation_block: BlockId,
    ) {
        self.emit(MirInst::StoreSlot {
            slot: count_slot,
            offset: 0,
            val: MirValue::Const(0),
            ty: MirType::U64,
        });

        for index in 0..max_len {
            let compare_block = self.func.alloc_block();
            let next_block = if index + 1 == max_len {
                continuation_block
            } else {
                self.func.alloc_block()
            };

            self.emit_static_index_in_bounds_branch(index, len_vreg, compare_block, next_block);

            self.current_block = compare_block;
            let item_vreg = self.load_sorted_math_mode_item(sorted_slot, index);
            let matches_vreg = self.func.alloc_vreg();
            self.emit(MirInst::BinOp {
                dst: matches_vreg,
                op: BinOpKind::Eq,
                lhs: MirValue::VReg(item_vreg),
                rhs: MirValue::VReg(candidate_vreg),
            });
            self.vreg_type_hints.insert(matches_vreg, MirType::Bool);
            let increment_block = self.func.alloc_block();
            self.terminate(MirInst::Branch {
                cond: matches_vreg,
                if_true: increment_block,
                if_false: next_block,
            });

            self.current_block = increment_block;
            let current_count_vreg = self.load_u64_math_mode_slot(count_slot);
            let incremented_vreg = self.func.alloc_vreg();
            self.emit(MirInst::BinOp {
                dst: incremented_vreg,
                op: BinOpKind::Add,
                lhs: MirValue::VReg(current_count_vreg),
                rhs: MirValue::Const(1),
            });
            self.vreg_type_hints.insert(incremented_vreg, MirType::U64);
            self.emit(MirInst::StoreSlot {
                slot: count_slot,
                offset: 0,
                val: MirValue::VReg(incremented_vreg),
                ty: MirType::U64,
            });
            self.terminate(MirInst::Jump { target: next_block });

            self.current_block = next_block;
        }
    }

    pub(in crate::compiler::ir_to_mir) fn lower_math_median(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const MAX_MEDIAN_STACK_LIST_LEN: usize = 16;

        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !self.named_flags.is_empty()
            || !self.named_args.is_empty()
            || !self.positional_args.is_empty()
        {
            return Err(CompileError::UnsupportedInstruction(
                "math median does not accept arguments in eBPF".into(),
            ));
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "math median requires compile-time known integer-list or integer/float-list input in eBPF".into(),
                )
            })?;

        if let Some(nu_protocol::Value::List { vals, .. }) = input_meta.constant_value.clone() {
            if vals.is_empty() {
                return Err(CompileError::UnsupportedInstruction(
                    "math median requires a non-empty integer or float list in eBPF".into(),
                ));
            }
            if vals.len() % 2 == 0 {
                return Err(CompileError::UnsupportedInstruction(
                    "math median requires an odd-length integer or float list in eBPF because even-length medians are floats in Nushell".into(),
                ));
            }

            let mut values = Vec::with_capacity(vals.len());
            for (index, value) in vals.into_iter().enumerate() {
                match &value {
                    nu_protocol::Value::Int { .. } => {}
                    nu_protocol::Value::Float { val, .. } if val.is_finite() => {}
                    nu_protocol::Value::Float { val, .. } => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "math median requires finite float list items in eBPF; item {index} is {val}"
                        )));
                    }
                    other => {
                        return Err(CompileError::UnsupportedInstruction(format!(
                            "math median requires integer or float list items in eBPF; item {index} has type {}",
                            other.get_type()
                        )));
                    }
                }
                values.push(value);
            }
            values.sort_by(|lhs, rhs| {
                lhs.partial_cmp(rhs)
                    .expect("median float values are validated as finite")
            });
            let median_value = &values[values.len() / 2];
            let nu_protocol::Value::Int { val: median, .. } = median_value else {
                return Err(CompileError::UnsupportedInstruction(
                    "math median compile-time list median has type float; eBPF supports only integer median results".into(),
                ));
            };
            let median = *median;

            let result_vreg = if src_dst_had_value {
                self.assign_fresh_vreg(src_dst)
            } else {
                dst_vreg
            };
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::Const(median),
            });
            self.reset_call_result_metadata(src_dst);
            let out_meta = self.get_or_create_metadata(src_dst);
            out_meta.field_type = Some(MirType::I64);
            out_meta.literal_int = Some(median);
            out_meta.constant_value = Some(nu_protocol::Value::int(median, Span::unknown()));
            self.vreg_type_hints.insert(result_vreg, MirType::I64);
            return Ok(());
        }

        let Some((_input_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(
                "math median requires compile-time known integer-list or stack-backed numeric-list input in eBPF".into(),
            ));
        };
        let Some(known_len) = Self::numeric_list_known_len(&input_meta) else {
            return Err(CompileError::UnsupportedInstruction(
                "math median requires a stack-backed numeric list with known odd length in eBPF"
                    .into(),
            ));
        };
        if known_len == 0 {
            return Err(CompileError::UnsupportedInstruction(
                "math median requires a non-empty stack-backed numeric list in eBPF".into(),
            ));
        }
        if known_len % 2 == 0 {
            return Err(CompileError::UnsupportedInstruction(
                "math median requires an odd-length stack-backed numeric list in eBPF because even-length medians are floats in Nushell".into(),
            ));
        }
        if known_len > max_len {
            return Err(CompileError::UnsupportedInstruction(format!(
                "math median known length {known_len} exceeds stack-backed numeric list capacity {max_len} in eBPF"
            )));
        }
        if known_len > MAX_MEDIAN_STACK_LIST_LEN {
            return Err(CompileError::UnsupportedInstruction(format!(
                "math median supports stack-backed numeric lists with known odd length <= {MAX_MEDIAN_STACK_LIST_LEN} in eBPF"
            )));
        }

        let sorted_vreg = self.func.alloc_vreg();
        let (sorted_slot, _sorted_ty) =
            self.create_stack_numeric_list_result(sorted_vreg, known_len);
        for source_index in 0..known_len {
            let item_vreg = self.func.alloc_vreg();
            self.emit(MirInst::ListGet {
                dst: item_vreg,
                list: input_vreg,
                idx: MirValue::Const(source_index as i64),
            });
            self.vreg_type_hints.insert(item_vreg, MirType::I64);
            self.emit(MirInst::ListPush {
                list: sorted_vreg,
                item: item_vreg,
            });
        }

        for pass in 0..known_len {
            for left_index in 0..known_len.saturating_sub(1 + pass) {
                self.emit_stack_list_compare_swap(sorted_slot, left_index, left_index + 1, false);
            }
        }

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        self.emit(MirInst::ListGet {
            dst: result_vreg,
            list: sorted_vreg,
            idx: MirValue::Const((known_len / 2) as i64),
        });
        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(MirType::I64);
        self.vreg_type_hints.insert(result_vreg, MirType::I64);
        Ok(())
    }

    pub(in crate::compiler::ir_to_mir) fn lower_stack_list_math_reduce(
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

        if !self.named_flags.is_empty()
            || !self.named_args.is_empty()
            || !self.positional_args.is_empty()
        {
            return Err(CompileError::UnsupportedInstruction(
                format!("{cmd_name} does not accept arguments in eBPF").into(),
            ));
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires a stack-backed numeric list input in eBPF"
                ))
            })?;

        if matches!(cmd_name, "math min" | "math max")
            && let Some(nu_protocol::Value::List { vals, .. }) = input_meta.constant_value.clone()
            && vals
                .iter()
                .any(|value| matches!(value, nu_protocol::Value::Float { .. }))
        {
            return self.lower_compile_time_math_min_max(
                cmd_name,
                src_dst,
                dst_vreg,
                src_dst_had_value,
                vals,
            );
        }

        let Some((_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a stack-backed numeric list input in eBPF"
            )));
        };
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

        let acc_slot = self.func.alloc_stack_slot(8, 8, StackSlotKind::Local);
        self.record_stack_slot_type(acc_slot, MirType::I64);
        let initial_value = match cmd_name {
            "math product" => 1,
            "math sum" => 0,
            "math max" | "math min" => {
                let first_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListGet {
                    dst: first_vreg,
                    list: input_vreg,
                    idx: MirValue::Const(0),
                });
                self.vreg_type_hints.insert(first_vreg, MirType::I64);
                self.emit(MirInst::StoreSlot {
                    slot: acc_slot,
                    offset: 0,
                    val: MirValue::VReg(first_vreg),
                    ty: MirType::I64,
                });
                0
            }
            _ => unreachable!("validated math reducer command"),
        };
        if matches!(cmd_name, "math product" | "math sum") {
            self.emit(MirInst::StoreSlot {
                slot: acc_slot,
                offset: 0,
                val: MirValue::Const(initial_value),
                ty: MirType::I64,
            });
        }

        let len_vreg = self.func.alloc_vreg();
        self.emit(MirInst::ListLen {
            dst: len_vreg,
            list: input_vreg,
        });
        self.vreg_type_hints.insert(len_vreg, MirType::U64);

        let start_index = if matches!(cmd_name, "math max" | "math min") {
            1
        } else {
            0
        };
        let continuation_block = (start_index < max_len).then(|| self.func.alloc_block());
        for i in start_index..max_len {
            let add_block = self.func.alloc_block();
            let next_block = if i + 1 == max_len {
                continuation_block.expect("math reducer loop should have a continuation block")
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
                if_true: add_block,
                if_false: next_block,
            });

            self.current_block = add_block;
            let item_vreg = self.func.alloc_vreg();
            self.emit(MirInst::ListGet {
                dst: item_vreg,
                list: input_vreg,
                idx: MirValue::Const(i as i64),
            });
            self.vreg_type_hints.insert(item_vreg, MirType::I64);

            let current_sum_vreg = self.func.alloc_vreg();
            self.emit(MirInst::LoadSlot {
                dst: current_sum_vreg,
                slot: acc_slot,
                offset: 0,
                ty: MirType::I64,
            });
            self.vreg_type_hints.insert(current_sum_vreg, MirType::I64);

            match cmd_name {
                "math product" | "math sum" => {
                    let next_sum_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::BinOp {
                        dst: next_sum_vreg,
                        op: if cmd_name == "math product" {
                            BinOpKind::Mul
                        } else {
                            BinOpKind::Add
                        },
                        lhs: MirValue::VReg(current_sum_vreg),
                        rhs: MirValue::VReg(item_vreg),
                    });
                    self.vreg_type_hints.insert(next_sum_vreg, MirType::I64);
                    self.emit(MirInst::StoreSlot {
                        slot: acc_slot,
                        offset: 0,
                        val: MirValue::VReg(next_sum_vreg),
                        ty: MirType::I64,
                    });
                    self.terminate(MirInst::Jump { target: next_block });
                }
                "math max" | "math min" => {
                    let update_cond = self.func.alloc_vreg();
                    self.emit(MirInst::BinOp {
                        dst: update_cond,
                        op: if cmd_name == "math max" {
                            BinOpKind::Gt
                        } else {
                            BinOpKind::Lt
                        },
                        lhs: MirValue::VReg(item_vreg),
                        rhs: MirValue::VReg(current_sum_vreg),
                    });
                    self.vreg_type_hints.insert(update_cond, MirType::Bool);
                    let update_block = self.func.alloc_block();
                    self.terminate(MirInst::Branch {
                        cond: update_cond,
                        if_true: update_block,
                        if_false: next_block,
                    });

                    self.current_block = update_block;
                    self.emit(MirInst::StoreSlot {
                        slot: acc_slot,
                        offset: 0,
                        val: MirValue::VReg(item_vreg),
                        ty: MirType::I64,
                    });
                    self.terminate(MirInst::Jump { target: next_block });
                }
                _ => unreachable!("validated math reducer command"),
            }

            self.current_block = next_block;
        }
        if let Some(continuation_block) = continuation_block {
            self.current_block = continuation_block;
        }

        self.emit(MirInst::LoadSlot {
            dst: result_vreg,
            slot: acc_slot,
            offset: 0,
            ty: MirType::I64,
        });

        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(MirType::I64);
        self.vreg_type_hints.insert(result_vreg, MirType::I64);

        if let Some(nu_protocol::Value::List { vals, .. }) = input_meta.constant_value {
            let ints = vals.into_iter().filter_map(|val| match val {
                nu_protocol::Value::Int { val, .. } => Some(val),
                _ => None,
            });
            let result = match cmd_name {
                "math max" => ints.max(),
                "math min" => ints.min(),
                "math product" => Some(ints.product::<i64>()),
                "math sum" => Some(ints.sum::<i64>()),
                _ => unreachable!("validated math reducer command"),
            };
            if let Some(result) = result {
                self.set_reg_constant_value(
                    src_dst,
                    Some(nu_protocol::Value::int(result, Span::unknown())),
                );
            }
        }
        Ok(())
    }

    fn lower_compile_time_math_min_max(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        vals: Vec<nu_protocol::Value>,
    ) -> Result<(), CompileError> {
        let mut selected = None::<nu_protocol::Value>;
        for (index, value) in vals.into_iter().enumerate() {
            match &value {
                nu_protocol::Value::Int { .. } => {}
                nu_protocol::Value::Float { val, .. } if val.is_finite() => {}
                nu_protocol::Value::Float { val, .. } => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} requires finite float list items in eBPF; item {index} is {val}"
                    )));
                }
                other => {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} requires integer or float list items in eBPF; item {index} has type {}",
                        other.get_type()
                    )));
                }
            }

            let should_update = selected.as_ref().is_none_or(|current| {
                let ordering = value
                    .partial_cmp(current)
                    .expect("min/max float values are validated as finite");
                matches!(
                    (cmd_name, ordering),
                    ("math min", Ordering::Less) | ("math max", Ordering::Greater)
                )
            });
            if should_update {
                selected = Some(value);
            }
        }

        let selected = selected.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a non-empty integer or float list in eBPF"
            ))
        })?;
        let nu_protocol::Value::Int { val, .. } = selected else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} compile-time list result has type float; eBPF supports only integer min/max results"
            )));
        };

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        self.emit(MirInst::Copy {
            dst: result_vreg,
            src: MirValue::Const(val),
        });
        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(MirType::I64);
        out_meta.literal_int = Some(val);
        out_meta.constant_value = Some(nu_protocol::Value::int(val, Span::unknown()));
        self.vreg_type_hints.insert(result_vreg, MirType::I64);
        Ok(())
    }
}
