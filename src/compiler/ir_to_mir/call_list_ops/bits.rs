use super::*;
use crate::compiler::mir::{BinOpKind, UnaryOpKind};

impl<'a> HirToMirLowering<'a> {
    fn bits_binary_op(cmd_name: &str) -> BinOpKind {
        match cmd_name {
            "bits and" => BinOpKind::And,
            "bits or" => BinOpKind::Or,
            "bits xor" => BinOpKind::Xor,
            _ => unreachable!("validated bits binary command"),
        }
    }

    fn bits_binary_output(cmd_name: &str, lhs: i64, rhs: i64) -> i64 {
        match cmd_name {
            "bits and" => lhs & rhs,
            "bits or" => lhs | rhs,
            "bits xor" => lhs ^ rhs,
            _ => unreachable!("validated bits binary command"),
        }
    }

    fn bits_integer_value_from_metadata(meta: &RegMetadata) -> Option<i64> {
        meta.literal_int
            .or_else(|| match meta.constant_value.as_ref() {
                Some(nu_protocol::Value::Int { val, .. }) => Some(*val),
                _ => None,
            })
    }

    fn validate_bits_integer_operand(
        &self,
        cmd_name: &str,
        role: &str,
        meta: &RegMetadata,
        vreg: VReg,
    ) -> Result<(), CompileError> {
        if Self::bits_integer_value_from_metadata(meta).is_some() {
            return Ok(());
        }

        let ty = meta
            .field_type
            .as_ref()
            .or_else(|| self.vreg_type_hints.get(&vreg))
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires compiler-known integer {role} in eBPF"
                ))
            })?;
        if Self::mir_type_is_integer(ty) {
            Ok(())
        } else {
            Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires integer {role} in eBPF; got MIR type {ty:?}"
            )))
        }
    }

    pub(in crate::compiler::ir_to_mir) fn lower_bits_binary(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const MAX_BITS_STACK_LIST_CAPACITY: usize = 60;

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
            || !self.parser_info_args.is_empty()
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} does not support flags or named arguments in eBPF"
            )));
        }
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires exactly one integer target argument in eBPF"
            )));
        }

        let input_reg = input_reg.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires integer or integer-list pipeline input in eBPF"
            ))
        })?;
        let input_meta = self.get_metadata(input_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires tracked integer or integer-list input in eBPF"
            ))
        })?;

        let (rhs_vreg, rhs_reg) = self.positional_args[0];
        let rhs_meta = self.get_metadata(rhs_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires tracked integer target argument in eBPF"
            ))
        })?;
        self.validate_bits_integer_operand(cmd_name, "target argument", &rhs_meta, rhs_vreg)?;
        let rhs_const = Self::bits_integer_value_from_metadata(&rhs_meta);
        let rhs_value = rhs_const.map_or(MirValue::VReg(rhs_vreg), MirValue::Const);
        let op = Self::bits_binary_op(cmd_name);

        if let Some(nu_protocol::Value::List { vals, .. }) = input_meta.constant_value.clone() {
            if vals.len() > MAX_BITS_STACK_LIST_CAPACITY {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} output exceeds stack-backed numeric list capacity {MAX_BITS_STACK_LIST_CAPACITY} in eBPF"
                )));
            }

            let Some(rhs) = rhs_const else {
                if input_meta.list_buffer.is_some() {
                    // A numeric constant list is also available as a stack-backed
                    // list, so runtime list lowering below can reuse the RHS vreg.
                    return self.lower_bits_binary_runtime_list(
                        cmd_name,
                        src_dst,
                        input_vreg,
                        result_vreg,
                        &input_meta,
                        op,
                        rhs_value,
                    );
                }
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires a compile-time integer target argument for compile-time known list input in eBPF"
                )));
            };
            let output = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let lhs = match value {
                        nu_protocol::Value::Int { val, .. } => val,
                        other => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "{cmd_name} requires integer list items in eBPF; item {index} has type {}",
                                other.get_type()
                            )));
                        }
                    };
                    Ok(nu_protocol::Value::int(
                        Self::bits_binary_output(cmd_name, lhs, rhs),
                        nu_protocol::Span::unknown(),
                    ))
                })
                .collect::<Result<Vec<_>, CompileError>>()?;

            self.reset_call_result_metadata(src_dst);
            self.lower_constant_value(
                src_dst,
                &nu_protocol::Value::list(output, nu_protocol::Span::unknown()),
            )?;
            return Ok(());
        }

        if input_meta.list_buffer.is_some() {
            return self.lower_bits_binary_runtime_list(
                cmd_name,
                src_dst,
                input_vreg,
                result_vreg,
                &input_meta,
                op,
                rhs_value,
            );
        }

        self.validate_bits_integer_operand(cmd_name, "pipeline input", &input_meta, input_vreg)?;
        let lhs_value = Self::bits_integer_value_from_metadata(&input_meta)
            .map_or(MirValue::VReg(input_vreg), MirValue::Const);
        let constant_output = match (
            Self::bits_integer_value_from_metadata(&input_meta),
            rhs_const,
        ) {
            (Some(lhs), Some(rhs)) => Some(Self::bits_binary_output(cmd_name, lhs, rhs)),
            _ => None,
        };

        if let Some(output) = constant_output {
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
        } else {
            self.emit(MirInst::BinOp {
                dst: result_vreg,
                op,
                lhs: lhs_value,
                rhs: rhs_value,
            });
            self.reset_call_result_metadata(src_dst);
            self.get_or_create_metadata(src_dst).field_type = Some(MirType::I64);
        }
        self.vreg_type_hints.insert(result_vreg, MirType::I64);
        Ok(())
    }

    pub(in crate::compiler::ir_to_mir) fn lower_bits_not_signed(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        const MAX_BITS_STACK_LIST_CAPACITY: usize = 60;

        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };

        if !self.positional_args.is_empty()
            || !self.named_args.is_empty()
            || !self.parser_info_args.is_empty()
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} only supports --signed with no arguments in eBPF"
            )));
        }
        if self.named_flags.len() != 1 || self.named_flags[0] != "signed" {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} currently requires --signed in eBPF because the default command is width-masked"
            )));
        }

        let input_reg = input_reg.ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires integer or integer-list pipeline input in eBPF"
            ))
        })?;
        let input_meta = self.get_metadata(input_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires tracked integer or integer-list input in eBPF"
            ))
        })?;

        if let Some(nu_protocol::Value::List { vals, .. }) = input_meta.constant_value.clone() {
            if vals.len() > MAX_BITS_STACK_LIST_CAPACITY {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} output exceeds stack-backed numeric list capacity {MAX_BITS_STACK_LIST_CAPACITY} in eBPF"
                )));
            }

            let output = vals
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let val = match value {
                        nu_protocol::Value::Int { val, .. } => val,
                        other => {
                            return Err(CompileError::UnsupportedInstruction(format!(
                                "{cmd_name} requires integer list items in eBPF; item {index} has type {}",
                                other.get_type()
                            )));
                        }
                    };
                    Ok(nu_protocol::Value::int(
                        !val,
                        nu_protocol::Span::unknown(),
                    ))
                })
                .collect::<Result<Vec<_>, CompileError>>()?;

            self.reset_call_result_metadata(src_dst);
            self.lower_constant_value(
                src_dst,
                &nu_protocol::Value::list(output, nu_protocol::Span::unknown()),
            )?;
            return Ok(());
        }

        if let Some((_input_slot, max_len)) = input_meta.list_buffer {
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
                    let transform_block = self.func.alloc_block();
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
                        if_true: transform_block,
                        if_false: next_block,
                    });

                    self.current_block = transform_block;
                    let item_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::ListGet {
                        dst: item_vreg,
                        list: input_vreg,
                        idx: MirValue::Const(index as i64),
                    });
                    self.vreg_type_hints.insert(item_vreg, MirType::I64);

                    let output_vreg = self.func.alloc_vreg();
                    self.emit(MirInst::UnaryOp {
                        dst: output_vreg,
                        op: UnaryOpKind::BitNot,
                        src: MirValue::VReg(item_vreg),
                    });
                    self.vreg_type_hints.insert(output_vreg, MirType::I64);
                    self.emit(MirInst::ListPush {
                        list: result_vreg,
                        item: output_vreg,
                    });
                    self.terminate(MirInst::Jump { target: next_block });

                    self.current_block = next_block;
                }
            }

            let known_len = Self::numeric_list_known_len(&input_meta).map(|len| len.min(max_len));
            self.install_stack_numeric_list_result_metadata(
                src_dst, out_slot, out_ty, max_len, known_len,
            );
            return Ok(());
        }

        self.validate_bits_integer_operand(cmd_name, "pipeline input", &input_meta, input_vreg)?;
        if let Some(input) = Self::bits_integer_value_from_metadata(&input_meta) {
            let output = !input;
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
        } else {
            self.emit(MirInst::UnaryOp {
                dst: result_vreg,
                op: UnaryOpKind::BitNot,
                src: MirValue::VReg(input_vreg),
            });
            self.reset_call_result_metadata(src_dst);
            self.get_or_create_metadata(src_dst).field_type = Some(MirType::I64);
        }
        self.vreg_type_hints.insert(result_vreg, MirType::I64);
        Ok(())
    }

    fn lower_bits_binary_runtime_list(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        input_vreg: VReg,
        result_vreg: VReg,
        input_meta: &RegMetadata,
        op: BinOpKind,
        rhs_value: MirValue,
    ) -> Result<(), CompileError> {
        let Some((_input_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a stack-backed integer list in eBPF"
            )));
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
            for index in 0..max_len {
                let transform_block = self.func.alloc_block();
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
                    if_true: transform_block,
                    if_false: next_block,
                });

                self.current_block = transform_block;
                let item_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListGet {
                    dst: item_vreg,
                    list: input_vreg,
                    idx: MirValue::Const(index as i64),
                });
                self.vreg_type_hints.insert(item_vreg, MirType::I64);

                let output_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: output_vreg,
                    op,
                    lhs: MirValue::VReg(item_vreg),
                    rhs: rhs_value.clone(),
                });
                self.vreg_type_hints.insert(output_vreg, MirType::I64);
                self.emit(MirInst::ListPush {
                    list: result_vreg,
                    item: output_vreg,
                });
                self.terminate(MirInst::Jump { target: next_block });

                self.current_block = next_block;
            }
        }

        let known_len = Self::numeric_list_known_len(input_meta).map(|len| len.min(max_len));
        self.install_stack_numeric_list_result_metadata(
            src_dst, out_slot, out_ty, max_len, known_len,
        );
        Ok(())
    }
}
