use super::*;

impl<'a> HirToMirLowering<'a> {
    pub(in crate::compiler::ir_to_mir) fn lower_stack_list_uniq(
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
                "uniq does not accept arguments in eBPF".into(),
            ));
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "uniq requires a pipeline input with tracked metadata in eBPF".into(),
                )
            })?;
        let Some((_input_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(
                "uniq requires a stack-backed list input in eBPF".into(),
            ));
        };

        let result_vreg = if src_dst_had_value {
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
            for source_index in 0..max_len {
                let consider_block = self.func.alloc_block();
                let next_block = if source_index + 1 == max_len {
                    continuation_block
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
                    if_true: consider_block,
                    if_false: next_block,
                });

                self.current_block = consider_block;
                let item_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListGet {
                    dst: item_vreg,
                    list: input_vreg,
                    idx: MirValue::Const(source_index as i64),
                });
                self.vreg_type_hints.insert(item_vreg, MirType::I64);

                let push_block = self.func.alloc_block();
                if source_index == 0 {
                    self.terminate(MirInst::Jump { target: push_block });
                } else {
                    for prior_index in 0..source_index {
                        let distinct_block = if prior_index + 1 == source_index {
                            push_block
                        } else {
                            self.func.alloc_block()
                        };
                        let prior_vreg = self.func.alloc_vreg();
                        self.emit(MirInst::ListGet {
                            dst: prior_vreg,
                            list: input_vreg,
                            idx: MirValue::Const(prior_index as i64),
                        });
                        self.vreg_type_hints.insert(prior_vreg, MirType::I64);

                        let duplicate_vreg = self.func.alloc_vreg();
                        self.emit(MirInst::BinOp {
                            dst: duplicate_vreg,
                            op: BinOpKind::Eq,
                            lhs: MirValue::VReg(item_vreg),
                            rhs: MirValue::VReg(prior_vreg),
                        });
                        self.vreg_type_hints.insert(duplicate_vreg, MirType::Bool);
                        self.terminate(MirInst::Branch {
                            cond: duplicate_vreg,
                            if_true: next_block,
                            if_false: distinct_block,
                        });
                        self.current_block = distinct_block;
                    }
                }

                self.current_block = push_block;
                self.emit(MirInst::ListPush {
                    list: result_vreg,
                    item: item_vreg,
                });
                self.terminate(MirInst::Jump { target: next_block });

                self.current_block = next_block;
            }
            self.current_block = continuation_block;
        }

        let constant_value = match input_meta.constant_value {
            Some(nu_protocol::Value::List { vals, .. }) => {
                let mut unique = Vec::new();
                for value in vals {
                    if !unique.contains(&value) {
                        unique.push(value);
                    }
                }
                Some(nu_protocol::Value::list(unique, Span::unknown()))
            }
            _ => None,
        };

        self.install_stack_numeric_list_result_metadata(src_dst, out_slot, out_ty, max_len, None);
        if let Some(value) = constant_value {
            let known_len = match &value {
                nu_protocol::Value::List { vals, .. } => Some(vals.len()),
                _ => None,
            };
            let out_meta = self.get_or_create_metadata(src_dst);
            out_meta.constant_value = Some(value);
            out_meta.annotated_semantics =
                Some(AnnotatedValueSemantics::NumericList { max_len, known_len });
        }
        Ok(())
    }
}
