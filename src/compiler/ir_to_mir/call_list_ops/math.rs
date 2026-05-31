use super::*;

impl<'a> HirToMirLowering<'a> {
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
}
