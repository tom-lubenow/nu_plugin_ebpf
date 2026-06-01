use super::*;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CompileTimeSortKey {
    Bool(bool),
    Int(i64),
    Binary(Vec<u8>),
    String(String),
}

const MAX_STACK_LIST_SORT_CAPACITY: usize = 16;

impl<'a> HirToMirLowering<'a> {
    pub(in crate::compiler::ir_to_mir) fn lower_stack_list_sort(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let reverse = self.named_flags.iter().any(|flag| flag == "reverse");
        if let Some(flag) = self
            .named_flags
            .iter()
            .find(|flag| flag.as_str() != "reverse")
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "sort --{flag} is not supported for stack-backed numeric lists in eBPF"
            )));
        }
        if !self.named_args.is_empty() || !self.positional_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "sort does not accept arguments in eBPF".into(),
            ));
        }

        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if let Some(mut values) = input_reg.and_then(|reg| {
            self.direct_list_builder_values(reg, input_vreg)
                .map(|values| values.to_vec())
        }) {
            let mut keyed = values
                .iter()
                .map(Self::compile_time_sort_key)
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "sort supports compile-time known fixed lists with boolean, integer, binary, or string elements in eBPF"
                            .into(),
                    )
                })?;
            if let Some((first, rest)) = keyed.split_first()
                && rest
                    .iter()
                    .any(|key| std::mem::discriminant(key) != std::mem::discriminant(first))
            {
                return Err(CompileError::UnsupportedInstruction(
                    "sort requires compile-time known fixed-list elements with one comparable type in eBPF"
                        .into(),
                ));
            }

            let mut indexed = keyed.drain(..).zip(values.drain(..)).collect::<Vec<_>>();
            indexed.sort_by(|(left_key, _), (right_key, _)| {
                let ord = left_key.cmp(right_key);
                if reverse { ord.reverse() } else { ord }
            });
            let vals = indexed
                .into_iter()
                .map(|(_, value)| value)
                .collect::<Vec<_>>();
            self.lower_constant_value(src_dst, &nu_protocol::Value::list(vals, Span::unknown()))?;
            return Ok(());
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "sort requires a pipeline input with tracked metadata in eBPF".into(),
                )
            })?;
        let Some((_input_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(
                "sort requires a stack-backed list input in eBPF".into(),
            ));
        };
        if max_len > MAX_STACK_LIST_SORT_CAPACITY {
            return Err(CompileError::UnsupportedInstruction(format!(
                "sort supports stack-backed numeric lists with capacity <= {MAX_STACK_LIST_SORT_CAPACITY} in eBPF"
            )));
        }

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
                let copy_block = self.func.alloc_block();
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

            for pass in 0..max_len {
                for left_index in 0..max_len.saturating_sub(1 + pass) {
                    self.emit_stack_list_compare_swap(
                        out_slot,
                        left_index,
                        left_index + 1,
                        reverse,
                    );
                }
            }
        }

        let known_len = Self::numeric_list_known_len(&input_meta).map(|len| len.min(max_len));
        let constant_value = match input_meta.constant_value {
            Some(nu_protocol::Value::List { mut vals, .. }) => {
                vals.sort_by(|lhs, rhs| {
                    let ord = match (Self::literal_int_value(lhs), Self::literal_int_value(rhs)) {
                        (Some(lhs), Some(rhs)) => lhs.cmp(&rhs),
                        _ => std::cmp::Ordering::Equal,
                    };
                    if reverse { ord.reverse() } else { ord }
                });
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

    fn emit_stack_list_compare_swap(
        &mut self,
        slot: StackSlotId,
        left_index: usize,
        right_index: usize,
        reverse: bool,
    ) {
        let compare_block = self.func.alloc_block();
        let swap_block = self.func.alloc_block();
        let next_block = self.func.alloc_block();

        let len_vreg = self.func.alloc_vreg();
        self.emit(MirInst::LoadSlot {
            dst: len_vreg,
            slot,
            offset: 0,
            ty: MirType::U64,
        });
        self.vreg_type_hints.insert(len_vreg, MirType::U64);

        let in_bounds_vreg = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: in_bounds_vreg,
            op: BinOpKind::Lt,
            lhs: MirValue::Const(right_index as i64),
            rhs: MirValue::VReg(len_vreg),
        });
        self.vreg_type_hints.insert(in_bounds_vreg, MirType::Bool);
        self.terminate(MirInst::Branch {
            cond: in_bounds_vreg,
            if_true: compare_block,
            if_false: next_block,
        });

        self.current_block = compare_block;
        let left_vreg = self.func.alloc_vreg();
        self.emit(MirInst::LoadSlot {
            dst: left_vreg,
            slot,
            offset: Self::list_item_offset(left_index),
            ty: MirType::I64,
        });
        self.vreg_type_hints.insert(left_vreg, MirType::I64);

        let right_vreg = self.func.alloc_vreg();
        self.emit(MirInst::LoadSlot {
            dst: right_vreg,
            slot,
            offset: Self::list_item_offset(right_index),
            ty: MirType::I64,
        });
        self.vreg_type_hints.insert(right_vreg, MirType::I64);

        let swap_cond = self.func.alloc_vreg();
        self.emit(MirInst::BinOp {
            dst: swap_cond,
            op: if reverse {
                BinOpKind::Lt
            } else {
                BinOpKind::Gt
            },
            lhs: MirValue::VReg(left_vreg),
            rhs: MirValue::VReg(right_vreg),
        });
        self.vreg_type_hints.insert(swap_cond, MirType::Bool);
        self.terminate(MirInst::Branch {
            cond: swap_cond,
            if_true: swap_block,
            if_false: next_block,
        });

        self.current_block = swap_block;
        self.emit(MirInst::StoreSlot {
            slot,
            offset: Self::list_item_offset(left_index),
            val: MirValue::VReg(right_vreg),
            ty: MirType::I64,
        });
        self.emit(MirInst::StoreSlot {
            slot,
            offset: Self::list_item_offset(right_index),
            val: MirValue::VReg(left_vreg),
            ty: MirType::I64,
        });
        self.terminate(MirInst::Jump { target: next_block });

        self.current_block = next_block;
    }

    fn list_item_offset(index: usize) -> i32 {
        (8 + index * 8) as i32
    }

    fn literal_int_value(value: &nu_protocol::Value) -> Option<i64> {
        match value {
            nu_protocol::Value::Int { val, .. } => Some(*val),
            _ => None,
        }
    }

    fn compile_time_sort_key(value: &nu_protocol::Value) -> Option<CompileTimeSortKey> {
        match value {
            nu_protocol::Value::Bool { val, .. } => Some(CompileTimeSortKey::Bool(*val)),
            nu_protocol::Value::Int { val, .. } => Some(CompileTimeSortKey::Int(*val)),
            nu_protocol::Value::Binary { val, .. } => Some(CompileTimeSortKey::Binary(val.clone())),
            nu_protocol::Value::String { val, .. } | nu_protocol::Value::Glob { val, .. } => {
                Some(CompileTimeSortKey::String(val.clone()))
            }
            _ => None,
        }
    }
}
