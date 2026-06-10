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

        if let Some(values) = input_reg.and_then(|reg| {
            self.compile_time_only_list_builder_values(reg, input_vreg)
                .map(|values| values.to_vec())
        }) {
            let mut unique = Vec::new();
            for value in values {
                if !unique.contains(&value) {
                    unique.push(value);
                }
            }
            self.lower_compile_time_list_transform_result(
                src_dst,
                &nu_protocol::Value::list(unique, Span::unknown()),
            )?;
            return Ok(());
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "uniq requires a pipeline input with tracked metadata in eBPF".into(),
                )
            })?;
        if let Some(input_reg) = input_reg
            && self.lower_typed_fixed_array_uniq(
                src_dst,
                dst_vreg,
                src_dst_had_value,
                input_reg,
                input_vreg,
                &input_meta,
            )?
        {
            return Ok(());
        }

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

        let input_min_len = input_meta
            .list_min_len
            .or_else(|| Self::numeric_list_known_len(&input_meta));
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
        let known_len = constant_value.as_ref().and_then(|value| match value {
            nu_protocol::Value::List { vals, .. } => Some(vals.len()),
            _ => None,
        });

        self.install_stack_numeric_list_result_metadata(
            src_dst, out_slot, out_ty, max_len, known_len,
        );
        if known_len.is_none()
            && let Some(input_min_len) = input_min_len
        {
            self.get_or_create_metadata(src_dst).list_min_len =
                Some(if input_min_len > 0 { 1 } else { 0 });
        }
        if let Some(value) = constant_value {
            let out_meta = self.get_or_create_metadata(src_dst);
            out_meta.constant_value = Some(value);
            out_meta.annotated_semantics =
                Some(AnnotatedValueSemantics::NumericList { max_len, known_len });
        }
        Ok(())
    }

    pub(super) fn typed_fixed_array_numeric_list_scalar_type(ty: &MirType) -> bool {
        matches!(
            ty,
            MirType::I8
                | MirType::I16
                | MirType::I32
                | MirType::I64
                | MirType::U8
                | MirType::U16
                | MirType::U32
        )
    }

    pub(super) fn typed_fixed_array_numeric_list_scalar_type_description() -> &'static str {
        "signed integer or <=32-bit unsigned integer scalar elements"
    }

    pub(super) fn emit_typed_fixed_array_numeric_list_item(
        &mut self,
        cmd_name: &str,
        input_vreg: VReg,
        elem_ty: &MirType,
        index: usize,
    ) -> Result<VReg, CompileError> {
        let elem_size = elem_ty.size();
        let offset = index.checked_mul(elem_size).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} typed fixed-array item offset overflowed in eBPF"
            ))
        })?;
        let offset = Self::checked_mir_offset(offset, "typed fixed-array numeric-list item")?;

        let raw_vreg = self.func.alloc_vreg();
        self.emit(MirInst::Load {
            dst: raw_vreg,
            ptr: input_vreg,
            offset,
            ty: elem_ty.clone(),
        });
        self.vreg_type_hints.insert(raw_vreg, elem_ty.clone());

        if matches!(elem_ty, MirType::I64) {
            return Ok(raw_vreg);
        }
        if matches!(elem_ty, MirType::I8 | MirType::I16 | MirType::I32) {
            return self
                .coerce_scalar_assignment_value(raw_vreg, elem_ty, &MirType::I64)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} could not widen typed fixed-array element type {:?} to i64 in eBPF",
                        elem_ty
                    ))
                });
        }

        let widened = self.func.alloc_vreg();
        self.vreg_type_hints.insert(widened, MirType::I64);
        self.emit(MirInst::Copy {
            dst: widened,
            src: MirValue::VReg(raw_vreg),
        });
        Ok(widened)
    }

    fn lower_typed_fixed_array_uniq(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        input_reg: RegId,
        mut input_vreg: VReg,
        input_meta: &RegMetadata,
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

        if !Self::typed_fixed_array_numeric_list_scalar_type(&elem_ty) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "uniq on typed fixed arrays currently supports {} in eBPF, got {:?}",
                Self::typed_fixed_array_numeric_list_scalar_type_description(),
                elem_ty
            )));
        }

        if !matches!(base_runtime_ty, MirType::Ptr { .. })
            && Self::aggregate_call_value_type(&base_runtime_ty).is_some()
        {
            input_vreg = self.materialized_metadata_aggregate_vreg(input_reg, input_vreg)?;
            base_runtime_ty = self
                .typed_value_runtime_type(input_reg, input_vreg)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "uniq requires typed fixed-array input in eBPF".into(),
                    )
                })?;
        }

        let MirType::Ptr { address_space, .. } = base_runtime_ty else {
            return Err(CompileError::UnsupportedInstruction(
                "uniq requires typed fixed-array pointer input in eBPF".into(),
            ));
        };
        if !matches!(
            address_space,
            AddressSpace::Stack | AddressSpace::Map | AddressSpace::Context
        ) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "uniq on typed fixed-array pointers in {address_space:?} address space is not yet supported in eBPF"
            )));
        }

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, array_len);

        for source_index in 0..array_len {
            let consider_block = self.func.alloc_block();
            let next_block = self.func.alloc_block();
            self.terminate(MirInst::Jump {
                target: consider_block,
            });
            self.current_block = consider_block;

            let item_vreg = self.emit_typed_fixed_array_numeric_list_item(
                "uniq",
                input_vreg,
                &elem_ty,
                source_index,
            )?;

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
                    let prior_vreg = self.emit_typed_fixed_array_numeric_list_item(
                        "uniq",
                        input_vreg,
                        &elem_ty,
                        prior_index,
                    )?;

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

        let constant_value = match &input_meta.constant_value {
            Some(nu_protocol::Value::List { vals, .. }) => {
                let mut unique = Vec::new();
                for value in vals {
                    if !unique.contains(value) {
                        unique.push(value.clone());
                    }
                }
                Some(nu_protocol::Value::list(unique, Span::unknown()))
            }
            _ => None,
        };
        let known_len = constant_value.as_ref().and_then(|value| match value {
            nu_protocol::Value::List { vals, .. } => Some(vals.len()),
            _ => None,
        });

        self.install_stack_numeric_list_result_metadata(
            src_dst, out_slot, out_ty, array_len, known_len,
        );
        if known_len.is_none() && array_len > 0 {
            self.get_or_create_metadata(src_dst).list_min_len = Some(1);
        }
        if let Some(value) = constant_value {
            self.get_or_create_metadata(src_dst).constant_value = Some(value);
        }
        Ok(true)
    }
}
