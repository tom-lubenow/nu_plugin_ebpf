use super::*;

impl<'a> HirToMirLowering<'a> {
    pub(in crate::compiler::ir_to_mir) fn lower_stack_list_find(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "find does not accept flags or named arguments for stack-backed numeric lists in eBPF"
                    .into(),
            ));
        }
        if self.positional_args.len() != 1 {
            return Err(CompileError::UnsupportedInstruction(
                "find requires exactly one numeric search argument in eBPF".into(),
            ));
        }

        let mut input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let (needle_vreg, needle_reg) = self.positional_args[0];

        if let Some((builder_reg, values)) = input_reg.and_then(|reg| {
            self.compile_time_only_list_builder_values(reg, input_vreg)
                .map(|values| (reg, values.to_vec()))
        }) {
            let Some(needle) = self
                .get_metadata(needle_reg)
                .and_then(|meta| meta.constant_value.clone())
                .or_else(|| {
                    self.get_metadata(needle_reg)
                        .and_then(|meta| meta.literal_int)
                        .map(|value| nu_protocol::Value::int(value, Span::unknown()))
                })
            else {
                if values
                    .iter()
                    .any(|value| Self::numeric_value_from_value(value).is_none())
                {
                    return Err(CompileError::UnsupportedInstruction(
                        "find search argument must be compile-time constant for compile-time known fixed lists in eBPF"
                            .into(),
                    ));
                }

                let materialized = nu_protocol::Value::list(values, Span::unknown());
                self.assign_fresh_vreg(builder_reg);
                self.lower_constant_value(builder_reg, &materialized)?;
                input_vreg = self.get_vreg(builder_reg);
                let input_meta = self.get_metadata(builder_reg).cloned().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "find could not materialize compile-time known integer list in eBPF".into(),
                    )
                })?;
                if input_meta.list_buffer.is_none() {
                    return Err(CompileError::UnsupportedInstruction(
                        "find could not materialize compile-time known integer list in eBPF".into(),
                    ));
                }

                return self.lower_stack_list_find_materialized(
                    src_dst,
                    dst_vreg,
                    src_dst_had_value,
                    input_vreg,
                    input_meta,
                    needle_vreg,
                    needle_reg,
                );
            };
            let vals = values
                .into_iter()
                .filter(|value| value == &needle)
                .collect::<Vec<_>>();
            self.lower_compile_time_list_transform_result(
                src_dst,
                &nu_protocol::Value::list(vals, Span::unknown()),
            )?;
            return Ok(());
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "find requires a pipeline input with tracked metadata in eBPF".into(),
                )
            })?;
        if let Some(input_reg) = input_reg
            && self.lower_typed_fixed_array_find(
                src_dst,
                dst_vreg,
                src_dst_had_value,
                input_reg,
                input_vreg,
                &input_meta,
                needle_vreg,
                needle_reg,
            )?
        {
            return Ok(());
        }
        self.lower_stack_list_find_materialized(
            src_dst,
            dst_vreg,
            src_dst_had_value,
            input_vreg,
            input_meta,
            needle_vreg,
            needle_reg,
        )
    }

    fn lower_typed_fixed_array_find(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        input_reg: RegId,
        mut input_vreg: VReg,
        input_meta: &RegMetadata,
        needle_vreg: VReg,
        needle_reg: RegId,
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

        if !Self::typed_fixed_array_find_scalar_type(&elem_ty) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "find on typed fixed arrays currently supports {} in eBPF, got {:?}",
                Self::typed_fixed_array_find_scalar_type_description(),
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
                        "find requires typed fixed-array input in eBPF".into(),
                    )
                })?;
        }

        let MirType::Ptr { address_space, .. } = base_runtime_ty else {
            return Err(CompileError::UnsupportedInstruction(
                "find requires typed fixed-array pointer input in eBPF".into(),
            ));
        };
        if !matches!(
            address_space,
            AddressSpace::Stack | AddressSpace::Map | AddressSpace::Context
        ) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "find on typed fixed-array pointers in {address_space:?} address space is not yet supported in eBPF"
            )));
        }

        let needle_meta = self.get_metadata(needle_reg).cloned();
        let needle_const = needle_meta
            .as_ref()
            .and_then(Self::numeric_value_from_metadata);
        if needle_const.is_none()
            && needle_meta
                .as_ref()
                .and_then(|meta| meta.constant_value.as_ref())
                .is_some()
        {
            return Err(CompileError::UnsupportedInstruction(
                "find search argument must be an integer scalar for typed fixed arrays in eBPF"
                    .into(),
            ));
        }
        if needle_const.is_none()
            && !matches!(
                self.typed_value_runtime_type(needle_reg, needle_vreg),
                Some(
                    MirType::I8
                        | MirType::I16
                        | MirType::I32
                        | MirType::I64
                        | MirType::U8
                        | MirType::U16
                        | MirType::U32
                        | MirType::U64
                        | MirType::Bool
                )
            )
        {
            return Err(CompileError::UnsupportedInstruction(
                "find search argument must be an integer or bool scalar in eBPF".into(),
            ));
        }
        let needle_value = needle_const
            .map(|needle| self.large_const_operand(&MirType::I64, needle))
            .unwrap_or(MirValue::VReg(needle_vreg));

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, array_len);

        for source_index in 0..array_len {
            let compare_block = self.func.alloc_block();
            let next_block = self.func.alloc_block();
            self.terminate(MirInst::Jump {
                target: compare_block,
            });
            self.current_block = compare_block;

            let item_vreg = self.emit_typed_fixed_array_numeric_list_item(
                "find",
                input_vreg,
                &elem_ty,
                source_index,
            )?;

            let found_vreg = self.func.alloc_vreg();
            self.emit(MirInst::BinOp {
                dst: found_vreg,
                op: BinOpKind::Eq,
                lhs: MirValue::VReg(item_vreg),
                rhs: needle_value.clone(),
            });
            self.vreg_type_hints.insert(found_vreg, MirType::Bool);
            let push_block = self.func.alloc_block();
            self.terminate(MirInst::Branch {
                cond: found_vreg,
                if_true: push_block,
                if_false: next_block,
            });

            self.current_block = push_block;
            self.emit(MirInst::ListPush {
                list: result_vreg,
                item: item_vreg,
            });
            self.terminate(MirInst::Jump { target: next_block });
            self.current_block = next_block;
        }

        let constant_value = match (&input_meta.constant_value, needle_const) {
            (Some(nu_protocol::Value::List { vals, .. }), Some(needle)) => {
                let vals = vals
                    .iter()
                    .filter(|value| Self::numeric_value_from_value(value) == Some(needle))
                    .cloned()
                    .collect::<Vec<_>>();
                Some(nu_protocol::Value::list(vals, Span::unknown()))
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
        if let Some(value) = constant_value {
            self.get_or_create_metadata(src_dst).constant_value = Some(value);
        }

        Ok(true)
    }

    fn lower_stack_list_find_materialized(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        input_vreg: VReg,
        input_meta: RegMetadata,
        needle_vreg: VReg,
        needle_reg: RegId,
    ) -> Result<(), CompileError> {
        let Some((_input_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(
                "find requires a stack-backed numeric list input in eBPF".into(),
            ));
        };

        let needle_meta = self.get_metadata(needle_reg).cloned();
        let needle_const = needle_meta
            .as_ref()
            .and_then(Self::numeric_value_from_metadata);
        if needle_const.is_none()
            && needle_meta
                .as_ref()
                .and_then(|meta| meta.constant_value.as_ref())
                .is_some()
        {
            return Err(CompileError::UnsupportedInstruction(
                "find search argument must be an integer scalar for stack-backed numeric lists in eBPF"
                    .into(),
            ));
        }
        if needle_const.is_none()
            && !matches!(
                self.typed_value_runtime_type(needle_reg, needle_vreg),
                Some(
                    MirType::I8
                        | MirType::I16
                        | MirType::I32
                        | MirType::I64
                        | MirType::U8
                        | MirType::U16
                        | MirType::U32
                        | MirType::U64
                )
            )
        {
            return Err(CompileError::UnsupportedInstruction(
                "find search argument must be a numeric scalar in eBPF".into(),
            ));
        }
        let needle_value = needle_const
            .map(|needle| self.large_const_operand(&MirType::I64, needle))
            .unwrap_or(MirValue::VReg(needle_vreg));

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
                let compare_block = self.func.alloc_block();
                let push_block = self.func.alloc_block();
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
                    if_true: compare_block,
                    if_false: next_block,
                });

                self.current_block = compare_block;
                let item_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListGet {
                    dst: item_vreg,
                    list: input_vreg,
                    idx: MirValue::Const(source_index as i64),
                });
                self.vreg_type_hints.insert(item_vreg, MirType::I64);

                let found_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: found_vreg,
                    op: BinOpKind::Eq,
                    lhs: MirValue::VReg(item_vreg),
                    rhs: needle_value.clone(),
                });
                self.vreg_type_hints.insert(found_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: found_vreg,
                    if_true: push_block,
                    if_false: next_block,
                });

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

        let constant_value = match (input_meta.constant_value, needle_const) {
            (Some(nu_protocol::Value::List { vals, .. }), Some(needle)) => {
                let vals = vals
                    .into_iter()
                    .filter(|value| Self::numeric_value_from_value(value) == Some(needle))
                    .collect::<Vec<_>>();
                Some(nu_protocol::Value::list(vals, Span::unknown()))
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
        if let Some(value) = constant_value {
            self.get_or_create_metadata(src_dst).constant_value = Some(value);
        }

        Ok(())
    }

    fn numeric_value_from_metadata(meta: &RegMetadata) -> Option<i64> {
        meta.literal_int.or_else(|| {
            meta.constant_value
                .as_ref()
                .and_then(Self::numeric_value_from_value)
        })
    }

    fn numeric_value_from_value(value: &nu_protocol::Value) -> Option<i64> {
        match value {
            nu_protocol::Value::Bool { val, .. } => Some(i64::from(*val)),
            nu_protocol::Value::Int { val, .. } => Some(*val),
            _ => None,
        }
    }

    fn typed_fixed_array_find_scalar_type(ty: &MirType) -> bool {
        Self::typed_fixed_array_numeric_list_scalar_type(ty) || matches!(ty, MirType::Bool)
    }

    fn typed_fixed_array_find_scalar_type_description() -> &'static str {
        "signed integer, bool, or <=32-bit unsigned integer scalar elements"
    }
}
