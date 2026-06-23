use super::*;

const MAX_FIND_SHAPE_LIST_CAPACITY: usize = 60;

struct TypedFixedArrayFind<'a> {
    src_dst: RegId,
    dst_vreg: VReg,
    src_dst_had_value: bool,
    input_reg: RegId,
    input_vreg: VReg,
    input_meta: &'a RegMetadata,
    needle_vreg: VReg,
    needle_reg: RegId,
    invert: bool,
}

struct MaterializedStackListFind {
    src_dst: RegId,
    dst_vreg: VReg,
    src_dst_had_value: bool,
    input_vreg: VReg,
    input_meta: RegMetadata,
    needle_vreg: VReg,
    needle_reg: RegId,
    invert: bool,
}

impl<'a> HirToMirLowering<'a> {
    pub(in crate::compiler::ir_to_mir) fn lower_stack_list_find(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let invert = self.find_invert_flag()?;
        if !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "find supports only --invert flag and no named arguments in eBPF".into(),
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
                if self.current_call_result_list_shape_metadata_only
                    && let Some(strings) = Self::compile_time_string_values(&values)
                {
                    return self.lower_compile_time_string_list_find_shape(
                        src_dst,
                        dst_vreg,
                        src_dst_had_value,
                        &strings,
                        needle_reg,
                        invert,
                    );
                }
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

                return self.lower_stack_list_find_materialized(MaterializedStackListFind {
                    src_dst,
                    dst_vreg,
                    src_dst_had_value,
                    input_vreg,
                    input_meta,
                    needle_vreg,
                    needle_reg,
                    invert,
                });
            };
            let vals = values
                .into_iter()
                .filter(|value| (value == &needle) != invert)
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
            && self.lower_typed_fixed_array_find(TypedFixedArrayFind {
                src_dst,
                dst_vreg,
                src_dst_had_value,
                input_reg,
                input_vreg,
                input_meta: &input_meta,
                needle_vreg,
                needle_reg,
                invert,
            })?
        {
            return Ok(());
        }
        self.lower_stack_list_find_materialized(MaterializedStackListFind {
            src_dst,
            dst_vreg,
            src_dst_had_value,
            input_vreg,
            input_meta,
            needle_vreg,
            needle_reg,
            invert,
        })
    }

    fn find_invert_flag(&self) -> Result<bool, CompileError> {
        let mut invert = false;
        for flag in &self.named_flags {
            match flag.as_str() {
                "invert" | "v" => invert = true,
                _ => {
                    return Err(CompileError::UnsupportedInstruction(
                        "find supports only --invert flag and no named arguments in eBPF".into(),
                    ));
                }
            }
        }
        Ok(invert)
    }

    fn lower_typed_fixed_array_find(
        &mut self,
        find: TypedFixedArrayFind<'_>,
    ) -> Result<bool, CompileError> {
        let TypedFixedArrayFind {
            src_dst,
            dst_vreg,
            src_dst_had_value,
            input_reg,
            mut input_vreg,
            input_meta,
            needle_vreg,
            needle_reg,
            invert,
        } = find;

        if matches!(
            input_meta.constant_value,
            Some(nu_protocol::Value::List { .. })
        ) && !Self::metadata_declares_fixed_array_layout(input_meta)
        {
            return Ok(false);
        }

        let Some(mut base_runtime_ty) = self.typed_value_runtime_type(input_reg, input_vreg) else {
            return Ok(false);
        };
        let Some((elem_ty, array_len)) =
            Self::typed_fixed_array_stack_list_array_type(&base_runtime_ty)
        else {
            return Ok(false);
        };

        let u64_shape_only_find = matches!(elem_ty, MirType::U64);

        if !u64_shape_only_find && !Self::typed_fixed_array_find_scalar_type(&elem_ty) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "find on typed fixed arrays currently supports {} in eBPF, got {:?}",
                Self::typed_fixed_array_find_scalar_type_description(),
                elem_ty
            )));
        }

        if !matches!(base_runtime_ty, MirType::Ptr { .. })
            && Self::typed_fixed_array_stack_list_array_type(&base_runtime_ty).is_some()
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
        Self::validate_typed_fixed_array_stack_list_address_space(
            "find",
            address_space,
            input_meta,
        )?;

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
        let constant_value =
            Self::typed_fixed_array_find_constant_value(input_meta, needle_const, invert).or_else(
                || {
                    Self::zero_initialized_typed_fixed_array_find_constant_value(
                        input_meta,
                        needle_const,
                        array_len,
                        invert,
                    )
                },
            );

        if u64_shape_only_find && !self.current_call_result_list_shape_metadata_only {
            if self.current_call_result_direct_list_projection.is_some()
                && let Some(value) = constant_value.as_ref()
            {
                self.lower_compile_time_only_constant_value(src_dst, value);
                return Ok(true);
            }
            return Err(CompileError::UnsupportedInstruction(
                "find on typed fixed arrays with u64 elements is supported only for metadata-only shape consumers such as length/is-empty in eBPF"
                    .into(),
            ));
        }

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

            let item_vreg = if u64_shape_only_find {
                self.emit_typed_fixed_array_predicate_item(
                    "find",
                    input_vreg,
                    &elem_ty,
                    source_index,
                )?
            } else {
                self.emit_typed_fixed_array_numeric_list_item(
                    "find",
                    input_vreg,
                    &elem_ty,
                    source_index,
                )?
            };

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
                if_true: if invert { next_block } else { push_block },
                if_false: if invert { push_block } else { next_block },
            });

            self.current_block = push_block;
            let push_vreg = if u64_shape_only_find {
                self.emit_typed_fixed_array_shape_marker()
            } else {
                item_vreg
            };
            self.emit(MirInst::ListPush {
                list: result_vreg,
                item: push_vreg,
            });
            self.terminate(MirInst::Jump { target: next_block });
            self.current_block = next_block;
        }

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

    fn lower_compile_time_string_list_find_shape(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        values: &[String],
        needle_reg: RegId,
        invert: bool,
    ) -> Result<(), CompileError> {
        if values.len() > MAX_FIND_SHAPE_LIST_CAPACITY {
            return Err(CompileError::UnsupportedInstruction(format!(
                "find output exceeds stack-backed numeric list capacity {MAX_FIND_SHAPE_LIST_CAPACITY} in eBPF"
            )));
        }
        if !self
            .get_metadata(needle_reg)
            .is_some_and(Self::metadata_is_string_find_needle)
        {
            return Err(CompileError::UnsupportedInstruction(
                "find search argument must be a tracked string for compile-time known string lists feeding shape consumers in eBPF"
                    .into(),
            ));
        }

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, values.len());

        if !values.is_empty() {
            let continuation_block = self.func.alloc_block();
            for (index, value) in values.iter().enumerate() {
                let literal_reg = self.alloc_synthetic_reg("find")?;
                let literal_vreg = self.get_vreg(literal_reg);
                self.lower_string_like_literal(literal_reg, literal_vreg, value.as_bytes())?;
                if !self.lower_runtime_string_equality(literal_reg, needle_reg, false)? {
                    return Err(CompileError::UnsupportedInstruction(
                        "find search argument must be a tracked string for compile-time known string lists feeding shape consumers in eBPF"
                            .into(),
                    ));
                }

                let found_vreg = self.get_vreg(literal_reg);
                let push_block = self.func.alloc_block();
                let next_block = if index + 1 == values.len() {
                    continuation_block
                } else {
                    self.func.alloc_block()
                };
                self.terminate(MirInst::Branch {
                    cond: found_vreg,
                    if_true: if invert { next_block } else { push_block },
                    if_false: if invert { push_block } else { next_block },
                });

                self.current_block = push_block;
                let marker = self.func.alloc_vreg();
                self.emit(MirInst::Copy {
                    dst: marker,
                    src: MirValue::Const(1),
                });
                self.vreg_type_hints.insert(marker, MirType::I64);
                self.emit(MirInst::ListPush {
                    list: result_vreg,
                    item: marker,
                });
                self.terminate(MirInst::Jump { target: next_block });
                self.current_block = next_block;
            }
            self.current_block = continuation_block;
        }

        self.install_stack_numeric_list_result_metadata(
            src_dst,
            out_slot,
            out_ty,
            values.len(),
            None,
        );
        Ok(())
    }

    fn typed_fixed_array_find_constant_value(
        input_meta: &RegMetadata,
        needle_const: Option<i64>,
        invert: bool,
    ) -> Option<nu_protocol::Value> {
        match (&input_meta.constant_value, needle_const) {
            (Some(nu_protocol::Value::List { vals, .. }), Some(needle)) => {
                let vals = vals
                    .iter()
                    .filter(|value| {
                        Self::numeric_value_from_value(value)
                            .is_some_and(|value| (value == needle) != invert)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                Some(nu_protocol::Value::list(vals, Span::unknown()))
            }
            _ => None,
        }
    }

    fn zero_initialized_typed_fixed_array_find_constant_value(
        input_meta: &RegMetadata,
        needle_const: Option<i64>,
        array_len: usize,
        invert: bool,
    ) -> Option<nu_protocol::Value> {
        let needle = needle_const?;
        if !input_meta.zero_initialized_global {
            return None;
        }
        let vals = if (needle == 0) != invert {
            (0..array_len)
                .map(|_| nu_protocol::Value::int(0, Span::unknown()))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        Some(nu_protocol::Value::list(vals, Span::unknown()))
    }

    fn lower_stack_list_find_materialized(
        &mut self,
        find: MaterializedStackListFind,
    ) -> Result<(), CompileError> {
        let MaterializedStackListFind {
            src_dst,
            dst_vreg,
            src_dst_had_value,
            input_vreg,
            input_meta,
            needle_vreg,
            needle_reg,
            invert,
        } = find;

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
                        | MirType::Bool
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
                    if_true: if invert { next_block } else { push_block },
                    if_false: if invert { push_block } else { next_block },
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
                    .filter(|value| {
                        Self::numeric_value_from_value(value)
                            .is_some_and(|value| (value == needle) != invert)
                    })
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

    fn compile_time_string_values(values: &[nu_protocol::Value]) -> Option<Vec<String>> {
        values
            .iter()
            .map(|value| match value {
                nu_protocol::Value::String { val, .. } | nu_protocol::Value::Glob { val, .. } => {
                    Some(val.clone())
                }
                _ => None,
            })
            .collect()
    }

    fn metadata_is_string_find_needle(meta: &RegMetadata) -> bool {
        (meta.string_slot.is_some() && meta.string_len_vreg.is_some())
            || meta.literal_string.is_some()
            || matches!(
                meta.constant_value,
                Some(nu_protocol::Value::String { .. } | nu_protocol::Value::Glob { .. })
            )
    }

    fn typed_fixed_array_find_scalar_type(ty: &MirType) -> bool {
        Self::typed_fixed_array_numeric_list_scalar_type(ty) || matches!(ty, MirType::Bool)
    }

    fn typed_fixed_array_find_scalar_type_description() -> &'static str {
        "signed integer, bool, or <=32-bit unsigned integer scalar elements"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn find_accepts_trusted_kernel_fixed_array() {
        let decl_names = HashMap::new();
        let closure_irs = HashMap::new();
        let closure_param_sources = HashMap::new();
        let captures = Vec::new();
        let user_functions = HashMap::new();
        let decl_signatures = HashMap::new();
        let mut lowering = HirToMirLowering::new(HirToMirLoweringInput {
            probe_ctx: None,
            decl_names: &decl_names,
            closure_irs: &closure_irs,
            closure_param_sources: &closure_param_sources,
            captures: &captures,
            ctx_param: None,
            type_hints: None,
            external_map_key_types: None,
            external_map_key_semantics: None,
            external_map_max_entries: None,
            external_map_inner_templates: None,
            external_map_value_types: None,
            external_map_value_semantics: None,
            user_functions: &user_functions,
            decl_signatures: &decl_signatures,
        });
        let entry = lowering.func.alloc_block();
        lowering.func.entry = entry;
        lowering.current_block = entry;

        let ptr_ty = MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U32),
                len: 2,
            }),
            address_space: AddressSpace::Kernel,
        };
        let input_reg = RegId::new(1);
        let input_vreg = lowering.get_vreg(input_reg);
        lowering.vreg_type_hints.insert(input_vreg, ptr_ty.clone());
        let input_meta = RegMetadata {
            field_type: Some(ptr_ty),
            trusted_btf: true,
            ..Default::default()
        };

        let needle_reg = RegId::new(2);
        let needle_vreg = lowering.get_vreg(needle_reg);
        lowering.vreg_type_hints.insert(needle_vreg, MirType::I64);
        lowering.reg_metadata.insert(
            needle_reg.get(),
            RegMetadata {
                literal_int: Some(7),
                field_type: Some(MirType::I64),
                ..Default::default()
            },
        );

        let src_dst = RegId::new(3);
        let dst_vreg = lowering.get_vreg(src_dst);
        assert!(
            lowering
                .lower_typed_fixed_array_find(TypedFixedArrayFind {
                    src_dst,
                    dst_vreg,
                    src_dst_had_value: false,
                    input_reg,
                    input_vreg,
                    input_meta: &input_meta,
                    needle_vreg,
                    needle_reg,
                    invert: false,
                })
                .expect("trusted kernel fixed-array find should lower")
        );

        let load_count = lowering
            .func
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|inst| {
                matches!(
                    inst,
                    MirInst::Load {
                        ptr,
                        ty: MirType::U32,
                        ..
                    } if *ptr == input_vreg
                )
            })
            .count();
        assert_eq!(load_count, 2);
        assert!(
            lowering
                .reg_metadata
                .get(&src_dst.get())
                .and_then(|meta| meta.list_buffer)
                .is_some()
        );
    }
}
