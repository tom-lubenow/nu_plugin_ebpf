use super::*;

const MAX_COMPACT_EMPTY_SHAPE_LIST_CAPACITY: usize = 60;

struct FixedArrayCompactIdentity<'a> {
    src_dst: RegId,
    dst_vreg: VReg,
    src_dst_had_value: bool,
    input_reg: RegId,
    input_vreg: VReg,
    input_meta: &'a RegMetadata,
    remove_empty: bool,
}

impl<'a> HirToMirLowering<'a> {
    pub(in crate::compiler::ir_to_mir) fn lower_stack_list_compact(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        if let Some(flag) = self
            .named_flags
            .iter()
            .find(|flag| flag.as_str() != "empty")
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "compact --{flag} is not supported for stack-backed numeric lists in eBPF"
            )));
        }
        if !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(
                "compact does not accept named arguments in eBPF".into(),
            ));
        }
        let remove_empty = self.named_flags.iter().any(|flag| flag == "empty");

        let input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));
        let input_reg = input_reg.ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "compact requires a pipeline input with tracked metadata in eBPF".into(),
            )
        })?;

        if let Some(values) = self
            .compile_time_only_list_builder_values(input_reg, input_vreg)
            .map(|values| values.to_vec())
        {
            let columns = if values
                .iter()
                .all(|value| matches!(value, nu_protocol::Value::Record { .. }))
            {
                self.compact_column_names()?
            } else {
                Vec::new()
            };
            let vals = values
                .into_iter()
                .filter(|value| {
                    Self::compact_keeps_value_for_columns(value, remove_empty, &columns)
                })
                .collect::<Vec<_>>();
            self.lower_compile_time_list_transform_result(
                src_dst,
                &nu_protocol::Value::list(vals, Span::unknown()),
            )?;
            return Ok(());
        }

        let input_meta = self.get_metadata(input_reg).cloned().ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "compact requires a pipeline input with tracked metadata in eBPF".into(),
            )
        })?;
        if !self.positional_args.is_empty() && Self::compact_columns_target_records(&input_meta) {
            return Err(CompileError::UnsupportedInstruction(
                "compact column arguments for typed record arrays require compile-time known fixed-list input in eBPF"
                    .into(),
            ));
        }
        if self.lower_typed_fixed_array_compact_identity(FixedArrayCompactIdentity {
            src_dst,
            dst_vreg,
            src_dst_had_value,
            input_reg,
            input_vreg,
            input_meta: &input_meta,
            remove_empty,
        })? {
            return Ok(());
        }
        if input_meta.list_buffer.is_none() {
            return Err(CompileError::UnsupportedInstruction(
                "compact requires a stack-backed numeric list input in eBPF".into(),
            ));
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

    fn lower_typed_fixed_array_compact_identity(
        &mut self,
        identity: FixedArrayCompactIdentity<'_>,
    ) -> Result<bool, CompileError> {
        let FixedArrayCompactIdentity {
            src_dst,
            dst_vreg,
            src_dst_had_value,
            input_reg,
            mut input_vreg,
            input_meta,
            remove_empty,
        } = identity;

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
        let Some(elem_ty) = Self::typed_fixed_array_compact_identity_array_type(&base_runtime_ty)
            .and_then(|ty| match ty {
                MirType::Array { elem, .. } => Some(elem.as_ref().clone()),
                _ => None,
            })
        else {
            return Ok(false);
        };

        let elem_semantics = match input_meta.annotated_semantics.as_ref() {
            Some(AnnotatedValueSemantics::FixedArray { elem, .. }) => Some(elem.as_ref()),
            _ => None,
        };
        let always_kept = Self::typed_fixed_array_compact_identity_always_kept_type(&elem_ty);
        if remove_empty && !always_kept {
            if self.lower_compile_time_fixed_array_compact_empty(src_dst, input_meta)? {
                return Ok(true);
            }
            if let Some(statically_kept) =
                Self::typed_fixed_array_compact_empty_static_keep(elem_semantics)
            {
                if statically_kept {
                    // Fixed non-empty aggregate elements keep the same fixed-array shape.
                } else if self.current_call_result_list_shape_metadata_only {
                    return self.lower_typed_fixed_array_compact_empty_shape_constant(
                        src_dst,
                        dst_vreg,
                        src_dst_had_value,
                        0,
                    );
                } else {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "compact --empty on typed fixed arrays would produce an empty variable-length result in eBPF; use a metadata consumer such as length or is-empty, got {:?}",
                        elem_ty
                    )));
                }
            } else if self.current_call_result_type_metadata_only {
                return self.lower_typed_fixed_array_compact_empty_type_only(
                    src_dst,
                    dst_vreg,
                    src_dst_had_value,
                    input_reg,
                    input_vreg,
                );
            } else if self.current_call_result_list_shape_metadata_only
                && self.lower_typed_fixed_array_compact_empty_shape_dynamic(
                    src_dst,
                    dst_vreg,
                    src_dst_had_value,
                    input_reg,
                    input_vreg,
                    input_meta,
                )?
            {
                return Ok(true);
            } else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "compact --empty on typed fixed arrays is only a safe identity for numeric, bool, or statically non-empty elements in eBPF; variable-length filtering for fixed-array elements is supported only for metadata-only shape consumers such as length/is-empty or type-only consumers such as describe, got {:?}",
                    elem_ty
                )));
            }
        }
        if !always_kept
            && !Self::typed_fixed_array_compact_identity_default_semantics(elem_semantics)
        {
            return Ok(false);
        }

        if !matches!(base_runtime_ty, MirType::Ptr { .. })
            && Self::typed_fixed_array_compact_identity_array_type(&base_runtime_ty).is_some()
        {
            input_vreg = self.materialized_metadata_aggregate_vreg(input_reg, input_vreg)?;
            base_runtime_ty = self
                .typed_value_runtime_type(input_reg, input_vreg)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "compact requires typed fixed-array input in eBPF".into(),
                    )
                })?;
        }

        let MirType::Ptr { address_space, .. } = base_runtime_ty else {
            return Err(CompileError::UnsupportedInstruction(
                "compact requires typed fixed-array pointer input in eBPF".into(),
            ));
        };
        if !matches!(
            address_space,
            AddressSpace::Stack | AddressSpace::Map | AddressSpace::Context | AddressSpace::Kernel
        ) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "compact on typed fixed-array pointers in {address_space:?} address space is not yet supported in eBPF"
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
        Ok(true)
    }

    fn lower_typed_fixed_array_compact_empty_type_only(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        input_reg: RegId,
        input_vreg: VReg,
    ) -> Result<bool, CompileError> {
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
        Ok(true)
    }

    fn lower_typed_fixed_array_compact_empty_shape_constant(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        known_len: usize,
    ) -> Result<bool, CompileError> {
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, known_len);
        for _ in 0..known_len {
            let item = self.func.alloc_vreg();
            self.emit(MirInst::Copy {
                dst: item,
                src: MirValue::Const(1),
            });
            self.vreg_type_hints.insert(item, MirType::I64);
            self.emit(MirInst::ListPush {
                list: result_vreg,
                item,
            });
        }
        self.install_stack_numeric_list_result_metadata(
            src_dst,
            out_slot,
            out_ty,
            known_len,
            Some(known_len),
        );
        Ok(true)
    }

    fn lower_typed_fixed_array_compact_empty_shape_dynamic(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        input_reg: RegId,
        mut input_vreg: VReg,
        input_meta: &RegMetadata,
    ) -> Result<bool, CompileError> {
        let Some(AnnotatedValueSemantics::FixedArray { elem, len }) =
            input_meta.annotated_semantics.as_ref()
        else {
            return Ok(false);
        };
        let Some((length_offset, min_elem_size)) =
            Self::typed_fixed_array_compact_empty_dynamic_len_prefix(elem.as_ref())
        else {
            return Ok(false);
        };

        let mut base_runtime_ty = match self.typed_value_runtime_type(input_reg, input_vreg) {
            Some(ty) => ty,
            None => return Ok(false),
        };
        if !matches!(base_runtime_ty, MirType::Ptr { .. })
            && Self::typed_fixed_array_compact_identity_array_type(&base_runtime_ty).is_some()
        {
            input_vreg = self.materialized_metadata_aggregate_vreg(input_reg, input_vreg)?;
            base_runtime_ty = self
                .typed_value_runtime_type(input_reg, input_vreg)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "compact --empty requires typed fixed-array input in eBPF".into(),
                    )
                })?;
        }

        let Some(MirType::Array {
            elem: array_elem_ty,
            len: array_len,
        }) = Self::typed_fixed_array_compact_identity_array_type(&base_runtime_ty)
        else {
            return Ok(false);
        };
        let elem_ty = array_elem_ty.as_ref().clone();
        let array_len = *array_len;
        if array_len != *len {
            return Err(CompileError::UnsupportedInstruction(format!(
                "compact --empty typed fixed-array length metadata mismatch: type length {array_len}, semantic length {len}"
            )));
        }
        if array_len > MAX_COMPACT_EMPTY_SHAPE_LIST_CAPACITY {
            return Err(CompileError::UnsupportedInstruction(format!(
                "compact --empty metadata-only shape output exceeds stack-backed numeric list capacity {MAX_COMPACT_EMPTY_SHAPE_LIST_CAPACITY} in eBPF"
            )));
        }
        let elem_size = elem_ty.size();
        if elem_size < min_elem_size {
            return Err(CompileError::UnsupportedInstruction(format!(
                "compact --empty typed fixed-array element storage is too small: element size {elem_size}, required {min_elem_size}"
            )));
        }
        let address_space = match &base_runtime_ty {
            MirType::Ptr { address_space, .. } => *address_space,
            _ => {
                return Err(CompileError::UnsupportedInstruction(
                    "compact --empty requires typed fixed-array pointer input in eBPF".into(),
                ));
            }
        };
        if !matches!(
            address_space,
            AddressSpace::Stack | AddressSpace::Map | AddressSpace::Context | AddressSpace::Kernel
        ) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "compact --empty on typed fixed-array pointers in {address_space:?} address space is not yet supported in eBPF"
            )));
        }
        if address_space == AddressSpace::Kernel && !input_meta.trusted_btf {
            return Err(CompileError::UnsupportedInstruction(
                "compact --empty on typed fixed-array pointers in Kernel address space requires trusted BTF provenance in eBPF"
                    .into(),
            ));
        }

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, array_len);

        if array_len > 0 {
            let continuation_block = self.func.alloc_block();
            for index in 0..array_len {
                let check_block = self.func.alloc_block();
                let push_block = self.func.alloc_block();
                let next_block = if index + 1 == array_len {
                    continuation_block
                } else {
                    self.func.alloc_block()
                };

                self.terminate(MirInst::Jump {
                    target: check_block,
                });
                self.current_block = check_block;

                let elem_offset = index.checked_mul(elem_size).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "compact --empty typed fixed-array element offset overflowed in eBPF"
                            .into(),
                    )
                })?;
                let len_offset = elem_offset.checked_add(length_offset).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "compact --empty typed fixed-array length offset overflowed in eBPF".into(),
                    )
                })?;
                let len_vreg = self.func.alloc_vreg();
                self.emit(MirInst::Load {
                    dst: len_vreg,
                    ptr: input_vreg,
                    offset: Self::checked_mir_offset(
                        len_offset,
                        "compact --empty fixed-array element length",
                    )?,
                    ty: MirType::I64,
                });
                self.vreg_type_hints.insert(len_vreg, MirType::I64);

                let keep_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: keep_vreg,
                    op: BinOpKind::Gt,
                    lhs: MirValue::VReg(len_vreg),
                    rhs: MirValue::Const(0),
                });
                self.vreg_type_hints.insert(keep_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: keep_vreg,
                    if_true: push_block,
                    if_false: next_block,
                });

                self.current_block = push_block;
                self.emit(MirInst::ListPush {
                    list: result_vreg,
                    item: len_vreg,
                });
                self.terminate(MirInst::Jump { target: next_block });
                self.current_block = next_block;
            }
            self.current_block = continuation_block;
        }

        self.install_stack_numeric_list_result_metadata(src_dst, out_slot, out_ty, array_len, None);
        Ok(true)
    }

    fn typed_fixed_array_compact_empty_dynamic_len_prefix(
        semantics: &AnnotatedValueSemantics,
    ) -> Option<(usize, usize)> {
        match semantics {
            AnnotatedValueSemantics::String { slot_len, .. } => {
                Some((0, 8usize.checked_add(*slot_len)?))
            }
            AnnotatedValueSemantics::NumericList {
                max_len,
                known_len: None,
            } => Some((0, i64_list_buffer_size(*max_len))),
            _ => None,
        }
    }

    fn lower_compile_time_fixed_array_compact_empty(
        &mut self,
        src_dst: RegId,
        input_meta: &RegMetadata,
    ) -> Result<bool, CompileError> {
        let Some(nu_protocol::Value::List { vals, .. }) = input_meta.constant_value.as_ref() else {
            return Ok(false);
        };

        // Fixed arrays cannot shrink at runtime, but known contents can be filtered before MIR.
        let vals = vals
            .iter()
            .filter(|value| Self::compact_keeps_value(value, true))
            .cloned()
            .collect::<Vec<_>>();
        if vals.is_empty() && !self.current_call_result_metadata_only {
            return Err(CompileError::UnsupportedInstruction(
                "compact --empty on a fixed array produced an empty compile-time list; use a metadata consumer such as length or keep at least one fixed-layout element so eBPF can infer an output layout"
                    .into(),
            ));
        }
        self.lower_compile_time_list_transform_result(
            src_dst,
            &nu_protocol::Value::list(vals, Span::unknown()),
        )?;
        Ok(true)
    }

    fn typed_fixed_array_compact_identity_array_type(ty: &MirType) -> Option<&MirType> {
        match ty {
            MirType::Array { .. } => Some(ty),
            MirType::Ptr {
                pointee,
                address_space:
                    AddressSpace::Stack
                    | AddressSpace::Map
                    | AddressSpace::Context
                    | AddressSpace::Kernel,
            } if matches!(pointee.as_ref(), MirType::Array { .. }) => Some(pointee.as_ref()),
            _ => None,
        }
    }

    fn typed_fixed_array_compact_identity_always_kept_type(ty: &MirType) -> bool {
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
                | MirType::Bool
        )
    }

    fn typed_fixed_array_compact_empty_static_keep(
        semantics: Option<&AnnotatedValueSemantics>,
    ) -> Option<bool> {
        match semantics? {
            AnnotatedValueSemantics::Binary { len } => Some(*len > 0),
            AnnotatedValueSemantics::NumericList {
                known_len: Some(len),
                ..
            } => Some(*len > 0),
            AnnotatedValueSemantics::Record(fields) => Some(!fields.is_empty()),
            AnnotatedValueSemantics::FixedArray { len, .. } => Some(*len > 0),
            AnnotatedValueSemantics::String { .. }
            | AnnotatedValueSemantics::NumericList {
                known_len: None, ..
            } => None,
        }
    }

    fn typed_fixed_array_compact_identity_default_semantics(
        semantics: Option<&AnnotatedValueSemantics>,
    ) -> bool {
        matches!(
            semantics,
            Some(
                AnnotatedValueSemantics::String { .. }
                    | AnnotatedValueSemantics::Binary { .. }
                    | AnnotatedValueSemantics::NumericList { .. }
                    | AnnotatedValueSemantics::Record(_)
                    | AnnotatedValueSemantics::FixedArray { .. }
            )
        )
    }

    fn compact_column_names(&self) -> Result<Vec<String>, CompileError> {
        let mut columns = Vec::with_capacity(self.positional_args.len());
        for (_, reg) in &self.positional_args {
            columns.push(self.top_level_field_name_arg(*reg, "compact")?);
        }
        Ok(columns)
    }

    fn compact_columns_target_records(input_meta: &RegMetadata) -> bool {
        matches!(
            input_meta.annotated_semantics.as_ref(),
            Some(AnnotatedValueSemantics::FixedArray { elem, .. })
                if matches!(elem.as_ref(), AnnotatedValueSemantics::Record(_))
        )
    }

    fn compact_keeps_value_for_columns(
        value: &nu_protocol::Value,
        remove_empty: bool,
        columns: &[String],
    ) -> bool {
        if columns.is_empty() {
            return Self::compact_keeps_value(value, remove_empty);
        }

        let nu_protocol::Value::Record { val, .. } = value else {
            return true;
        };

        columns.iter().all(|column| {
            val.get(column)
                .is_some_and(|value| Self::compact_keeps_value(value, remove_empty))
        })
    }

    fn compact_keeps_value(value: &nu_protocol::Value, remove_empty: bool) -> bool {
        match value {
            nu_protocol::Value::Nothing { .. } => false,
            nu_protocol::Value::String { val, .. } => !remove_empty || !val.is_empty(),
            nu_protocol::Value::Binary { val, .. } => !remove_empty || !val.is_empty(),
            nu_protocol::Value::List { vals, .. } => !remove_empty || !vals.is_empty(),
            nu_protocol::Value::Record { val, .. } => !remove_empty || !val.is_empty(),
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn compact_identity_accepts_kernel_fixed_array_without_loads() {
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

        let elem_ty = MirType::Array {
            elem: Box::new(MirType::U8),
            len: 4,
        };
        let array_ty = MirType::Array {
            elem: Box::new(elem_ty),
            len: 2,
        };
        let ptr_ty = MirType::Ptr {
            pointee: Box::new(array_ty),
            address_space: AddressSpace::Kernel,
        };
        let semantics = AnnotatedValueSemantics::FixedArray {
            elem: Box::new(AnnotatedValueSemantics::Binary { len: 4 }),
            len: 2,
        };

        let input_reg = RegId::new(1);
        let input_vreg = lowering.get_vreg(input_reg);
        let src_dst = RegId::new(2);
        let dst_vreg = lowering.get_vreg(src_dst);
        lowering.pipeline_input = Some(input_vreg);
        lowering.pipeline_input_reg = Some(input_reg);
        lowering.vreg_type_hints.insert(input_vreg, ptr_ty.clone());
        lowering.reg_metadata.insert(
            input_reg.get(),
            RegMetadata {
                field_type: Some(ptr_ty.clone()),
                annotated_semantics: Some(semantics.clone()),
                trusted_btf: true,
                ..Default::default()
            },
        );

        lowering
            .lower_stack_list_compact(src_dst, dst_vreg, false)
            .expect("default compact identity should accept kernel fixed-array pointers");

        let instructions = &lowering.func.block(entry).instructions;
        assert_eq!(instructions.len(), 1);
        match &instructions[0] {
            MirInst::Copy { dst, src } => {
                assert_eq!(*dst, dst_vreg);
                assert_eq!(*src, MirValue::VReg(input_vreg));
            }
            inst => panic!("expected pass-through copy, got {inst:?}"),
        }
        assert!(
            instructions
                .iter()
                .all(|inst| !matches!(inst, MirInst::Load { .. })),
            "kernel fixed-array compact identity must not dereference input"
        );
        assert_eq!(lowering.vreg_type_hints.get(&dst_vreg), Some(&ptr_ty));

        let out_meta = lowering
            .reg_metadata
            .get(&src_dst.get())
            .expect("compact identity should preserve output metadata");
        assert_eq!(out_meta.field_type.as_ref(), Some(&ptr_ty));
        assert_eq!(out_meta.annotated_semantics.as_ref(), Some(&semantics));
        assert!(out_meta.trusted_btf);
    }

    fn with_test_lowering(test: impl FnOnce(&mut HirToMirLowering<'_>)) {
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
        test(&mut lowering);
    }

    fn register_kernel_string_array(
        lowering: &mut HirToMirLowering<'_>,
        reg: RegId,
        slot_len: usize,
        array_len: usize,
        trusted_btf: bool,
    ) -> VReg {
        let elem_ty = MirType::Array {
            elem: Box::new(MirType::U8),
            len: 8 + slot_len,
        };
        let array_ty = MirType::Array {
            elem: Box::new(elem_ty),
            len: array_len,
        };
        let ptr_ty = MirType::Ptr {
            pointee: Box::new(array_ty),
            address_space: AddressSpace::Kernel,
        };
        let vreg = lowering.get_vreg(reg);
        lowering.vreg_type_hints.insert(vreg, ptr_ty.clone());
        lowering.reg_metadata.insert(
            reg.get(),
            RegMetadata {
                field_type: Some(ptr_ty),
                annotated_semantics: Some(AnnotatedValueSemantics::FixedArray {
                    elem: Box::new(AnnotatedValueSemantics::String {
                        slot_len,
                        content_cap: slot_len.saturating_sub(1),
                    }),
                    len: array_len,
                }),
                trusted_btf,
                ..Default::default()
            },
        );
        vreg
    }

    fn count_i64_loads(lowering: &HirToMirLowering<'_>) -> usize {
        lowering
            .func
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|inst| {
                matches!(
                    inst,
                    MirInst::Load {
                        ty: MirType::I64,
                        ..
                    }
                )
            })
            .count()
    }

    #[test]
    fn compact_empty_shape_accepts_trusted_kernel_string_array() {
        with_test_lowering(|lowering| {
            let input_reg = RegId::new(1);
            let input_vreg = register_kernel_string_array(lowering, input_reg, 8, 2, true);
            let input_meta = lowering
                .get_metadata(input_reg)
                .expect("registered input metadata")
                .clone();
            let src_dst = RegId::new(2);
            let dst_vreg = lowering.get_vreg(src_dst);

            assert!(
                lowering
                    .lower_typed_fixed_array_compact_empty_shape_dynamic(
                        src_dst,
                        dst_vreg,
                        false,
                        input_reg,
                        input_vreg,
                        &input_meta,
                    )
                    .expect("trusted kernel compact --empty shape should lower")
            );

            assert_eq!(count_i64_loads(lowering), 2);
            assert!(
                lowering
                    .reg_metadata
                    .get(&src_dst.get())
                    .and_then(|meta| meta.list_buffer)
                    .is_some(),
                "compact --empty shape output should install stack-list metadata"
            );
        });
    }

    #[test]
    fn compact_empty_shape_rejects_untrusted_kernel_string_array() {
        with_test_lowering(|lowering| {
            let input_reg = RegId::new(1);
            let input_vreg = register_kernel_string_array(lowering, input_reg, 8, 2, false);
            let input_meta = lowering
                .get_metadata(input_reg)
                .expect("registered input metadata")
                .clone();
            let src_dst = RegId::new(2);
            let dst_vreg = lowering.get_vreg(src_dst);

            let err = lowering
                .lower_typed_fixed_array_compact_empty_shape_dynamic(
                    src_dst,
                    dst_vreg,
                    false,
                    input_reg,
                    input_vreg,
                    &input_meta,
                )
                .expect_err("untrusted kernel compact --empty shape should be rejected");

            assert!(
                err.to_string().contains("requires trusted BTF provenance"),
                "unexpected error: {err}"
            );
        });
    }
}
