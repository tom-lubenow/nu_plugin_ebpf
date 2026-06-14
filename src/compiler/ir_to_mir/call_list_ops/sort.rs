use super::*;

#[derive(Debug, Clone, Copy)]
struct FloatSortKey(f64);

impl PartialEq for FloatSortKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for FloatSortKey {}

impl PartialOrd for FloatSortKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FloatSortKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .partial_cmp(&other.0)
            .expect("float sort keys are finite")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CompileTimeSortKey {
    Bool(bool),
    Int(i64),
    Float(FloatSortKey),
    Binary(Vec<u8>),
    String(String),
}

const MAX_STACK_LIST_SORT_CAPACITY: usize = 16;

struct TypedFixedArraySort<'a> {
    src_dst: RegId,
    dst_vreg: VReg,
    src_dst_had_value: bool,
    input_reg: RegId,
    input_vreg: VReg,
    input_meta: &'a RegMetadata,
    reverse: bool,
    natural: bool,
    ignore_case: bool,
}

impl<'a> HirToMirLowering<'a> {
    pub(in crate::compiler::ir_to_mir) fn lower_stack_list_sort(
        &mut self,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let reverse = self.named_flags.iter().any(|flag| flag == "reverse");
        let natural = self.named_flags.iter().any(|flag| flag == "natural");
        let ignore_case = self.named_flags.iter().any(|flag| flag == "ignore-case");
        let values_flag = self.named_flags.iter().any(|flag| flag == "values");
        if let Some(flag) = self.named_flags.iter().find(|flag| {
            !matches!(
                flag.as_str(),
                "reverse" | "natural" | "ignore-case" | "values"
            )
        }) {
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

        if values_flag
            && let Some(record) =
                input_reg
                    .and_then(|reg| self.get_metadata(reg))
                    .and_then(|meta| match meta.constant_value.as_ref() {
                        Some(nu_protocol::Value::Record { val, .. }) => {
                            Some(val.clone().into_owned())
                        }
                        _ => None,
                    })
        {
            let sorted =
                Self::compile_time_record_sort_values(&record, reverse, natural, ignore_case)?;
            self.lower_compile_time_list_transform_result(
                src_dst,
                &nu_protocol::Value::record(sorted, Span::unknown()),
            )?;
            return Ok(());
        }

        if let Some(mut values) = input_reg.and_then(|reg| {
            self.compile_time_only_list_builder_values(reg, input_vreg)
                .map(|values| values.to_vec())
        }) {
            let mut keyed = values
                .iter()
                .map(Self::compile_time_sort_key)
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "sort supports compile-time known fixed lists with boolean, integer, finite float, binary, or string elements in eBPF"
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
            if natural
                && keyed
                    .iter()
                    .any(|key| !Self::sort_key_supports_natural(key))
            {
                return Err(CompileError::UnsupportedInstruction(
                    "sort --natural is only supported for numeric or string compile-time lists in eBPF"
                        .into(),
                ));
            }
            if ignore_case
                && keyed
                    .iter()
                    .any(|key| !Self::sort_key_supports_ignore_case(key))
            {
                return Err(CompileError::UnsupportedInstruction(
                    "sort --ignore-case is only supported for numeric or string compile-time lists in eBPF"
                        .into(),
                ));
            }

            let mut indexed = keyed.drain(..).zip(values.drain(..)).collect::<Vec<_>>();
            indexed.sort_by(|(left_key, _), (right_key, _)| {
                let ord =
                    Self::compare_compile_time_sort_keys(left_key, right_key, natural, ignore_case);
                if reverse { ord.reverse() } else { ord }
            });
            let vals = indexed
                .into_iter()
                .map(|(_, value)| value)
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
                    "sort requires a pipeline input with tracked metadata in eBPF".into(),
                )
            })?;

        if let Some(input_reg) = input_reg
            && self.lower_typed_fixed_array_sort(TypedFixedArraySort {
                src_dst,
                dst_vreg,
                src_dst_had_value,
                input_reg,
                input_vreg,
                input_meta: &input_meta,
                reverse,
                natural,
                ignore_case,
            })?
        {
            return Ok(());
        }

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

    pub(in crate::compiler::ir_to_mir) fn compile_time_record_sort_values(
        record: &nu_protocol::Record,
        reverse: bool,
        natural: bool,
        ignore_case: bool,
    ) -> Result<nu_protocol::Record, CompileError> {
        let mut keyed = record
            .iter()
            .map(|(name, value)| {
                Self::compile_time_sort_key(value).map(|key| (key, name.clone(), value.clone()))
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "sort --values supports compile-time record values with boolean, integer, finite float, binary, or string values in eBPF"
                        .into(),
                )
            })?;
        if let Some((first, rest)) = keyed.split_first()
            && rest
                .iter()
                .any(|(key, _, _)| std::mem::discriminant(key) != std::mem::discriminant(&first.0))
        {
            return Err(CompileError::UnsupportedInstruction(
                "sort --values requires compile-time record values with one comparable type in eBPF"
                    .into(),
            ));
        }
        if natural
            && keyed
                .iter()
                .any(|(key, _, _)| !Self::sort_key_supports_natural(key))
        {
            return Err(CompileError::UnsupportedInstruction(
                "sort --values --natural is only supported for numeric or string compile-time record values in eBPF"
                    .into(),
            ));
        }
        if ignore_case
            && keyed
                .iter()
                .any(|(key, _, _)| !Self::sort_key_supports_ignore_case(key))
        {
            return Err(CompileError::UnsupportedInstruction(
                "sort --values --ignore-case is only supported for numeric or string compile-time record values in eBPF"
                    .into(),
            ));
        }

        keyed.sort_by(|(left_key, left_name, _), (right_key, right_name, _)| {
            let ord =
                Self::compare_compile_time_sort_keys(left_key, right_key, natural, ignore_case)
                    .then_with(|| left_name.cmp(right_name));
            if reverse { ord.reverse() } else { ord }
        });

        let mut out = nu_protocol::Record::new();
        for (_, name, value) in keyed {
            out.push(name, value);
        }
        Ok(out)
    }

    fn typed_fixed_array_sort_scalar_type(ty: &MirType) -> bool {
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

    fn lower_typed_fixed_array_sort(
        &mut self,
        sort: TypedFixedArraySort<'_>,
    ) -> Result<bool, CompileError> {
        let TypedFixedArraySort {
            src_dst,
            dst_vreg,
            src_dst_had_value,
            input_reg,
            mut input_vreg,
            input_meta,
            reverse,
            natural,
            ignore_case,
        } = sort;

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
        let Some((elem_ty, array_len)) =
            Self::typed_fixed_array_stack_list_array_type(&base_runtime_ty)
        else {
            return Ok(false);
        };

        if !Self::typed_fixed_array_sort_scalar_type(&elem_ty)
            && self.try_lower_typed_fixed_array_compile_time_sort(
                src_dst,
                input_meta,
                reverse,
                natural,
                ignore_case,
            )?
        {
            return Ok(true);
        }

        if !Self::typed_fixed_array_sort_scalar_type(&elem_ty) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "sort on typed fixed arrays currently supports only integer or bool scalar elements in eBPF, got {:?}",
                elem_ty
            )));
        }
        if array_len > MAX_STACK_LIST_SORT_CAPACITY {
            return Err(CompileError::UnsupportedInstruction(format!(
                "sort supports typed fixed arrays with length <= {MAX_STACK_LIST_SORT_CAPACITY} in eBPF"
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
                        "sort requires typed fixed-array input in eBPF".into(),
                    )
                })?;
        }

        let MirType::Ptr { address_space, .. } = base_runtime_ty else {
            return Err(CompileError::UnsupportedInstruction(
                "sort requires typed fixed-array pointer input in eBPF".into(),
            ));
        };
        Self::validate_typed_fixed_array_stack_list_address_space(
            "sort",
            address_space,
            input_meta,
        )?;

        let out_ty = MirType::Array {
            elem: Box::new(elem_ty.clone()),
            len: array_len,
        };
        let out_size = out_ty.size();
        if out_size == 0 {
            self.lower_compile_time_list_transform_result(
                src_dst,
                &nu_protocol::Value::list(Vec::new(), Span::unknown()),
            )?;
            return Ok(true);
        }

        let out_slot =
            self.func
                .alloc_stack_slot(align_to_eight(out_size), 8, StackSlotKind::Local);
        self.record_stack_slot_type(out_slot, out_ty.clone());

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        self.emit(MirInst::Copy {
            dst: result_vreg,
            src: MirValue::StackSlot(out_slot),
        });
        self.vreg_type_hints.insert(
            result_vreg,
            MirType::Ptr {
                pointee: Box::new(out_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );
        self.emit_ptr_to_slot_copy(out_slot, 0, input_vreg, 0, out_size)?;

        for pass in 0..array_len {
            for left_index in 0..array_len.saturating_sub(1 + pass) {
                self.emit_fixed_array_compare_swap(
                    out_slot,
                    &elem_ty,
                    left_index,
                    left_index + 1,
                    reverse,
                )?;
            }
        }

        let constant_value = match &input_meta.constant_value {
            Some(nu_protocol::Value::List { vals, .. }) => {
                let mut vals = vals.clone();
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
        let annotated_semantics = match &input_meta.annotated_semantics {
            Some(AnnotatedValueSemantics::FixedArray { elem, .. }) => {
                Some(AnnotatedValueSemantics::FixedArray {
                    elem: elem.clone(),
                    len: array_len,
                })
            }
            _ => None,
        };

        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.field_type = Some(out_ty);
        out_meta.root_ctx_field = input_meta.root_ctx_field.clone();
        out_meta.constant_value = constant_value;
        out_meta.annotated_semantics = annotated_semantics;
        Ok(true)
    }

    fn try_lower_typed_fixed_array_compile_time_sort(
        &mut self,
        src_dst: RegId,
        input_meta: &RegMetadata,
        reverse: bool,
        natural: bool,
        ignore_case: bool,
    ) -> Result<bool, CompileError> {
        let Some(nu_protocol::Value::List { vals, .. }) = input_meta.constant_value.as_ref() else {
            return Ok(false);
        };
        let mut keyed = vals
            .iter()
            .map(Self::compile_time_sort_key)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "sort supports compile-time known fixed arrays with boolean, integer, finite float, binary, or string elements in eBPF"
                        .into(),
                )
            })?;
        let Some((first, rest)) = keyed.split_first() else {
            self.lower_compile_time_list_transform_result(
                src_dst,
                &nu_protocol::Value::list(Vec::new(), Span::unknown()),
            )?;
            return Ok(true);
        };
        if !matches!(
            first,
            CompileTimeSortKey::Binary(_) | CompileTimeSortKey::String(_)
        ) {
            return Ok(false);
        }
        if rest
            .iter()
            .any(|key| std::mem::discriminant(key) != std::mem::discriminant(first))
        {
            return Err(CompileError::UnsupportedInstruction(
                "sort requires compile-time known fixed-array elements with one comparable type in eBPF"
                    .into(),
            ));
        }
        if natural
            && keyed
                .iter()
                .any(|key| !Self::sort_key_supports_natural(key))
        {
            return Err(CompileError::UnsupportedInstruction(
                "sort --natural is only supported for numeric or string compile-time fixed arrays in eBPF"
                    .into(),
            ));
        }
        if ignore_case
            && keyed
                .iter()
                .any(|key| !Self::sort_key_supports_ignore_case(key))
        {
            return Err(CompileError::UnsupportedInstruction(
                "sort --ignore-case is only supported for numeric or string compile-time fixed arrays in eBPF"
                    .into(),
            ));
        }

        let mut indexed = keyed.drain(..).zip(vals.clone()).collect::<Vec<_>>();
        indexed.sort_by(|(left_key, _), (right_key, _)| {
            let ord =
                Self::compare_compile_time_sort_keys(left_key, right_key, natural, ignore_case);
            if reverse { ord.reverse() } else { ord }
        });
        let vals = indexed
            .into_iter()
            .map(|(_, value)| value)
            .collect::<Vec<_>>();
        self.lower_compile_time_list_transform_result(
            src_dst,
            &nu_protocol::Value::list(vals, Span::unknown()),
        )?;
        Ok(true)
    }

    fn emit_fixed_array_compare_swap(
        &mut self,
        slot: StackSlotId,
        elem_ty: &MirType,
        left_index: usize,
        right_index: usize,
        reverse: bool,
    ) -> Result<(), CompileError> {
        let elem_size = elem_ty.size();
        let left_offset = left_index.checked_mul(elem_size).ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "sort typed fixed-array left offset overflowed in eBPF".into(),
            )
        })?;
        let right_offset = right_index.checked_mul(elem_size).ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "sort typed fixed-array right offset overflowed in eBPF".into(),
            )
        })?;
        let left_offset =
            Self::checked_mir_offset(left_offset, "typed fixed-array sort left item")?;
        let right_offset =
            Self::checked_mir_offset(right_offset, "typed fixed-array sort right item")?;

        let compare_block = self.func.alloc_block();
        let swap_block = self.func.alloc_block();
        let next_block = self.func.alloc_block();

        self.terminate(MirInst::Jump {
            target: compare_block,
        });
        self.current_block = compare_block;

        let left_vreg = self.func.alloc_vreg();
        self.emit(MirInst::LoadSlot {
            dst: left_vreg,
            slot,
            offset: left_offset,
            ty: elem_ty.clone(),
        });
        self.vreg_type_hints.insert(left_vreg, elem_ty.clone());

        let right_vreg = self.func.alloc_vreg();
        self.emit(MirInst::LoadSlot {
            dst: right_vreg,
            slot,
            offset: right_offset,
            ty: elem_ty.clone(),
        });
        self.vreg_type_hints.insert(right_vreg, elem_ty.clone());

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
            offset: left_offset,
            val: MirValue::VReg(right_vreg),
            ty: elem_ty.clone(),
        });
        self.emit(MirInst::StoreSlot {
            slot,
            offset: right_offset,
            val: MirValue::VReg(left_vreg),
            ty: elem_ty.clone(),
        });
        self.terminate(MirInst::Jump { target: next_block });

        self.current_block = next_block;
        Ok(())
    }

    pub(super) fn emit_stack_list_compare_swap(
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

    pub(super) fn list_item_offset(index: usize) -> i32 {
        let offset = index
            .checked_mul(std::mem::size_of::<i64>())
            .and_then(|offset| offset.checked_add(std::mem::size_of::<i64>()))
            .expect("list item offset overflowed");
        i32::try_from(offset).expect("list item offset exceeded MIR i32 offset range")
    }

    fn literal_int_value(value: &nu_protocol::Value) -> Option<i64> {
        match value {
            nu_protocol::Value::Bool { val, .. } => Some(i64::from(*val)),
            nu_protocol::Value::Int { val, .. } => Some(*val),
            _ => None,
        }
    }

    fn compile_time_sort_key(value: &nu_protocol::Value) -> Option<CompileTimeSortKey> {
        match value {
            nu_protocol::Value::Bool { val, .. } => Some(CompileTimeSortKey::Bool(*val)),
            nu_protocol::Value::Int { val, .. } => Some(CompileTimeSortKey::Int(*val)),
            nu_protocol::Value::Float { val, .. } if val.is_finite() => {
                Some(CompileTimeSortKey::Float(FloatSortKey(*val)))
            }
            nu_protocol::Value::Binary { val, .. } => Some(CompileTimeSortKey::Binary(val.clone())),
            nu_protocol::Value::String { val, .. } | nu_protocol::Value::Glob { val, .. } => {
                Some(CompileTimeSortKey::String(val.clone()))
            }
            _ => None,
        }
    }

    fn sort_key_supports_natural(key: &CompileTimeSortKey) -> bool {
        matches!(
            key,
            CompileTimeSortKey::Int(_)
                | CompileTimeSortKey::Float(_)
                | CompileTimeSortKey::String(_)
        )
    }

    fn sort_key_supports_ignore_case(key: &CompileTimeSortKey) -> bool {
        matches!(
            key,
            CompileTimeSortKey::Int(_)
                | CompileTimeSortKey::Float(_)
                | CompileTimeSortKey::String(_)
        )
    }

    fn compare_compile_time_sort_keys(
        left: &CompileTimeSortKey,
        right: &CompileTimeSortKey,
        natural: bool,
        ignore_case: bool,
    ) -> std::cmp::Ordering {
        match (left, right) {
            (CompileTimeSortKey::String(left), CompileTimeSortKey::String(right)) => {
                if natural {
                    Self::natural_string_cmp(left, right, ignore_case)
                } else if ignore_case {
                    left.to_lowercase().cmp(&right.to_lowercase())
                } else {
                    left.cmp(right)
                }
            }
            _ => left.cmp(right),
        }
    }

    fn natural_string_cmp(left: &str, right: &str, ignore_case: bool) -> std::cmp::Ordering {
        let left = if ignore_case {
            std::borrow::Cow::Owned(left.to_lowercase())
        } else {
            std::borrow::Cow::Borrowed(left)
        };
        let right = if ignore_case {
            std::borrow::Cow::Owned(right.to_lowercase())
        } else {
            std::borrow::Cow::Borrowed(right)
        };
        Self::natural_string_cmp_normalized(&left, &right)
    }

    fn natural_string_cmp_normalized(left: &str, right: &str) -> std::cmp::Ordering {
        let mut left_chars = left.char_indices().peekable();
        let mut right_chars = right.char_indices().peekable();
        loop {
            match (left_chars.peek().copied(), right_chars.peek().copied()) {
                (None, None) => return std::cmp::Ordering::Equal,
                (None, Some(_)) => return std::cmp::Ordering::Less,
                (Some(_), None) => return std::cmp::Ordering::Greater,
                (Some((_, left_ch)), Some((_, right_ch)))
                    if left_ch.is_ascii_digit() && right_ch.is_ascii_digit() =>
                {
                    let left_digits = Self::take_ascii_digit_run(left, &mut left_chars);
                    let right_digits = Self::take_ascii_digit_run(right, &mut right_chars);
                    let ord = Self::compare_natural_digit_runs(left_digits, right_digits);
                    if !ord.is_eq() {
                        return ord;
                    }
                }
                (Some((_, left_ch)), Some((_, right_ch))) => {
                    left_chars.next();
                    right_chars.next();
                    let ord = left_ch.cmp(&right_ch);
                    if !ord.is_eq() {
                        return ord;
                    }
                }
            }
        }
    }

    fn take_ascii_digit_run<'s>(
        source: &'s str,
        chars: &mut std::iter::Peekable<std::str::CharIndices<'s>>,
    ) -> &'s str {
        let start = chars
            .peek()
            .map(|(index, _)| *index)
            .expect("digit run requires a current character");
        let mut end = source.len();
        while let Some((index, ch)) = chars.peek().copied() {
            if !ch.is_ascii_digit() {
                end = index;
                break;
            }
            chars.next();
        }
        &source[start..end]
    }

    fn compare_natural_digit_runs(left: &str, right: &str) -> std::cmp::Ordering {
        let left_trimmed = left.trim_start_matches('0');
        let right_trimmed = right.trim_start_matches('0');
        let left_numeric = if left_trimmed.is_empty() {
            "0"
        } else {
            left_trimmed
        };
        let right_numeric = if right_trimmed.is_empty() {
            "0"
        } else {
            right_trimmed
        };
        left_numeric
            .len()
            .cmp(&right_numeric.len())
            .then_with(|| left_numeric.cmp(right_numeric))
            .then_with(|| left.len().cmp(&right.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn sort_accepts_trusted_kernel_fixed_array() {
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

        let array_ty = MirType::Array {
            elem: Box::new(MirType::U32),
            len: 2,
        };
        let ptr_ty = MirType::Ptr {
            pointee: Box::new(array_ty.clone()),
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

        let src_dst = RegId::new(2);
        let dst_vreg = lowering.get_vreg(src_dst);
        assert!(
            lowering
                .lower_typed_fixed_array_sort(TypedFixedArraySort {
                    src_dst,
                    dst_vreg,
                    src_dst_had_value: false,
                    input_reg,
                    input_vreg,
                    input_meta: &input_meta,
                    reverse: false,
                    natural: false,
                    ignore_case: false,
                })
                .expect("trusted kernel fixed-array sort should lower")
        );

        assert!(
            lowering
                .func
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .any(|inst| matches!(inst, MirInst::Load { ptr, .. } if *ptr == input_vreg)),
            "expected sort to copy from the trusted kernel fixed-array input"
        );
        assert_eq!(
            lowering.vreg_type_hints.get(&dst_vreg),
            Some(&MirType::Ptr {
                pointee: Box::new(array_ty.clone()),
                address_space: AddressSpace::Stack,
            })
        );
        assert_eq!(
            lowering
                .reg_metadata
                .get(&src_dst.get())
                .and_then(|meta| meta.field_type.as_ref()),
            Some(&array_ty)
        );
    }
}
