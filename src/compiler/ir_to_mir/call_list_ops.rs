use super::*;
use crate::compiler::mir::AddressSpace;

mod bits;
mod compact;
mod dedupe;
mod find;
mod map_filter;
mod math;
mod predicates;
mod sort;
mod split;

impl<'a> HirToMirLowering<'a> {
    fn is_stack_list_placeholder_type(ty: &MirType) -> bool {
        matches!(
            ty,
            MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack,
            } if matches!(
                pointee.as_ref(),
                MirType::Array { elem, .. } if matches!(elem.as_ref(), MirType::I64)
            )
        )
    }

    fn is_metadata_only_placeholder_type(ty: &MirType) -> bool {
        matches!(ty, MirType::I64)
    }

    pub(super) fn direct_list_builder_values(
        &self,
        input_reg: RegId,
        input_vreg: VReg,
    ) -> Option<&[nu_protocol::Value]> {
        let meta = self.get_metadata(input_reg)?;
        let nu_protocol::Value::List { vals, .. } = meta.constant_value.as_ref()? else {
            return None;
        };
        if meta.list_buffer.is_some() {
            return None;
        }
        let ty = self.vreg_type_hints.get(&input_vreg)?;
        if !Self::is_stack_list_placeholder_type(ty) {
            return None;
        }
        Some(vals)
    }

    pub(super) fn compile_time_only_list_builder_values(
        &self,
        input_reg: RegId,
        input_vreg: VReg,
    ) -> Option<&[nu_protocol::Value]> {
        let meta = self.get_metadata(input_reg)?;
        let value @ nu_protocol::Value::List { vals, .. } = meta.constant_value.as_ref()? else {
            return None;
        };
        if meta.list_buffer.is_some() {
            return None;
        }
        if crate::compiler::hir::supports_numeric_constant_list(value)
            && matches!(
                meta.annotated_semantics,
                Some(AnnotatedValueSemantics::NumericList { .. })
            )
        {
            return Some(vals);
        }
        if self
            .vreg_type_hints
            .get(&input_vreg)
            .is_some_and(Self::is_metadata_only_placeholder_type)
        {
            return Some(vals);
        }
        self.direct_list_builder_values(input_reg, input_vreg)
    }

    pub(super) fn lower_compile_time_list_transform_result(
        &mut self,
        dst: RegId,
        value: &nu_protocol::Value,
    ) -> Result<(), CompileError> {
        if self.current_call_result_metadata_only {
            self.lower_compile_time_only_constant_value(dst, value);
            Ok(())
        } else {
            self.lower_constant_value(dst, value)
        }
    }

    pub(super) fn create_stack_numeric_list_result(
        &mut self,
        dst_vreg: VReg,
        max_len: usize,
    ) -> (StackSlotId, MirType) {
        let out_ty = MirType::Array {
            elem: Box::new(MirType::I64),
            len: max_len.saturating_add(1),
        };
        let out_slot = self.func.alloc_stack_slot(
            align_to_eight(i64_list_buffer_size(max_len)),
            8,
            StackSlotKind::ListBuffer,
        );
        self.record_list_buffer_slot_type(out_slot, max_len);
        self.emit(MirInst::ListNew {
            dst: dst_vreg,
            buffer: out_slot,
            max_len,
        });
        self.vreg_type_hints.insert(
            dst_vreg,
            MirType::Ptr {
                pointee: Box::new(out_ty.clone()),
                address_space: AddressSpace::Stack,
            },
        );
        (out_slot, out_ty)
    }

    pub(super) fn numeric_list_known_len(meta: &RegMetadata) -> Option<usize> {
        match &meta.annotated_semantics {
            Some(AnnotatedValueSemantics::NumericList { known_len, .. }) => *known_len,
            _ => None,
        }
        .or_else(|| match &meta.constant_value {
            Some(nu_protocol::Value::List { vals, .. }) => Some(vals.len()),
            _ => None,
        })
    }

    fn typed_fixed_array_slice_bounds(
        cmd_name: &str,
        count: usize,
        array_len: usize,
    ) -> Result<(usize, usize), CompileError> {
        let (start, len) = match cmd_name {
            "take" | "first" => (0, count.min(array_len)),
            "skip" => {
                let start = count.min(array_len);
                (start, array_len.saturating_sub(start))
            }
            "drop" => (0, array_len.saturating_sub(count.min(array_len))),
            "last" => {
                let len = count.min(array_len);
                (array_len.saturating_sub(len), len)
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "unsupported typed fixed-array slice command '{cmd_name}'"
                )));
            }
        };
        Ok((start, len))
    }

    fn lower_typed_fixed_array_count_slice(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        input_reg: RegId,
        mut input_vreg: VReg,
        input_meta: &RegMetadata,
        count: usize,
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

        let (slice_start, slice_len) =
            Self::typed_fixed_array_slice_bounds(cmd_name, count, array_len)?;
        if slice_len == 0 {
            self.lower_compile_time_list_transform_result(
                src_dst,
                &nu_protocol::Value::list(Vec::new(), Span::unknown()),
            )?;
            return Ok(true);
        }

        if !matches!(base_runtime_ty, MirType::Ptr { .. })
            && Self::aggregate_call_value_type(&base_runtime_ty).is_some()
        {
            input_vreg = self.materialized_metadata_aggregate_vreg(input_reg, input_vreg)?;
            base_runtime_ty = self
                .typed_value_runtime_type(input_reg, input_vreg)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} requires typed fixed-array input in eBPF"
                    ))
                })?;
        }

        let MirType::Ptr { address_space, .. } = base_runtime_ty else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires typed fixed-array pointer input in eBPF"
            )));
        };

        let elem_size = elem_ty.size();
        let byte_offset = slice_start.checked_mul(elem_size).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} typed fixed-array slice offset overflowed in eBPF"
            ))
        })?;
        let byte_offset = i64::try_from(byte_offset).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} typed fixed-array slice offset is too large for eBPF"
            ))
        })?;

        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let out_ty = MirType::Array {
            elem: Box::new(elem_ty),
            len: slice_len,
        };
        self.vreg_type_hints.insert(
            result_vreg,
            MirType::Ptr {
                pointee: Box::new(out_ty.clone()),
                address_space,
            },
        );

        if byte_offset == 0 {
            self.emit(MirInst::Copy {
                dst: result_vreg,
                src: MirValue::VReg(input_vreg),
            });
        } else {
            self.emit(MirInst::BinOp {
                dst: result_vreg,
                op: BinOpKind::Add,
                lhs: MirValue::VReg(input_vreg),
                rhs: MirValue::Const(byte_offset),
            });
        }

        let constant_value = match &input_meta.constant_value {
            Some(nu_protocol::Value::List { vals, .. }) => Some(nu_protocol::Value::list(
                vals.iter()
                    .skip(slice_start)
                    .take(slice_len)
                    .cloned()
                    .collect(),
                Span::unknown(),
            )),
            _ => None,
        };
        let annotated_semantics = match &input_meta.annotated_semantics {
            Some(AnnotatedValueSemantics::FixedArray { elem, .. }) => {
                Some(AnnotatedValueSemantics::FixedArray {
                    elem: elem.clone(),
                    len: slice_len,
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

    fn lower_typed_fixed_array_reverse(
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

        if !matches!(base_runtime_ty, MirType::Ptr { .. })
            && Self::aggregate_call_value_type(&base_runtime_ty).is_some()
        {
            input_vreg = self.materialized_metadata_aggregate_vreg(input_reg, input_vreg)?;
            base_runtime_ty = self
                .typed_value_runtime_type(input_reg, input_vreg)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "reverse requires typed fixed-array input in eBPF".into(),
                    )
                })?;
        }

        let MirType::Ptr { address_space, .. } = base_runtime_ty else {
            return Err(CompileError::UnsupportedInstruction(
                "reverse requires typed fixed-array pointer input in eBPF".into(),
            ));
        };
        if !matches!(
            address_space,
            AddressSpace::Stack | AddressSpace::Map | AddressSpace::Context
        ) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "reverse on typed fixed-array pointers in {address_space:?} address space is not yet supported in eBPF"
            )));
        }

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

        let elem_size = elem_ty.size();
        for output_index in 0..array_len {
            let source_index = array_len - 1 - output_index;
            let dst_offset = output_index.checked_mul(elem_size).ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "reverse typed fixed-array destination offset overflowed in eBPF".into(),
                )
            })?;
            let src_offset = source_index.checked_mul(elem_size).ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "reverse typed fixed-array source offset overflowed in eBPF".into(),
                )
            })?;
            self.emit_ptr_to_slot_copy(out_slot, dst_offset, input_vreg, src_offset, elem_size)?;
        }

        let constant_value = match &input_meta.constant_value {
            Some(nu_protocol::Value::List { vals, .. }) => {
                let mut vals = vals.clone();
                vals.reverse();
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

    fn typed_fixed_array_append_scalar_type(ty: &MirType) -> bool {
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

    fn typed_fixed_array_literal_scalar_value(value: i64, dst_ty: &MirType) -> Option<MirValue> {
        let fits = match dst_ty {
            MirType::I8 => i8::try_from(value).is_ok(),
            MirType::I16 => i16::try_from(value).is_ok(),
            MirType::I32 => i32::try_from(value).is_ok(),
            MirType::I64 => true,
            MirType::U8 => u8::try_from(value).is_ok(),
            MirType::U16 => u16::try_from(value).is_ok(),
            MirType::U32 => u32::try_from(value).is_ok(),
            MirType::U64 => u64::try_from(value).is_ok(),
            MirType::Bool => matches!(value, 0 | 1),
            _ => false,
        };
        fits.then_some(MirValue::Const(value))
    }

    fn typed_fixed_array_aggregate_copy_size(
        elem_ty: &MirType,
        item_ty: &MirType,
    ) -> Option<usize> {
        if elem_ty == item_ty {
            return Some(elem_ty.size());
        }

        match (elem_ty.byte_array_len(), item_ty.byte_array_len()) {
            (Some(elem_len), Some(item_len)) if item_len <= elem_len => Some(item_len),
            _ => None,
        }
    }

    pub(super) fn lower_typed_fixed_array_append_or_prepend(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
        input_reg: RegId,
        mut input_vreg: VReg,
        input_meta: &RegMetadata,
        item_reg: RegId,
        item_vreg: VReg,
    ) -> Result<bool, CompileError> {
        if !matches!(cmd_name, "append" | "prepend") {
            return Err(CompileError::UnsupportedInstruction(format!(
                "unsupported typed fixed-array insert command '{cmd_name}'"
            )));
        }

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

        if !matches!(base_runtime_ty, MirType::Ptr { .. })
            && Self::aggregate_call_value_type(&base_runtime_ty).is_some()
        {
            input_vreg = self.materialized_metadata_aggregate_vreg(input_reg, input_vreg)?;
            base_runtime_ty = self
                .typed_value_runtime_type(input_reg, input_vreg)
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} requires typed fixed-array input in eBPF"
                    ))
                })?;
        }

        let MirType::Ptr { address_space, .. } = base_runtime_ty else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires typed fixed-array pointer input in eBPF"
            )));
        };
        if !matches!(
            address_space,
            AddressSpace::Stack | AddressSpace::Map | AddressSpace::Context
        ) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} on typed fixed-array pointers in {address_space:?} address space is not yet supported in eBPF"
            )));
        }

        enum InsertItem {
            Scalar(MirValue),
            Aggregate { ptr: VReg, copy_size: usize },
        }

        let item_runtime_ty = self.typed_value_runtime_type(item_reg, item_vreg);
        let insert_item = if Self::typed_fixed_array_append_scalar_type(&elem_ty) {
            let item_runtime_ty = item_runtime_ty.ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} typed fixed-array item requires tracked scalar type in eBPF"
                ))
            })?;
            let item_val = if let Some(coerced_vreg) =
                self.coerce_scalar_assignment_value(item_vreg, &item_runtime_ty, &elem_ty)
            {
                MirValue::VReg(coerced_vreg)
            } else if let Some(literal) = self
                .get_metadata(item_reg)
                .and_then(|meta| meta.literal_int)
            {
                Self::typed_fixed_array_literal_scalar_value(literal, &elem_ty).ok_or_else(
                    || {
                        CompileError::UnsupportedInstruction(format!(
                            "{cmd_name} item literal {literal} cannot fit typed fixed-array element type {:?} in eBPF",
                            elem_ty
                        ))
                    },
                )?
            } else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} item type {:?} cannot be stored in typed fixed-array element type {:?} in eBPF",
                    item_runtime_ty, elem_ty
                )));
            };
            InsertItem::Scalar(item_val)
        } else if Self::aggregate_call_value_type(&elem_ty).is_some() {
            let item_ptr = self.materialized_metadata_aggregate_vreg(item_reg, item_vreg)?;
            let item_ptr_ty = self
                .vreg_type_hints
                .get(&item_ptr)
                .cloned()
                .or_else(|| self.typed_value_runtime_type(item_reg, item_ptr))
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} typed fixed-array aggregate item requires tracked pointer type in eBPF"
                    ))
                })?;
            let MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack | AddressSpace::Map,
            } = item_ptr_ty
            else {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} typed fixed-array aggregate item requires a stack/map aggregate pointer in eBPF, got {:?}",
                    item_ptr_ty
                )));
            };
            let item_ty = pointee.as_ref().clone();
            let copy_size =
                Self::typed_fixed_array_aggregate_copy_size(&elem_ty, &item_ty).ok_or_else(
                    || {
                        CompileError::UnsupportedInstruction(format!(
                            "{cmd_name} item type {:?} cannot be stored in typed fixed-array element type {:?} in eBPF",
                            item_ty, elem_ty
                        ))
                    },
                )?;
            InsertItem::Aggregate {
                ptr: item_ptr,
                copy_size,
            }
        } else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} on typed fixed arrays currently supports only scalar or aggregate fixed-layout elements in eBPF, got {:?}",
                elem_ty
            )));
        };

        let out_len = array_len.checked_add(1).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} typed fixed-array result length overflowed in eBPF"
            ))
        })?;
        let out_ty = MirType::Array {
            elem: Box::new(elem_ty.clone()),
            len: out_len,
        };
        let out_size = out_ty.size();
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

        let elem_size = elem_ty.size();
        let input_size = array_len.checked_mul(elem_size).ok_or_else(|| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} typed fixed-array input byte length overflowed in eBPF"
            ))
        })?;
        let insert_offset = if cmd_name == "prepend" { elem_size } else { 0 };
        if input_size > 0 {
            self.emit_ptr_to_slot_copy(out_slot, insert_offset, input_vreg, 0, input_size)?;
        }

        let item_offset = if cmd_name == "prepend" { 0 } else { input_size };
        match insert_item {
            InsertItem::Scalar(item_val) => {
                self.emit(MirInst::StoreSlot {
                    slot: out_slot,
                    offset: Self::checked_mir_offset(item_offset, "typed fixed-array insert item")?,
                    val: item_val,
                    ty: elem_ty,
                });
            }
            InsertItem::Aggregate { ptr, copy_size } => {
                if elem_size > 0 {
                    self.emit_ptr_zero(result_vreg, item_offset, elem_size)?;
                    self.emit_ptr_copy_with_offsets(result_vreg, item_offset, ptr, 0, copy_size)?;
                }
            }
        }

        let item_constant = self.get_metadata(item_reg).and_then(|meta| {
            meta.constant_value.clone().or_else(|| {
                meta.literal_int
                    .map(|value| nu_protocol::Value::int(value, Span::unknown()))
            })
        });
        let constant_value = match (&input_meta.constant_value, item_constant) {
            (Some(nu_protocol::Value::List { vals, .. }), Some(item)) => {
                let mut vals = vals.clone();
                if cmd_name == "prepend" {
                    vals.insert(0, item);
                } else {
                    vals.push(item);
                }
                Some(nu_protocol::Value::list(vals, Span::unknown()))
            }
            _ => None,
        };
        let annotated_semantics = match &input_meta.annotated_semantics {
            Some(AnnotatedValueSemantics::FixedArray { elem, .. }) => {
                Some(AnnotatedValueSemantics::FixedArray {
                    elem: elem.clone(),
                    len: out_len,
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

    pub(super) fn lower_stack_list_first_or_last_scalar(
        &mut self,
        cmd_name: &str,
        src_dst: RegId,
        dst_vreg: VReg,
        src_dst_had_value: bool,
    ) -> Result<(), CompileError> {
        let mut input_vreg = self.pipeline_input.unwrap_or(dst_vreg);
        let input_reg = self
            .pipeline_input_reg
            .or(src_dst_had_value.then_some(src_dst));

        if !matches!(cmd_name, "first" | "last") {
            return Err(CompileError::UnsupportedInstruction(format!(
                "unsupported stack list scalar command '{cmd_name}'"
            )));
        }
        if !self.named_flags.is_empty()
            || !self.named_args.is_empty()
            || !self.positional_args.is_empty()
        {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} does not accept arguments in scalar eBPF list lowering"
            )));
        }

        let Some(input_reg) = input_reg else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a pipeline input in eBPF"
            )));
        };
        let input_meta = self.get_metadata(input_reg).cloned();

        if let Some(projected) = self
            .compile_time_only_list_builder_values(input_reg, input_vreg)
            .map(|values| {
                if values.is_empty() {
                    return Ok::<nu_protocol::Value, CompileError>(nu_protocol::Value::nothing(
                        Span::unknown(),
                    ));
                }
                Ok(if cmd_name == "first" {
                    values[0].clone()
                } else {
                    values[values.len() - 1].clone()
                })
            })
            .transpose()?
        {
            self.lower_compile_time_list_transform_result(src_dst, &projected)?;
        } else if input_meta
            .as_ref()
            .and_then(|meta| meta.list_buffer)
            .is_some()
        {
            let input_meta = input_meta.expect("checked stack-list metadata");
            let known_len = Self::numeric_list_known_len(&input_meta);
            let min_len = input_meta.list_min_len.or(known_len);
            if cmd_name == "first" && min_len.unwrap_or(0) == 0 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires a stack-backed numeric list with proven non-empty length in eBPF"
                )));
            }
            if cmd_name == "last" && min_len.unwrap_or(0) == 0 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires a stack-backed numeric list with proven non-empty length in eBPF"
                )));
            }

            let result_vreg = if src_dst_had_value {
                self.assign_fresh_vreg(src_dst)
            } else {
                dst_vreg
            };

            let idx = if cmd_name == "first" {
                MirValue::Const(0)
            } else {
                let len_vreg = self.func.alloc_vreg();
                let idx_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListLen {
                    dst: len_vreg,
                    list: input_vreg,
                });
                self.vreg_type_hints.insert(len_vreg, MirType::U64);
                self.emit(MirInst::BinOp {
                    dst: idx_vreg,
                    op: BinOpKind::Sub,
                    lhs: MirValue::VReg(len_vreg),
                    rhs: MirValue::Const(1),
                });
                self.vreg_type_hints.insert(idx_vreg, MirType::U64);
                MirValue::VReg(idx_vreg)
            };

            self.emit(MirInst::ListGet {
                dst: result_vreg,
                list: input_vreg,
                idx,
            });
            self.reset_call_result_metadata(src_dst);
            let out_meta = self.get_or_create_metadata(src_dst);
            out_meta.field_type = Some(MirType::I64);
            out_meta.constant_value = match &input_meta.constant_value {
                Some(nu_protocol::Value::List { vals, .. }) => {
                    if cmd_name == "first" {
                        vals.first().cloned()
                    } else {
                        vals.last().cloned()
                    }
                }
                _ => None,
            };
            self.vreg_type_hints.insert(result_vreg, MirType::I64);
        } else if let Some(mut base_runtime_ty) =
            self.typed_value_runtime_type(input_reg, input_vreg)
            && let Some(array_len) =
                Self::aggregate_call_value_type(&base_runtime_ty).and_then(|ty| match ty {
                    MirType::Array { len, .. } => Some(*len),
                    _ => None,
                })
        {
            if array_len == 0 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires a non-empty typed fixed-array input in eBPF"
                )));
            }

            let idx_usize = if cmd_name == "first" {
                0
            } else {
                array_len.saturating_sub(1)
            };
            let idx_i64 = i64::try_from(idx_usize).map_err(|_| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} typed fixed-array index is too large for eBPF"
                ))
            })?;

            let result_vreg = if src_dst_had_value {
                self.assign_fresh_vreg(src_dst)
            } else {
                dst_vreg
            };

            if !matches!(base_runtime_ty, MirType::Ptr { .. })
                && Self::aggregate_call_value_type(&base_runtime_ty).is_some()
            {
                input_vreg = self.materialized_metadata_aggregate_vreg(input_reg, input_vreg)?;
                base_runtime_ty = self
                    .typed_value_runtime_type(input_reg, input_vreg)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "{cmd_name} requires typed fixed-array input in eBPF"
                        ))
                    })?;
            }

            let projected_constant =
                input_meta
                    .as_ref()
                    .and_then(|meta| match &meta.constant_value {
                        Some(nu_protocol::Value::List { vals, .. }) => vals.get(idx_usize).cloned(),
                        _ => None,
                    });
            let projected_semantics =
                input_meta
                    .as_ref()
                    .and_then(|meta| match &meta.annotated_semantics {
                        Some(AnnotatedValueSemantics::FixedArray { elem, .. }) => {
                            Some((**elem).clone())
                        }
                        _ => None,
                    });
            let projected_string_bytes = match projected_constant.as_ref() {
                Some(nu_protocol::Value::String { val, .. })
                | Some(nu_protocol::Value::Glob { val, .. })
                    if matches!(
                        projected_semantics,
                        Some(AnnotatedValueSemantics::String { .. })
                    ) =>
                {
                    Some(val.as_bytes().to_vec())
                }
                _ => None,
            };

            if let Some(bytes) = projected_string_bytes {
                self.reset_call_result_metadata(src_dst);
                self.lower_string_like_literal(src_dst, result_vreg, &bytes)?;
                self.set_reg_constant_value(src_dst, projected_constant);
            } else {
                let root_ctx_field = self
                    .get_metadata(input_reg)
                    .and_then(|meta| meta.root_ctx_field.clone());
                self.lower_dynamic_typed_numeric_get(
                    src_dst,
                    input_vreg,
                    &base_runtime_ty,
                    MirValue::Const(idx_i64),
                    projected_semantics.as_ref(),
                    root_ctx_field.as_ref(),
                )?;
                let out_meta = self.get_or_create_metadata(src_dst);
                out_meta.constant_value = projected_constant;
                out_meta.annotated_semantics = projected_semantics;
            }
        } else {
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
        }

        Ok(())
    }

    pub(super) fn lower_stack_list_take_skip_or_drop(
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

        if !self.named_flags.is_empty() || !self.named_args.is_empty() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} does not accept named flags or arguments in eBPF"
            )));
        }

        let raw_count = match cmd_name {
            "skip" | "drop" => {
                if self.positional_args.len() > 1 {
                    return Err(CompileError::UnsupportedInstruction(format!(
                        "{cmd_name} accepts at most one positional count argument in eBPF"
                    )));
                }
                if let Some((_, count_reg)) = self.positional_args.first() {
                    self.get_metadata(*count_reg)
                        .and_then(|m| m.literal_int)
                        .ok_or_else(|| {
                            CompileError::UnsupportedInstruction(format!(
                                "{cmd_name} count must be a compile-time integer literal in eBPF"
                            ))
                        })?
                } else {
                    1
                }
            }
            "take" | "first" => {
                if self.positional_args.len() != 1 {
                    return Err(CompileError::UnsupportedInstruction(
                        format!(
                            "{cmd_name} requires exactly one positional count argument in eBPF"
                        )
                        .into(),
                    ));
                }
                let (_, count_reg) = self.positional_args[0];
                self.get_metadata(count_reg)
                    .and_then(|m| m.literal_int)
                    .ok_or_else(|| {
                        CompileError::UnsupportedInstruction(format!(
                            "{cmd_name} count must be a compile-time integer literal in eBPF"
                        ))
                    })?
            }
            _ => {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "unsupported stack list slice command '{cmd_name}'"
                )));
            }
        };

        if raw_count < 0 {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} count must be non-negative in eBPF"
            )));
        }
        let count = usize::try_from(raw_count).map_err(|_| {
            CompileError::UnsupportedInstruction(format!(
                "{cmd_name} count is too large for eBPF list lowering"
            ))
        })?;

        if let Some(values) = input_reg.and_then(|reg| {
            self.compile_time_only_list_builder_values(reg, input_vreg)
                .map(|values| values.to_vec())
        }) {
            let vals = match cmd_name {
                "take" | "first" => values.into_iter().take(count).collect::<Vec<_>>(),
                "skip" => values.into_iter().skip(count).collect::<Vec<_>>(),
                "drop" => {
                    let keep_len = values.len().saturating_sub(count);
                    values.into_iter().take(keep_len).collect::<Vec<_>>()
                }
                _ => unreachable!("validated stack list slice command"),
            };
            self.lower_compile_time_list_transform_result(
                src_dst,
                &nu_protocol::Value::list(vals, Span::unknown()),
            )?;
            return Ok(());
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "{cmd_name} requires a pipeline input with tracked metadata in eBPF"
                ))
            })?;
        if let Some(input_reg) = input_reg
            && self.lower_typed_fixed_array_count_slice(
                cmd_name,
                src_dst,
                dst_vreg,
                src_dst_had_value,
                input_reg,
                input_vreg,
                &input_meta,
                count,
            )?
        {
            return Ok(());
        }
        let Some((_input_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(format!(
                "{cmd_name} requires a stack-backed list input in eBPF"
            )));
        };

        let (source_start, source_end, out_max_len, guard_tail_drop) = match cmd_name {
            "take" | "first" => {
                let take_count = count.min(max_len);
                (0, take_count, take_count, 0)
            }
            "skip" => {
                let skip_count = count.min(max_len);
                (skip_count, max_len, max_len.saturating_sub(skip_count), 0)
            }
            "drop" => {
                let drop_count = count.min(max_len);
                let out_max_len = max_len.saturating_sub(drop_count);
                (0, out_max_len, out_max_len, drop_count)
            }
            _ => unreachable!("validated stack list slice command"),
        };
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, out_max_len);

        if source_start < source_end {
            let len_vreg = self.func.alloc_vreg();
            self.emit(MirInst::ListLen {
                dst: len_vreg,
                list: input_vreg,
            });
            self.vreg_type_hints.insert(len_vreg, MirType::U64);

            let continuation_block = self.func.alloc_block();
            for source_index in source_start..source_end {
                let copy_block = self.func.alloc_block();
                let next_block = if source_index + 1 == source_end {
                    continuation_block
                } else {
                    self.func.alloc_block()
                };

                let cond_vreg = self.func.alloc_vreg();
                let guard_index = source_index.saturating_add(guard_tail_drop);
                self.emit(MirInst::BinOp {
                    dst: cond_vreg,
                    op: BinOpKind::Lt,
                    lhs: MirValue::Const(guard_index as i64),
                    rhs: MirValue::VReg(len_vreg),
                });
                self.vreg_type_hints.insert(cond_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: cond_vreg,
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
        }

        let known_len = Self::numeric_list_known_len(&input_meta).map(|known_len| match cmd_name {
            "take" | "first" => known_len.min(count).min(out_max_len),
            "skip" | "drop" => known_len.saturating_sub(count).min(out_max_len),
            _ => unreachable!("validated stack list slice command"),
        });
        let constant_value = match input_meta.constant_value {
            Some(nu_protocol::Value::List { vals, .. }) => {
                let vals = match cmd_name {
                    "take" | "first" => vals.into_iter().take(count).collect::<Vec<_>>(),
                    "skip" => vals.into_iter().skip(count).collect::<Vec<_>>(),
                    "drop" => {
                        let keep_len = vals.len().saturating_sub(count);
                        vals.into_iter().take(keep_len).collect::<Vec<_>>()
                    }
                    _ => unreachable!("validated stack list slice command"),
                };
                Some(nu_protocol::Value::list(vals, Span::unknown()))
            }
            _ => None,
        };

        self.install_stack_numeric_list_result_metadata(
            src_dst,
            out_slot,
            out_ty,
            out_max_len,
            known_len,
        );
        if let Some(value) = constant_value {
            self.get_or_create_metadata(src_dst).constant_value = Some(value);
        }
        Ok(())
    }

    pub(super) fn lower_stack_list_reverse(
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
                "reverse does not accept arguments in eBPF".into(),
            ));
        }

        if let Some(mut values) = input_reg.and_then(|reg| {
            self.compile_time_only_list_builder_values(reg, input_vreg)
                .map(|values| values.to_vec())
        }) {
            values.reverse();
            self.lower_compile_time_list_transform_result(
                src_dst,
                &nu_protocol::Value::list(values, Span::unknown()),
            )?;
            return Ok(());
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "reverse requires a pipeline input with tracked metadata in eBPF".into(),
                )
            })?;
        if let Some(input_reg) = input_reg
            && self.lower_typed_fixed_array_reverse(
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
                "reverse requires a stack-backed list input in eBPF".into(),
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
            for output_index in 0..max_len {
                let source_index = max_len - 1 - output_index;
                let copy_block = self.func.alloc_block();
                let next_block = if output_index + 1 == max_len {
                    continuation_block
                } else {
                    self.func.alloc_block()
                };

                let cond_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: cond_vreg,
                    op: BinOpKind::Lt,
                    lhs: MirValue::Const(source_index as i64),
                    rhs: MirValue::VReg(len_vreg),
                });
                self.vreg_type_hints.insert(cond_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: cond_vreg,
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
        }

        let known_len = Self::numeric_list_known_len(&input_meta).map(|len| len.min(max_len));
        let constant_value = match input_meta.constant_value {
            Some(nu_protocol::Value::List { mut vals, .. }) => {
                vals.reverse();
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

    pub(super) fn lower_stack_list_last_count(
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
            || self.positional_args.len() != 1
        {
            return Err(CompileError::UnsupportedInstruction(
                "last requires exactly one positional count argument in eBPF".into(),
            ));
        }

        let (_, count_reg) = self.positional_args[0];
        let raw_count = self
            .get_metadata(count_reg)
            .and_then(|m| m.literal_int)
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "last count must be a compile-time integer literal in eBPF".into(),
                )
            })?;
        if raw_count < 0 {
            return Err(CompileError::UnsupportedInstruction(
                "last count must be non-negative in eBPF".into(),
            ));
        }
        let count = usize::try_from(raw_count).map_err(|_| {
            CompileError::UnsupportedInstruction(
                "last count is too large for eBPF list lowering".into(),
            )
        })?;

        if let Some(values) = input_reg.and_then(|reg| {
            self.compile_time_only_list_builder_values(reg, input_vreg)
                .map(|values| values.to_vec())
        }) {
            let start = values.len().saturating_sub(count);
            self.lower_compile_time_list_transform_result(
                src_dst,
                &nu_protocol::Value::list(
                    values.into_iter().skip(start).collect::<Vec<_>>(),
                    Span::unknown(),
                ),
            )?;
            return Ok(());
        }

        let input_meta = input_reg
            .and_then(|reg| self.get_metadata(reg).cloned())
            .ok_or_else(|| {
                CompileError::UnsupportedInstruction(
                    "last requires a stack-backed list input in eBPF".into(),
                )
            })?;
        if let Some(input_reg) = input_reg
            && self.lower_typed_fixed_array_count_slice(
                "last",
                src_dst,
                dst_vreg,
                src_dst_had_value,
                input_reg,
                input_vreg,
                &input_meta,
                count,
            )?
        {
            return Ok(());
        }
        let Some((_input_slot, max_len)) = input_meta.list_buffer else {
            return Err(CompileError::UnsupportedInstruction(
                "last requires a stack-backed list input in eBPF".into(),
            ));
        };

        let out_max_len = count.min(max_len);
        let result_vreg = if src_dst_had_value {
            self.assign_fresh_vreg(src_dst)
        } else {
            dst_vreg
        };
        let temp_vreg = self.func.alloc_vreg();
        let (out_slot, out_ty) = self.create_stack_numeric_list_result(result_vreg, out_max_len);
        self.create_stack_numeric_list_result(temp_vreg, out_max_len);

        if max_len > 0 && out_max_len > 0 {
            let input_len_vreg = self.func.alloc_vreg();
            self.emit(MirInst::ListLen {
                dst: input_len_vreg,
                list: input_vreg,
            });
            self.vreg_type_hints.insert(input_len_vreg, MirType::U64);

            let reverse_block = self.func.alloc_block();
            for source_index in (0..max_len).rev() {
                let capacity_block = self.func.alloc_block();
                let push_block = self.func.alloc_block();
                let next_block = if source_index == 0 {
                    reverse_block
                } else {
                    self.func.alloc_block()
                };

                let in_bounds_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: in_bounds_vreg,
                    op: BinOpKind::Lt,
                    lhs: MirValue::Const(source_index as i64),
                    rhs: MirValue::VReg(input_len_vreg),
                });
                self.vreg_type_hints.insert(in_bounds_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: in_bounds_vreg,
                    if_true: capacity_block,
                    if_false: next_block,
                });

                self.current_block = capacity_block;
                let temp_len_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListLen {
                    dst: temp_len_vreg,
                    list: temp_vreg,
                });
                self.vreg_type_hints.insert(temp_len_vreg, MirType::U64);
                let has_capacity_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: has_capacity_vreg,
                    op: BinOpKind::Lt,
                    lhs: MirValue::VReg(temp_len_vreg),
                    rhs: MirValue::Const(out_max_len as i64),
                });
                self.vreg_type_hints
                    .insert(has_capacity_vreg, MirType::Bool);
                self.terminate(MirInst::Branch {
                    cond: has_capacity_vreg,
                    if_true: push_block,
                    if_false: next_block,
                });

                self.current_block = push_block;
                let item_vreg = self.func.alloc_vreg();
                self.emit(MirInst::ListGet {
                    dst: item_vreg,
                    list: input_vreg,
                    idx: MirValue::Const(source_index as i64),
                });
                self.vreg_type_hints.insert(item_vreg, MirType::I64);
                self.emit(MirInst::ListPush {
                    list: temp_vreg,
                    item: item_vreg,
                });
                self.terminate(MirInst::Jump { target: next_block });

                self.current_block = next_block;
            }

            let temp_len_vreg = self.func.alloc_vreg();
            self.emit(MirInst::ListLen {
                dst: temp_len_vreg,
                list: temp_vreg,
            });
            self.vreg_type_hints.insert(temp_len_vreg, MirType::U64);

            let continuation_block = self.func.alloc_block();
            for temp_index in (0..out_max_len).rev() {
                let copy_block = self.func.alloc_block();
                let next_block = if temp_index == 0 {
                    continuation_block
                } else {
                    self.func.alloc_block()
                };

                let in_bounds_vreg = self.func.alloc_vreg();
                self.emit(MirInst::BinOp {
                    dst: in_bounds_vreg,
                    op: BinOpKind::Lt,
                    lhs: MirValue::Const(temp_index as i64),
                    rhs: MirValue::VReg(temp_len_vreg),
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
                    list: temp_vreg,
                    idx: MirValue::Const(temp_index as i64),
                });
                self.vreg_type_hints.insert(item_vreg, MirType::I64);
                self.emit(MirInst::ListPush {
                    list: result_vreg,
                    item: item_vreg,
                });
                self.terminate(MirInst::Jump { target: next_block });

                self.current_block = next_block;
            }
            self.current_block = continuation_block;
        }

        let known_len = Self::numeric_list_known_len(&input_meta).map(|len| len.min(count));
        let constant_value = match input_meta.constant_value {
            Some(nu_protocol::Value::List { vals, .. }) => {
                let start = vals.len().saturating_sub(count);
                Some(nu_protocol::Value::list(
                    vals.into_iter().skip(start).collect::<Vec<_>>(),
                    Span::unknown(),
                ))
            }
            _ => None,
        };

        self.install_stack_numeric_list_result_metadata(
            src_dst,
            out_slot,
            out_ty,
            out_max_len,
            known_len,
        );
        if let Some(value) = constant_value {
            self.get_or_create_metadata(src_dst).constant_value = Some(value);
        }
        Ok(())
    }

    pub(super) fn install_stack_numeric_list_result_metadata(
        &mut self,
        src_dst: RegId,
        out_slot: StackSlotId,
        out_ty: MirType,
        max_len: usize,
        known_len: Option<usize>,
    ) {
        self.reset_call_result_metadata(src_dst);
        let out_meta = self.get_or_create_metadata(src_dst);
        out_meta.list_buffer = Some((out_slot, max_len));
        out_meta.list_min_len = known_len;
        out_meta.field_type = Some(out_ty);
        out_meta.annotated_semantics =
            Some(AnnotatedValueSemantics::NumericList { max_len, known_len });
    }
}
