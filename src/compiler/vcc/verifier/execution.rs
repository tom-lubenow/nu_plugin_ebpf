use super::*;

impl VccVerifier {
    pub(super) fn verify_inst(&mut self, inst: &VccInst, state: &mut VccState) {
        if !state.is_reachable() {
            return;
        }
        match inst {
            VccInst::Const { dst, value } => {
                state.set_reg(
                    *dst,
                    VccValueType::Scalar {
                        range: Some(VccRange {
                            min: *value,
                            max: *value,
                        }),
                    },
                );
                if *value != 0 {
                    state.set_not_equal_const(*dst, 0);
                }
            }
            VccInst::Copy { dst, src } => match state.value_type(*src) {
                Ok(ty) => {
                    let (copied_refinement, src_not_equal) = match src {
                        VccValue::Reg(src_reg) => (
                            state.cond_refinement(*src_reg),
                            state.not_equal_consts(*src_reg).to_vec(),
                        ),
                        VccValue::Imm(v) if *v != 0 => (None, vec![0]),
                        _ => (None, Vec::new()),
                    };
                    state.set_reg(*dst, ty);
                    if let Some(refinement) = copied_refinement {
                        state.set_cond_refinement(*dst, refinement);
                    }
                    for value in src_not_equal {
                        state.set_not_equal_const(*dst, value);
                    }
                }
                Err(err) => self.errors.push(err),
            },
            VccInst::Assume { dst, ty } => {
                state.set_reg(*dst, *ty);
            }
            VccInst::AssertScalar { value } => match state.value_type(*value) {
                Ok(ty) => {
                    if ty.class() != VccTypeClass::Scalar && ty.class() != VccTypeClass::Bool {
                        self.errors.push(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Scalar,
                                actual: ty.class(),
                            },
                            "expected scalar value",
                        ));
                    }
                }
                Err(err) => self.errors.push(err),
            },
            VccInst::AssertPositive { value, message } => {
                let ty = match state.value_type(*value) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                if ty.class() != VccTypeClass::Scalar && ty.class() != VccTypeClass::Bool {
                    self.errors.push(VccError::new(
                        VccErrorKind::TypeMismatch {
                            expected: VccTypeClass::Scalar,
                            actual: ty.class(),
                        },
                        "expected scalar value",
                    ));
                    return;
                }
                if let Some(range) = state.value_range(*value, ty) {
                    if range.max <= 0 || range.min <= 0 {
                        self.errors.push(VccError::new(
                            VccErrorKind::UnsupportedInstruction,
                            message.clone(),
                        ));
                    }
                }
            }
            VccInst::AssertConstEq {
                value,
                expected,
                message,
            } => {
                let ty = match state.value_type(*value) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                if ty.class() != VccTypeClass::Scalar && ty.class() != VccTypeClass::Bool {
                    self.errors.push(VccError::new(
                        VccErrorKind::TypeMismatch {
                            expected: VccTypeClass::Scalar,
                            actual: ty.class(),
                        },
                        "expected scalar value",
                    ));
                    return;
                }
                let Some(range) = state.value_range(*value, ty) else {
                    self.errors.push(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        message.clone(),
                    ));
                    return;
                };
                if range.min != *expected || range.max != *expected {
                    self.errors.push(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        message.clone(),
                    ));
                }
            }
            VccInst::AssertKnownConst { value, message } => {
                let ty = match state.value_type(*value) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                if ty.class() != VccTypeClass::Scalar && ty.class() != VccTypeClass::Bool {
                    self.errors.push(VccError::new(
                        VccErrorKind::TypeMismatch {
                            expected: VccTypeClass::Scalar,
                            actual: ty.class(),
                        },
                        "expected scalar value",
                    ));
                    return;
                }
                let Some(range) = state.value_range(*value, ty) else {
                    self.errors.push(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        message.clone(),
                    ));
                    return;
                };
                if range.min != range.max {
                    self.errors.push(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        message.clone(),
                    ));
                }
            }
            VccInst::AssertPtrAccess { ptr, size, op } => {
                let ptr_ty = match state.reg_type(*ptr) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                let ptr_info = match ptr_ty {
                    VccValueType::Ptr(info) => {
                        if let Err(err) = self.require_non_null_ptr(info, op) {
                            self.errors.push(err);
                            return;
                        }
                        info
                    }
                    other => {
                        self.errors.push(VccError::new(
                            VccErrorKind::InvalidLoadStore,
                            format!("{op} requires pointer operand (got {:?})", other.class()),
                        ));
                        return;
                    }
                };
                let size_ty = match state.value_type(*size) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                if size_ty.class() != VccTypeClass::Scalar && size_ty.class() != VccTypeClass::Bool
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::TypeMismatch {
                            expected: VccTypeClass::Scalar,
                            actual: size_ty.class(),
                        },
                        format!("{op} size must be scalar"),
                    ));
                    return;
                }
                if let Some(size_range) = state.value_range(*size, size_ty) {
                    if size_range.max <= 0 || size_range.min <= 0 {
                        self.errors.push(VccError::new(
                            VccErrorKind::UnsupportedInstruction,
                            format!("{op} size must be > 0"),
                        ));
                        return;
                    }
                    if let (VccAddrSpace::Stack(_) | VccAddrSpace::MapValue, Some(bounds)) =
                        (ptr_info.space, ptr_info.bounds)
                    {
                        if bounds.shifted_with_size(0, size_range.max).is_none() {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                format!("{op} out of bounds"),
                            ));
                        }
                    }
                } else if matches!(ptr_info.space, VccAddrSpace::Stack(_) | VccAddrSpace::MapValue)
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!("{op} size must have bounded upper range"),
                    ));
                }
            }
            VccInst::AssertStackSlotBase { ptr, op } => {
                let _ = self.stack_slot_from_reg(state, *ptr, op);
            }
            VccInst::AssertDistinctStackSlots { lhs, rhs, message } => {
                let Some(lhs_slot) =
                    self.stack_slot_from_reg(state, *lhs, "kfunc 'bpf_dynptr_clone' arg0")
                else {
                    return;
                };
                let Some(rhs_slot) =
                    self.stack_slot_from_reg(state, *rhs, "kfunc 'bpf_dynptr_clone' arg1")
                else {
                    return;
                };
                if lhs_slot == rhs_slot {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        message.clone(),
                    ));
                }
            }
            VccInst::StackAddr { dst, slot, size } => {
                let bounds = if *size > 0 {
                    Some(VccBounds {
                        min: 0,
                        max: 0,
                        limit: size.saturating_sub(1),
                    })
                } else {
                    None
                };
                state.set_reg(
                    *dst,
                    VccValueType::Ptr(VccPointerInfo {
                        space: VccAddrSpace::Stack(*slot),
                        nullability: VccNullability::NonNull,
                        bounds,
                        ringbuf_ref: None,
                        kfunc_ref: None,
                    }),
                );
            }
            VccInst::BinOp { dst, op, lhs, rhs } => {
                let lhs_ty = match state.value_type(*lhs) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                let rhs_ty = match state.value_type(*rhs) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };

                match op {
                    VccBinOp::Eq | VccBinOp::Ne => {
                        let ptr_cmp = self.ptr_null_comparison(*lhs, lhs_ty, *rhs, rhs_ty);
                        let ptr_cond_cmp =
                            self.ptr_cond_comparison(*op, *lhs, lhs_ty, *rhs, rhs_ty, state);
                        let scalar_cmp =
                            self.scalar_const_comparison(*lhs, lhs_ty, *rhs, rhs_ty, *op);
                        let scalar_reg_cmp =
                            self.scalar_reg_comparison(*lhs, lhs_ty, *rhs, rhs_ty, *op);
                        let lhs_is_ptr = matches!(lhs_ty, VccValueType::Ptr(_));
                        let rhs_is_ptr = matches!(rhs_ty, VccValueType::Ptr(_));
                        if lhs_is_ptr || rhs_is_ptr {
                            match (lhs_ty, rhs_ty) {
                                (VccValueType::Ptr(lp), VccValueType::Ptr(rp)) => {
                                    if lp.space != rp.space
                                        && lp.space != VccAddrSpace::Unknown
                                        && rp.space != VccAddrSpace::Unknown
                                    {
                                        self.errors.push(VccError::new(
                                            VccErrorKind::TypeMismatch {
                                                expected: VccTypeClass::Ptr,
                                                actual: VccTypeClass::Ptr,
                                            },
                                            "pointer comparison requires matching address space",
                                        ));
                                        return;
                                    }
                                }
                                (VccValueType::Ptr(_), other) | (other, VccValueType::Ptr(_)) => {
                                    if !self.is_null_scalar(*lhs, lhs_ty)
                                        && !self.is_null_scalar(*rhs, rhs_ty)
                                        && other.class() != VccTypeClass::Ptr
                                    {
                                        self.errors.push(VccError::new(
                                            VccErrorKind::TypeMismatch {
                                                expected: VccTypeClass::Scalar,
                                                actual: other.class(),
                                            },
                                            "pointer comparison only supports null scalar",
                                        ));
                                        return;
                                    }
                                }
                                _ => {}
                            }
                        } else if lhs_ty.class() != VccTypeClass::Scalar
                            && lhs_ty.class() != VccTypeClass::Bool
                        {
                            self.errors.push(VccError::new(
                                VccErrorKind::TypeMismatch {
                                    expected: VccTypeClass::Scalar,
                                    actual: lhs_ty.class(),
                                },
                                "comparison expects scalar operands",
                            ));
                            return;
                        } else if rhs_ty.class() != VccTypeClass::Scalar
                            && rhs_ty.class() != VccTypeClass::Bool
                        {
                            self.errors.push(VccError::new(
                                VccErrorKind::TypeMismatch {
                                    expected: VccTypeClass::Scalar,
                                    actual: rhs_ty.class(),
                                },
                                "comparison expects scalar operands",
                            ));
                            return;
                        }
                        state.set_reg(*dst, VccValueType::Bool);
                        if let Some((ptr_reg, ringbuf_ref, kfunc_ref)) = ptr_cmp {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement::PtrNull {
                                    ptr_reg,
                                    ringbuf_ref,
                                    kfunc_ref,
                                    true_means_non_null: matches!(op, VccBinOp::Ne),
                                },
                            );
                        } else if let Some((ptr_reg, ringbuf_ref, kfunc_ref, true_means_non_null)) =
                            ptr_cond_cmp
                        {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement::PtrNull {
                                    ptr_reg,
                                    ringbuf_ref,
                                    kfunc_ref,
                                    true_means_non_null,
                                },
                            );
                        } else if let Some((reg, cmp_op, value)) = scalar_cmp {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement::ScalarCmpConst {
                                    reg,
                                    op: cmp_op,
                                    value,
                                },
                            );
                        } else if let Some((lhs, rhs, cmp_op)) = scalar_reg_cmp {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement::ScalarCmpRegs {
                                    lhs,
                                    rhs,
                                    op: cmp_op,
                                },
                            );
                        }
                    }
                    VccBinOp::Lt | VccBinOp::Le | VccBinOp::Gt | VccBinOp::Ge => {
                        let scalar_cmp =
                            self.scalar_const_comparison(*lhs, lhs_ty, *rhs, rhs_ty, *op);
                        let scalar_reg_cmp =
                            self.scalar_reg_comparison(*lhs, lhs_ty, *rhs, rhs_ty, *op);
                        if lhs_ty.class() != VccTypeClass::Scalar
                            && lhs_ty.class() != VccTypeClass::Bool
                        {
                            self.errors.push(VccError::new(
                                VccErrorKind::TypeMismatch {
                                    expected: VccTypeClass::Scalar,
                                    actual: lhs_ty.class(),
                                },
                                "comparison expects scalar operands",
                            ));
                            return;
                        }
                        if rhs_ty.class() != VccTypeClass::Scalar
                            && rhs_ty.class() != VccTypeClass::Bool
                        {
                            self.errors.push(VccError::new(
                                VccErrorKind::TypeMismatch {
                                    expected: VccTypeClass::Scalar,
                                    actual: rhs_ty.class(),
                                },
                                "comparison expects scalar operands",
                            ));
                            return;
                        }
                        state.set_reg(*dst, VccValueType::Bool);
                        if let Some((reg, cmp_op, value)) = scalar_cmp {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement::ScalarCmpConst {
                                    reg,
                                    op: cmp_op,
                                    value,
                                },
                            );
                        } else if let Some((lhs, rhs, cmp_op)) = scalar_reg_cmp {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement::ScalarCmpRegs {
                                    lhs,
                                    rhs,
                                    op: cmp_op,
                                },
                            );
                        }
                    }
                    _ => {
                        if lhs_ty.class() != VccTypeClass::Scalar
                            && lhs_ty.class() != VccTypeClass::Bool
                        {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerArithmetic,
                                "binop requires scalar operands (pointer used)",
                            ));
                            return;
                        }
                        if rhs_ty.class() != VccTypeClass::Scalar
                            && rhs_ty.class() != VccTypeClass::Bool
                        {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerArithmetic,
                                "binop requires scalar operands (pointer used)",
                            ));
                            return;
                        }
                        let range = state.binop_range(*op, *lhs, lhs_ty, *rhs, rhs_ty);
                        state.set_reg(*dst, VccValueType::Scalar { range });
                    }
                }
            }
            VccInst::PtrAdd { dst, base, offset } => {
                let base_ty = state.reg_type(*base);
                let base_ptr = match base_ty {
                    Ok(VccValueType::Ptr(ptr)) => ptr,
                    Ok(other) => {
                        self.errors.push(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Ptr,
                                actual: other.class(),
                            },
                            "ptr_add base must be a pointer",
                        ));
                        return;
                    }
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };

                let offset_ty = match state.value_type(*offset) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                if offset_ty.class() != VccTypeClass::Scalar
                    && offset_ty.class() != VccTypeClass::Bool
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerArithmetic,
                        "ptr_add offset must be scalar",
                    ));
                    return;
                }

                let offset_range = state.value_range(*offset, offset_ty);
                let bounds = match (base_ptr.bounds, offset_range) {
                    (Some(bounds), Some(range)) => {
                        bounds.shifted(range).map(Some).unwrap_or_else(|| {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                "pointer arithmetic out of bounds",
                            ));
                            None
                        })
                    }
                    (Some(_), None) => {
                        self.errors.push(VccError::new(
                            VccErrorKind::UnknownOffset,
                            "pointer arithmetic requires bounded scalar offset",
                        ));
                        None
                    }
                    _ => base_ptr.bounds,
                };

                state.set_reg(
                    *dst,
                    VccValueType::Ptr(VccPointerInfo {
                        space: base_ptr.space,
                        nullability: base_ptr.nullability,
                        bounds,
                        ringbuf_ref: base_ptr.ringbuf_ref,
                        kfunc_ref: base_ptr.kfunc_ref,
                    }),
                );
            }
            VccInst::Load {
                dst,
                ptr,
                offset,
                size,
            } => {
                let ptr_ty = match state.reg_type(*ptr) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                match ptr_ty {
                    VccValueType::Ptr(ptr_info) => {
                        if let Err(err) = self.require_non_null_ptr(ptr_info, "load") {
                            self.errors.push(err);
                            return;
                        }
                        if !Self::is_mem_space_allowed(ptr_info.space) {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                format!(
                                    "load requires pointer in [Stack, Map], got {}",
                                    Self::space_name(ptr_info.space)
                                ),
                            ));
                            return;
                        }
                        if let Some(bounds) = ptr_info.bounds {
                            let size = *size as i64;
                            if size <= 0 {
                                self.errors.push(VccError::new(
                                    VccErrorKind::InvalidLoadStore,
                                    "load size must be positive",
                                ));
                                return;
                            }
                            if bounds.shifted_with_size(*offset, size).is_none() {
                                self.errors.push(VccError::new(
                                    VccErrorKind::PointerBounds,
                                    "load offset out of bounds",
                                ));
                            }
                        }
                    }
                    other => {
                        self.errors.push(VccError::new(
                            VccErrorKind::InvalidLoadStore,
                            format!("load requires pointer operand (got {:?})", other.class()),
                        ));
                        return;
                    }
                }
                state.set_reg(*dst, VccValueType::Scalar { range: None });
            }
            VccInst::Store {
                ptr,
                offset,
                src,
                size,
            } => {
                let ptr_ty = match state.reg_type(*ptr) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                match ptr_ty {
                    VccValueType::Ptr(ptr_info) => {
                        if let Err(err) = self.require_non_null_ptr(ptr_info, "store") {
                            self.errors.push(err);
                            return;
                        }
                        if !Self::is_mem_space_allowed(ptr_info.space) {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                format!(
                                    "store requires pointer in [Stack, Map], got {}",
                                    Self::space_name(ptr_info.space)
                                ),
                            ));
                            return;
                        }
                        if let Some(bounds) = ptr_info.bounds {
                            let size = *size as i64;
                            if size <= 0 {
                                self.errors.push(VccError::new(
                                    VccErrorKind::InvalidLoadStore,
                                    "store size must be positive",
                                ));
                                return;
                            }
                            if bounds.shifted_with_size(*offset, size).is_none() {
                                self.errors.push(VccError::new(
                                    VccErrorKind::PointerBounds,
                                    "store offset out of bounds",
                                ));
                            }
                        }
                    }
                    other => {
                        self.errors.push(VccError::new(
                            VccErrorKind::InvalidLoadStore,
                            format!("store requires pointer operand (got {:?})", other.class()),
                        ));
                        return;
                    }
                }

                if let Err(err) = state.value_type(*src) {
                    self.errors.push(err);
                }
            }
            VccInst::Phi { dst, args } => {
                let mut merged: Option<VccValueType> = None;
                for (_, reg) in args {
                    match state.reg_type(*reg) {
                        Ok(ty) => {
                            merged = Some(match merged {
                                None => ty,
                                Some(existing) => state.merge_types(existing, ty),
                            });
                        }
                        Err(err) => self.errors.push(err),
                    }
                }
                let ty = merged.unwrap_or(VccValueType::Unknown);
                state.set_reg(*dst, ty);
                let mut merged_refinement: Option<Option<VccCondRefinement>> = None;
                for (_, reg) in args {
                    let next = state.cond_refinement(*reg);
                    merged_refinement = Some(match merged_refinement {
                        None => next,
                        Some(existing) if existing == next => existing,
                        _ => None,
                    });
                    if matches!(merged_refinement, Some(None)) {
                        break;
                    }
                }
                if let Some(Some(refinement)) = merged_refinement {
                    state.set_cond_refinement(*dst, refinement);
                }
            }
            VccInst::RingbufAcquire { id } => {
                state.set_live_ringbuf_ref(*id, true);
            }
            VccInst::RingbufRelease { ptr } => {
                let ty = match state.value_type(*ptr) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                match ty {
                    VccValueType::Ptr(info) if info.space == VccAddrSpace::RingBuf => {
                        if let Err(err) = self.require_non_null_ptr(info, "ringbuf release") {
                            self.errors.push(err);
                            return;
                        }
                        if let Some(ref_id) = info.ringbuf_ref {
                            if state.is_live_ringbuf_ref(ref_id) {
                                state.invalidate_ringbuf_ref(ref_id);
                            } else {
                                self.errors.push(VccError::new(
                                    VccErrorKind::PointerBounds,
                                    "ringbuf record already released",
                                ));
                            }
                        } else {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                "ringbuf record pointer is not tracked",
                            ));
                        }
                    }
                    VccValueType::Ptr(_) => {
                        self.errors.push(VccError::new(
                            VccErrorKind::PointerBounds,
                            "ringbuf release requires ringbuf record pointer",
                        ));
                    }
                    other => {
                        self.errors.push(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Ptr,
                                actual: other.class(),
                            },
                            "ringbuf release requires pointer operand",
                        ));
                    }
                }
            }
            VccInst::KfuncAcquire { id, kind } => {
                state.set_live_kfunc_ref(*id, true, Some(*kind));
            }
            VccInst::KfuncRelease { ptr, kind, arg_idx } => {
                let ty = match state.value_type(*ptr) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                match ty {
                    VccValueType::Ptr(info) if info.space == VccAddrSpace::Kernel => {
                        if let Err(err) = self.require_non_null_ptr(info, "kfunc release") {
                            self.errors.push(err);
                            return;
                        }
                        if let Some(ref_id) = info.kfunc_ref {
                            if !state.is_live_kfunc_ref(ref_id) {
                                self.errors.push(VccError::new(
                                    VccErrorKind::PointerBounds,
                                    format!("kfunc arg{} reference already released", arg_idx),
                                ));
                                return;
                            }
                            let actual_kind = state.kfunc_ref_kind(ref_id);
                            if actual_kind == Some(*kind) {
                                state.invalidate_kfunc_ref(ref_id);
                            } else {
                                let expected = kind.label();
                                let actual = actual_kind.map(|k| k.label()).unwrap_or("unknown");
                                self.errors.push(VccError::new(
                                    VccErrorKind::PointerBounds,
                                    format!(
                                        "kfunc arg{} expects {} reference, got {} reference",
                                        arg_idx, expected, actual
                                    ),
                                ));
                            }
                        } else {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                format!("kfunc arg{} pointer is not tracked", arg_idx),
                            ));
                        }
                    }
                    VccValueType::Ptr(_) => {
                        let expected = kind.label();
                        self.errors.push(VccError::new(
                            VccErrorKind::PointerBounds,
                            format!(
                                "kfunc arg{} requires kernel {} reference pointer",
                                arg_idx, expected
                            ),
                        ));
                    }
                    other => {
                        self.errors.push(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Ptr,
                                actual: other.class(),
                            },
                            format!("kfunc arg{} requires pointer operand", arg_idx),
                        ));
                    }
                }
            }
            VccInst::RcuReadLockAcquire => {
                state.acquire_rcu_read_lock();
            }
            VccInst::RcuReadLockRelease => {
                if !state.release_rcu_read_lock() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_rcu_read_unlock' requires a matching bpf_rcu_read_lock",
                    ));
                }
            }
            VccInst::PreemptDisableAcquire => {
                state.acquire_preempt_disable();
            }
            VccInst::PreemptDisableRelease => {
                if !state.release_preempt_disable() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_preempt_enable' requires a matching bpf_preempt_disable",
                    ));
                }
            }
            VccInst::LocalIrqDisableAcquire { flags } => {
                let Some(slot) = self.stack_slot_from_reg(state, *flags, "kfunc 'bpf_local_irq_save' arg0") else {
                    return;
                };
                state.acquire_local_irq_disable_slot(slot);
            }
            VccInst::LocalIrqDisableRelease { flags } => {
                let Some(slot) = self.stack_slot_from_reg(state, *flags, "kfunc 'bpf_local_irq_restore' arg0") else {
                    return;
                };
                if !state.release_local_irq_disable_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_local_irq_restore' requires a matching bpf_local_irq_save",
                    ));
                }
            }
            VccInst::ResSpinLockAcquire => {
                state.acquire_res_spin_lock();
            }
            VccInst::ResSpinLockRelease => {
                if !state.release_res_spin_lock() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_res_spin_unlock' requires a matching bpf_res_spin_lock",
                    ));
                }
            }
            VccInst::ResSpinLockIrqsaveAcquire { flags } => {
                let Some(slot) = self.stack_slot_from_reg(
                    state,
                    *flags,
                    "kfunc 'bpf_res_spin_lock_irqsave' arg1",
                ) else {
                    return;
                };
                state.acquire_res_spin_lock_irqsave_slot(slot);
            }
            VccInst::ResSpinLockIrqsaveRelease { flags } => {
                let Some(slot) = self.stack_slot_from_reg(
                    state,
                    *flags,
                    "kfunc 'bpf_res_spin_unlock_irqrestore' arg1",
                ) else {
                    return;
                };
                if !state.release_res_spin_lock_irqsave_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_res_spin_unlock_irqrestore' requires a matching bpf_res_spin_lock_irqsave",
                    ));
                }
            }
            VccInst::IterTaskVmaNew { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_task_vma_new' arg0")
                else {
                    return;
                };
                state.acquire_iter_task_vma_slot(slot);
            }
            VccInst::IterTaskVmaNext { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_task_vma_next' arg0")
                else {
                    return;
                };
                if !state.use_iter_task_vma_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_task_vma_next' requires a matching bpf_iter_task_vma_new",
                    ));
                }
            }
            VccInst::IterTaskVmaDestroy { iter } => {
                let Some(slot) = self.stack_slot_from_reg(
                    state,
                    *iter,
                    "kfunc 'bpf_iter_task_vma_destroy' arg0",
                ) else {
                    return;
                };
                if !state.release_iter_task_vma_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_task_vma_destroy' requires a matching bpf_iter_task_vma_new",
                    ));
                }
            }
            VccInst::IterTaskNew { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_task_new' arg0")
                else {
                    return;
                };
                state.acquire_iter_task_slot(slot);
            }
            VccInst::IterTaskNext { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_task_next' arg0")
                else {
                    return;
                };
                if !state.use_iter_task_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_task_next' requires a matching bpf_iter_task_new",
                    ));
                }
            }
            VccInst::IterTaskDestroy { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_task_destroy' arg0")
                else {
                    return;
                };
                if !state.release_iter_task_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_task_destroy' requires a matching bpf_iter_task_new",
                    ));
                }
            }
            VccInst::IterScxDsqNew { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_scx_dsq_new' arg0")
                else {
                    return;
                };
                state.acquire_iter_scx_dsq_slot(slot);
            }
            VccInst::IterScxDsqNext { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_scx_dsq_next' arg0")
                else {
                    return;
                };
                if !state.use_iter_scx_dsq_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_scx_dsq_next' requires a matching bpf_iter_scx_dsq_new",
                    ));
                }
            }
            VccInst::IterScxDsqDestroy { iter } => {
                let Some(slot) = self.stack_slot_from_reg(
                    state,
                    *iter,
                    "kfunc 'bpf_iter_scx_dsq_destroy' arg0",
                ) else {
                    return;
                };
                if !state.release_iter_scx_dsq_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_scx_dsq_destroy' requires a matching bpf_iter_scx_dsq_new",
                    ));
                }
            }
            VccInst::IterScxDsqMove { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'scx_bpf_dsq_move' arg0")
                else {
                    return;
                };
                if !state.use_iter_scx_dsq_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'scx_bpf_dsq_move' requires a matching bpf_iter_scx_dsq_new",
                    ));
                }
            }
            VccInst::IterScxDsqMoveSetSlice { iter } => {
                let Some(slot) = self
                    .stack_slot_from_reg(state, *iter, "kfunc 'scx_bpf_dsq_move_set_slice' arg0")
                else {
                    return;
                };
                if !state.use_iter_scx_dsq_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'scx_bpf_dsq_move_set_slice' requires a matching bpf_iter_scx_dsq_new",
                    ));
                }
            }
            VccInst::IterScxDsqMoveSetVtime { iter } => {
                let Some(slot) = self
                    .stack_slot_from_reg(state, *iter, "kfunc 'scx_bpf_dsq_move_set_vtime' arg0")
                else {
                    return;
                };
                if !state.use_iter_scx_dsq_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'scx_bpf_dsq_move_set_vtime' requires a matching bpf_iter_scx_dsq_new",
                    ));
                }
            }
            VccInst::IterScxDsqMoveVtime { iter } => {
                let Some(slot) = self
                    .stack_slot_from_reg(state, *iter, "kfunc 'scx_bpf_dsq_move_vtime' arg0")
                else {
                    return;
                };
                if !state.use_iter_scx_dsq_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'scx_bpf_dsq_move_vtime' requires a matching bpf_iter_scx_dsq_new",
                    ));
                }
            }
            VccInst::IterNumNew { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_num_new' arg0")
                else {
                    return;
                };
                state.acquire_iter_num_slot(slot);
            }
            VccInst::IterNumNext { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_num_next' arg0")
                else {
                    return;
                };
                if !state.use_iter_num_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_num_next' requires a matching bpf_iter_num_new",
                    ));
                }
            }
            VccInst::IterNumDestroy { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_num_destroy' arg0")
                else {
                    return;
                };
                if !state.release_iter_num_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_num_destroy' requires a matching bpf_iter_num_new",
                    ));
                }
            }
            VccInst::IterBitsNew { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_bits_new' arg0")
                else {
                    return;
                };
                state.acquire_iter_bits_slot(slot);
            }
            VccInst::IterBitsNext { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_bits_next' arg0")
                else {
                    return;
                };
                if !state.use_iter_bits_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_bits_next' requires a matching bpf_iter_bits_new",
                    ));
                }
            }
            VccInst::IterBitsDestroy { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_bits_destroy' arg0")
                else {
                    return;
                };
                if !state.release_iter_bits_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_bits_destroy' requires a matching bpf_iter_bits_new",
                    ));
                }
            }
            VccInst::IterCssNew { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_css_new' arg0")
                else {
                    return;
                };
                state.acquire_iter_css_slot(slot);
            }
            VccInst::IterCssNext { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_css_next' arg0")
                else {
                    return;
                };
                if !state.use_iter_css_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_css_next' requires a matching bpf_iter_css_new",
                    ));
                }
            }
            VccInst::IterCssDestroy { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_css_destroy' arg0")
                else {
                    return;
                };
                if !state.release_iter_css_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_css_destroy' requires a matching bpf_iter_css_new",
                    ));
                }
            }
            VccInst::IterCssTaskNew { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_css_task_new' arg0")
                else {
                    return;
                };
                state.acquire_iter_css_task_slot(slot);
            }
            VccInst::IterCssTaskNext { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_css_task_next' arg0")
                else {
                    return;
                };
                if !state.use_iter_css_task_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_css_task_next' requires a matching bpf_iter_css_task_new",
                    ));
                }
            }
            VccInst::IterCssTaskDestroy { iter } => {
                let Some(slot) = self.stack_slot_from_reg(
                    state,
                    *iter,
                    "kfunc 'bpf_iter_css_task_destroy' arg0",
                ) else {
                    return;
                };
                if !state.release_iter_css_task_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_css_task_destroy' requires a matching bpf_iter_css_task_new",
                    ));
                }
            }
            VccInst::IterDmabufNew { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_dmabuf_new' arg0")
                else {
                    return;
                };
                state.acquire_iter_dmabuf_slot(slot);
            }
            VccInst::IterDmabufNext { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_dmabuf_next' arg0")
                else {
                    return;
                };
                if !state.use_iter_dmabuf_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_dmabuf_next' requires a matching bpf_iter_dmabuf_new",
                    ));
                }
            }
            VccInst::IterDmabufDestroy { iter } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_dmabuf_destroy' arg0")
                else {
                    return;
                };
                if !state.release_iter_dmabuf_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_dmabuf_destroy' requires a matching bpf_iter_dmabuf_new",
                    ));
                }
            }
            VccInst::IterKmemCacheNew { iter } => {
                let Some(slot) = self
                    .stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_kmem_cache_new' arg0")
                else {
                    return;
                };
                state.acquire_iter_kmem_cache_slot(slot);
            }
            VccInst::IterKmemCacheNext { iter } => {
                let Some(slot) = self
                    .stack_slot_from_reg(state, *iter, "kfunc 'bpf_iter_kmem_cache_next' arg0")
                else {
                    return;
                };
                if !state.use_iter_kmem_cache_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_kmem_cache_next' requires a matching bpf_iter_kmem_cache_new",
                    ));
                }
            }
            VccInst::IterKmemCacheDestroy { iter } => {
                let Some(slot) = self.stack_slot_from_reg(
                    state,
                    *iter,
                    "kfunc 'bpf_iter_kmem_cache_destroy' arg0",
                ) else {
                    return;
                };
                if !state.release_iter_kmem_cache_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_iter_kmem_cache_destroy' requires a matching bpf_iter_kmem_cache_new",
                    ));
                }
            }
            VccInst::DynptrMarkInitialized {
                ptr,
                kfunc,
                arg_idx,
            } => {
                let op = format!("kfunc '{}' arg{}", kfunc, arg_idx);
                let Some(slot) = self.stack_slot_from_reg(state, *ptr, &op) else {
                    return;
                };
                state.initialize_dynptr_slot(slot);
            }
            VccInst::DynptrRequireInitialized {
                ptr,
                kfunc,
                arg_idx,
            } => {
                let op = format!("kfunc '{}' arg{}", kfunc, arg_idx);
                let Some(slot) = self.stack_slot_from_reg(state, *ptr, &op) else {
                    return;
                };
                if !state.is_dynptr_slot_initialized(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "kfunc '{}' arg{} requires initialized dynptr stack object",
                            kfunc, arg_idx
                        ),
                    ));
                }
            }
            VccInst::DynptrCopy {
                src,
                dst,
                kfunc,
                src_arg_idx,
                dst_arg_idx,
            } => {
                let src_op = format!("kfunc '{}' arg{}", kfunc, src_arg_idx);
                let Some(src_slot) = self.stack_slot_from_reg(state, *src, &src_op) else {
                    return;
                };
                let dst_op = format!("kfunc '{}' arg{}", kfunc, dst_arg_idx);
                let Some(dst_slot) = self.stack_slot_from_reg(state, *dst, &dst_op) else {
                    return;
                };
                if src_slot == dst_slot {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "kfunc '{}' arg{} must reference distinct stack slot from arg{}",
                            kfunc, dst_arg_idx, src_arg_idx
                        ),
                    ));
                }
                if state.is_dynptr_slot_initialized(src_slot) {
                    state.initialize_dynptr_slot(dst_slot);
                }
            }
            VccInst::KfuncExpectRefKind {
                ptr,
                arg_idx,
                kind,
                kfunc,
            } => {
                let ty = match state.value_type(*ptr) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                match ty {
                    VccValueType::Ptr(info) if info.space == VccAddrSpace::Kernel => {
                        if let Some(ref_id) = info.kfunc_ref {
                            let op = format!("kfunc '{}' arg{}", kfunc, arg_idx);
                            if let Err(err) = self.require_non_null_ptr(info, &op) {
                                self.errors.push(err);
                            }
                            if !state.is_live_kfunc_ref(ref_id) {
                                self.errors.push(VccError::new(
                                    VccErrorKind::PointerBounds,
                                    format!(
                                        "kfunc '{}' arg{} reference already released",
                                        kfunc, arg_idx
                                    ),
                                ));
                                return;
                            }
                            let actual_kind = state.kfunc_ref_kind(ref_id);
                            if actual_kind != Some(*kind) {
                                let expected = kind.label();
                                let actual = actual_kind.map(|k| k.label()).unwrap_or("unknown");
                                self.errors.push(VccError::new(
                                    VccErrorKind::PointerBounds,
                                    format!(
                                        "kfunc '{}' arg{} expects {} reference, got {} reference",
                                        kfunc, arg_idx, expected, actual
                                    ),
                                ));
                            }
                        }
                    }
                    VccValueType::Ptr(info) => {
                        self.errors.push(VccError::new(
                            VccErrorKind::PointerBounds,
                            format!(
                                "kfunc '{}' arg{} expects pointer in [Kernel], got {}",
                                kfunc,
                                arg_idx,
                                Self::space_name(info.space)
                            ),
                        ));
                    }
                    other => {
                        self.errors.push(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Ptr,
                                actual: other.class(),
                            },
                            format!("kfunc '{}' arg{} expects pointer value", kfunc, arg_idx),
                        ));
                    }
                }
            }
            VccInst::HelperExpectRefKind {
                ptr,
                arg_idx,
                kind,
                helper_id,
            } => {
                let ty = match state.value_type(*ptr) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                if let VccValueType::Ptr(info) = ty
                    && info.space == VccAddrSpace::Kernel
                    && let Some(ref_id) = info.kfunc_ref
                {
                    let op = format!("helper {} arg{}", helper_id, arg_idx);
                    if let Err(err) = self.require_non_null_ptr(info, &op) {
                        self.errors.push(err);
                    }
                    if !state.is_live_kfunc_ref(ref_id) {
                        self.errors.push(VccError::new(
                            VccErrorKind::PointerBounds,
                            format!(
                                "helper {} arg{} reference already released",
                                helper_id, arg_idx
                            ),
                        ));
                        return;
                    }
                    let actual_kind = state.kfunc_ref_kind(ref_id);
                    if actual_kind != Some(*kind) {
                        let expected = kind.label();
                        let actual = actual_kind.map(|k| k.label()).unwrap_or("unknown");
                        self.errors.push(VccError::new(
                            VccErrorKind::PointerBounds,
                            format!(
                                "helper {} arg{} expects {} reference, got {} reference",
                                helper_id, arg_idx, expected, actual
                            ),
                        ));
                    }
                }
            }
            VccInst::KptrXchgTransfer { dst, src } => {
                let ty = match state.value_type(*src) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                if let VccValueType::Ptr(info) = ty
                    && let Some(ref_id) = info.kfunc_ref
                {
                    if !state.is_live_kfunc_ref(ref_id) {
                        self.errors.push(VccError::new(
                            VccErrorKind::PointerBounds,
                            "helper 194 arg1 reference already released",
                        ));
                        return;
                    }
                    let kind = state.kfunc_ref_kind(ref_id);
                    state.invalidate_kfunc_ref(ref_id);
                    state.set_live_kfunc_ref(*dst, true, kind);

                    if let Ok(VccValueType::Ptr(mut dst_info)) = state.reg_type(*dst) {
                        dst_info.kfunc_ref = Some(*dst);
                        state.set_reg(*dst, VccValueType::Ptr(dst_info));
                    }
                }
            }
        }
    }

    fn stack_slot_from_reg(
        &mut self,
        state: &VccState,
        reg: VccReg,
        op: &str,
    ) -> Option<StackSlotId> {
        let ty = match state.reg_type(reg) {
            Ok(ty) => ty,
            Err(err) => {
                self.errors.push(err);
                return None;
            }
        };
        match ty {
            VccValueType::Ptr(info) => match info.space {
                VccAddrSpace::Stack(slot)
                    if slot.0 != u32::MAX
                        && info
                            .bounds
                            .map_or(true, |bounds| bounds.min == 0 && bounds.max == 0) =>
                {
                    Some(slot)
                }
                VccAddrSpace::Stack(_) => {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!("{op} expects stack slot base pointer"),
                    ));
                    None
                }
                space => {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!("{op} expects pointer in [Stack], got {}", Self::space_name(space)),
                    ));
                    None
                }
            },
            other => {
                self.errors.push(VccError::new(
                    VccErrorKind::TypeMismatch {
                        expected: VccTypeClass::Ptr,
                        actual: other.class(),
                    },
                    format!("{op} expects pointer value"),
                ));
                None
            }
        }
    }

    pub(super) fn verify_terminator(&mut self, term: &VccTerminator, state: &mut VccState) {
        if !state.is_reachable() {
            return;
        }
        match term {
            VccTerminator::Jump { .. } => {}
            VccTerminator::Branch { cond, .. } => match state.value_type(*cond) {
                Ok(ty) => {
                    if ty.class() != VccTypeClass::Scalar && ty.class() != VccTypeClass::Bool {
                        self.errors.push(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Bool,
                                actual: ty.class(),
                            },
                            "branch condition must be scalar/bool",
                        ));
                    }
                }
                Err(err) => self.errors.push(err),
            },
            VccTerminator::Return { value } => {
                if let Some(value) = value {
                    if let Err(err) = state.value_type(*value) {
                        self.errors.push(err);
                    }
                }
                if state.has_live_ringbuf_refs() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased ringbuf record reference at function exit",
                    ));
                }
                if state.has_live_kfunc_refs() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased kfunc reference at function exit",
                    ));
                }
                if state.has_live_rcu_read_lock() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased RCU read lock at function exit",
                    ));
                }
                if state.has_live_preempt_disable() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased preempt disable at function exit",
                    ));
                }
                if state.has_live_local_irq_disable() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased local irq disable at function exit",
                    ));
                }
                if state.has_live_res_spin_lock() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased res spin lock at function exit",
                    ));
                }
                if state.has_live_res_spin_lock_irqsave() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased res spin lock irqsave at function exit",
                    ));
                }
                if state.has_live_iter_task_vma() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased iter_task_vma iterator at function exit",
                    ));
                }
                if state.has_live_iter_task() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased iter_task iterator at function exit",
                    ));
                }
                if state.has_live_iter_scx_dsq() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased iter_scx_dsq iterator at function exit",
                    ));
                }
                if state.has_live_iter_num() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased iter_num iterator at function exit",
                    ));
                }
                if state.has_live_iter_bits() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased iter_bits iterator at function exit",
                    ));
                }
                if state.has_live_iter_css() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased iter_css iterator at function exit",
                    ));
                }
                if state.has_live_iter_css_task() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased iter_css_task iterator at function exit",
                    ));
                }
                if state.has_live_iter_dmabuf() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased iter_dmabuf iterator at function exit",
                    ));
                }
                if state.has_live_iter_kmem_cache() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased iter_kmem_cache iterator at function exit",
                    ));
                }
            }
        }
    }
}
