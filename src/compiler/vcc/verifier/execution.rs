use super::*;
use crate::compiler::instruction::{
    scalar_range_contains_only_allowed_values, scalar_range_contains_only_bitmask,
    scalar_range_contains_only_multiple_of, scalar_range_satisfies_bit_combination,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IterLifecycleFailure {
    LiveSlot,
    MissingMatchingConstructor,
}

fn iter_lifecycle_result(
    valid: bool,
    failure: IterLifecycleFailure,
) -> Result<(), IterLifecycleFailure> {
    if valid { Ok(()) } else { Err(failure) }
}

fn iter_lifecycle_error_message(
    kfunc: &str,
    family: KfuncIterFamily,
    failure: IterLifecycleFailure,
) -> String {
    match failure {
        IterLifecycleFailure::LiveSlot => format!(
            "kfunc '{}' requires uninitialized {} stack object slot",
            kfunc,
            family.stack_object_type_name()
        ),
        IterLifecycleFailure::MissingMatchingConstructor => format!(
            "kfunc '{}' requires a matching {}",
            kfunc,
            family.constructor_kfunc()
        ),
    }
}

fn iter_exit_label(family: KfuncIterFamily) -> &'static str {
    match family {
        KfuncIterFamily::TaskVma => "iter_task_vma",
        KfuncIterFamily::Task => "iter_task",
        KfuncIterFamily::ScxDsq => "iter_scx_dsq",
        KfuncIterFamily::Num => "iter_num",
        KfuncIterFamily::Bits => "iter_bits",
        KfuncIterFamily::Css => "iter_css",
        KfuncIterFamily::CssTask => "iter_css_task",
        KfuncIterFamily::Dmabuf => "iter_dmabuf",
        KfuncIterFamily::KmemCache => "iter_kmem_cache",
    }
}

impl VccVerifier {
    fn apply_iter_lifecycle_op(
        state: &mut VccState,
        family: KfuncIterFamily,
        op: KfuncIterLifecycleOp,
        slot: StackSlotId,
    ) -> Result<(), IterLifecycleFailure> {
        match (family, op) {
            (KfuncIterFamily::TaskVma, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
                state.acquire_iter_task_vma_slot(slot),
                IterLifecycleFailure::LiveSlot,
            ),
            (KfuncIterFamily::TaskVma, KfuncIterLifecycleOp::Next) => {
                iter_lifecycle_result(
                    state.use_iter_task_vma_slot(slot),
                    IterLifecycleFailure::MissingMatchingConstructor,
                )
            }
            (KfuncIterFamily::TaskVma, KfuncIterLifecycleOp::Destroy) => {
                iter_lifecycle_result(
                    state.release_iter_task_vma_slot(slot),
                    IterLifecycleFailure::MissingMatchingConstructor,
                )
            }
            (KfuncIterFamily::Task, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
                state.acquire_iter_task_slot(slot),
                IterLifecycleFailure::LiveSlot,
            ),
            (KfuncIterFamily::Task, KfuncIterLifecycleOp::Next) => iter_lifecycle_result(
                state.use_iter_task_slot(slot),
                IterLifecycleFailure::MissingMatchingConstructor,
            ),
            (KfuncIterFamily::Task, KfuncIterLifecycleOp::Destroy) => iter_lifecycle_result(
                state.release_iter_task_slot(slot),
                IterLifecycleFailure::MissingMatchingConstructor,
            ),
            (KfuncIterFamily::ScxDsq, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
                state.acquire_iter_scx_dsq_slot(slot),
                IterLifecycleFailure::LiveSlot,
            ),
            (KfuncIterFamily::ScxDsq, KfuncIterLifecycleOp::Next) => {
                iter_lifecycle_result(
                    state.use_iter_scx_dsq_slot(slot),
                    IterLifecycleFailure::MissingMatchingConstructor,
                )
            }
            (KfuncIterFamily::ScxDsq, KfuncIterLifecycleOp::Destroy) => {
                iter_lifecycle_result(
                    state.release_iter_scx_dsq_slot(slot),
                    IterLifecycleFailure::MissingMatchingConstructor,
                )
            }
            (KfuncIterFamily::Num, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
                state.acquire_iter_num_slot(slot),
                IterLifecycleFailure::LiveSlot,
            ),
            (KfuncIterFamily::Num, KfuncIterLifecycleOp::Next) => iter_lifecycle_result(
                state.use_iter_num_slot(slot),
                IterLifecycleFailure::MissingMatchingConstructor,
            ),
            (KfuncIterFamily::Num, KfuncIterLifecycleOp::Destroy) => iter_lifecycle_result(
                state.release_iter_num_slot(slot),
                IterLifecycleFailure::MissingMatchingConstructor,
            ),
            (KfuncIterFamily::Bits, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
                state.acquire_iter_bits_slot(slot),
                IterLifecycleFailure::LiveSlot,
            ),
            (KfuncIterFamily::Bits, KfuncIterLifecycleOp::Next) => iter_lifecycle_result(
                state.use_iter_bits_slot(slot),
                IterLifecycleFailure::MissingMatchingConstructor,
            ),
            (KfuncIterFamily::Bits, KfuncIterLifecycleOp::Destroy) => {
                iter_lifecycle_result(
                    state.release_iter_bits_slot(slot),
                    IterLifecycleFailure::MissingMatchingConstructor,
                )
            }
            (KfuncIterFamily::Css, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
                state.acquire_iter_css_slot(slot),
                IterLifecycleFailure::LiveSlot,
            ),
            (KfuncIterFamily::Css, KfuncIterLifecycleOp::Next) => iter_lifecycle_result(
                state.use_iter_css_slot(slot),
                IterLifecycleFailure::MissingMatchingConstructor,
            ),
            (KfuncIterFamily::Css, KfuncIterLifecycleOp::Destroy) => iter_lifecycle_result(
                state.release_iter_css_slot(slot),
                IterLifecycleFailure::MissingMatchingConstructor,
            ),
            (KfuncIterFamily::CssTask, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
                state.acquire_iter_css_task_slot(slot),
                IterLifecycleFailure::LiveSlot,
            ),
            (KfuncIterFamily::CssTask, KfuncIterLifecycleOp::Next) => {
                iter_lifecycle_result(
                    state.use_iter_css_task_slot(slot),
                    IterLifecycleFailure::MissingMatchingConstructor,
                )
            }
            (KfuncIterFamily::CssTask, KfuncIterLifecycleOp::Destroy) => {
                iter_lifecycle_result(
                    state.release_iter_css_task_slot(slot),
                    IterLifecycleFailure::MissingMatchingConstructor,
                )
            }
            (KfuncIterFamily::Dmabuf, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
                state.acquire_iter_dmabuf_slot(slot),
                IterLifecycleFailure::LiveSlot,
            ),
            (KfuncIterFamily::Dmabuf, KfuncIterLifecycleOp::Next) => {
                iter_lifecycle_result(
                    state.use_iter_dmabuf_slot(slot),
                    IterLifecycleFailure::MissingMatchingConstructor,
                )
            }
            (KfuncIterFamily::Dmabuf, KfuncIterLifecycleOp::Destroy) => {
                iter_lifecycle_result(
                    state.release_iter_dmabuf_slot(slot),
                    IterLifecycleFailure::MissingMatchingConstructor,
                )
            }
            (KfuncIterFamily::KmemCache, KfuncIterLifecycleOp::New) => iter_lifecycle_result(
                state.acquire_iter_kmem_cache_slot(slot),
                IterLifecycleFailure::LiveSlot,
            ),
            (KfuncIterFamily::KmemCache, KfuncIterLifecycleOp::Next) => {
                iter_lifecycle_result(
                    state.use_iter_kmem_cache_slot(slot),
                    IterLifecycleFailure::MissingMatchingConstructor,
                )
            }
            (KfuncIterFamily::KmemCache, KfuncIterLifecycleOp::Destroy) => {
                iter_lifecycle_result(
                    state.release_iter_kmem_cache_slot(slot),
                    IterLifecycleFailure::MissingMatchingConstructor,
                )
            }
        }
    }

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
                    let ty = match src {
                        VccValue::Imm(0) => state
                            .reg_type(*dst)
                            .ok()
                            .and_then(typed_null_copy_type)
                            .unwrap_or(ty),
                        VccValue::Reg(src_reg)
                            if matches!(
                                state.value_range(*src, ty),
                                Some(VccRange { min: 0, max: 0 })
                            ) =>
                        {
                            state
                                .reg_type(*dst)
                                .ok()
                                .and_then(typed_null_copy_type)
                                .unwrap_or_else(|| {
                                    state
                                        .reg_type(*src_reg)
                                        .ok()
                                        .and_then(typed_null_copy_type)
                                        .unwrap_or(ty)
                                })
                        }
                        _ => ty,
                    };
                    let (copied_refinement, src_not_equal) = match src {
                        VccValue::Reg(src_reg) => (
                            state.cond_refinement(*src_reg),
                            state.not_equal_consts(*src_reg).to_vec(),
                        ),
                        VccValue::Imm(v) if *v != 0 => (None, vec![0]),
                        _ => (None, Vec::new()),
                    };
                    let src_ctx_field = match src {
                        VccValue::Reg(src_reg) => state.ctx_field_source(*src_reg).cloned(),
                        _ => None,
                    };
                    let src_map_fd = match src {
                        VccValue::Reg(src_reg) => state.map_fd_source(*src_reg).cloned(),
                        _ => None,
                    };
                    let src_map_lookup_source = match src {
                        VccValue::Reg(src_reg) => state.map_value_source(*src_reg).cloned(),
                        _ => None,
                    };
                    let src_map_lookup_ambiguous = match src {
                        VccValue::Reg(src_reg) => state.map_value_source_is_ambiguous(*src_reg),
                        _ => false,
                    };
                    let src_ambiguous_map = match src {
                        VccValue::Reg(src_reg) => {
                            state.map_value_ambiguous_map_source(*src_reg).cloned()
                        }
                        _ => None,
                    };
                    let src_released_kfunc_ref = matches!(src, VccValue::Reg(src_reg) if state.is_released_kfunc_ref(*src_reg));
                    let src_scalar_alias = match src {
                        VccValue::Reg(src_reg)
                            if matches!(ty, VccValueType::Scalar { .. } | VccValueType::Bool) =>
                        {
                            Some(*src_reg)
                        }
                        _ => None,
                    };
                    state.set_reg(*dst, ty);
                    if let Some(src_reg) = src_scalar_alias {
                        state.set_scalar_alias(*dst, src_reg);
                    }
                    if src_released_kfunc_ref {
                        state.mark_released_kfunc_ref(*dst);
                        return;
                    }
                    state.set_ctx_field_source(*dst, src_ctx_field);
                    if let Some(map) = src_map_fd {
                        state.set_map_fd_source(*dst, map);
                    }
                    if src_map_lookup_ambiguous {
                        if let Some(map) = src_ambiguous_map {
                            state.set_ambiguous_map_lookup_source_with_map(*dst, map);
                        } else {
                            state.set_ambiguous_map_lookup_source(*dst);
                        }
                    } else if let Some(source) = src_map_lookup_source {
                        state.set_map_lookup_source(*dst, source.map, source.key);
                    }
                    if let Some(refinement) = copied_refinement {
                        state.set_cond_refinement(*dst, refinement);
                    }
                    for value in src_not_equal {
                        state.set_not_equal_const(*dst, value);
                    }
                }
                Err(err) => self.errors.push(err),
            },
            VccInst::Assume {
                dst,
                ty,
                ctx_field_source,
            } => {
                state.set_reg(*dst, *ty);
                state.set_ctx_field_source(*dst, ctx_field_source.clone());
            }
            VccInst::CtxFieldSource { reg, field } => {
                if let Ok(ty) = state.reg_type(*reg) {
                    state.set_reg(*reg, Self::ctx_field_phi_type(*reg, ty, field));
                }
                state.set_ctx_field_source(*reg, Some(field.clone()));
            }
            VccInst::ScalarAlias { dst, src } => {
                state.set_scalar_alias(*dst, *src);
            }
            VccInst::MapLookupSource { root, map, key } => {
                state.set_map_lookup_source(*root, map.clone(), *key);
            }
            VccInst::AmbiguousMapLookupSource { root, map } => {
                if let Some(map) = map {
                    state.set_ambiguous_map_lookup_source_with_map(*root, map.clone());
                } else {
                    state.set_ambiguous_map_lookup_source(*root);
                }
            }
            VccInst::MapFdSource { map_fd, map } => {
                state.set_map_fd_source(*map_fd, map.clone());
            }
            VccInst::AssertMapFdMatchesMapValue {
                map_value,
                map_fd,
                map_value_label,
                map_fd_label,
                call,
            } => {
                let Some(map_fd_source) = state.map_fd_source(*map_fd) else {
                    return;
                };
                if state.map_value_source_is_ambiguous(*map_value) {
                    if let Some(map_value_map) =
                        state.map_value_ambiguous_map_source(*map_value).cloned()
                    {
                        if map_value_map != *map_fd_source {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                format!(
                                    "{} {} '{}' does not match {} '{}'",
                                    call,
                                    map_fd_label,
                                    map_fd_source.name,
                                    map_value_label,
                                    map_value_map.name
                                ),
                            ));
                        }
                        return;
                    }
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "{} {} may come from multiple maps and cannot be matched to {} '{}'",
                            call, map_value_label, map_fd_label, map_fd_source.name
                        ),
                    ));
                    return;
                }
                let Some(map_value_source) = state.map_value_source(*map_value) else {
                    return;
                };
                if map_value_source.map != *map_fd_source {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "{} {} '{}' does not match {} '{}'",
                            call, map_fd_label, map_fd_source.name, map_value_label, map_value_source.map.name
                        ),
                    ));
                }
            }
            VccInst::AssertScalar { value, op } => match state.value_type(*value) {
                Ok(ty) => {
                    if ty.class() != VccTypeClass::Scalar && ty.class() != VccTypeClass::Bool {
                        self.errors.push(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Scalar,
                                actual: ty.class(),
                            },
                            op.map_or_else(
                                || "expected scalar value".to_string(),
                                |op| format!("{op} expects scalar"),
                            ),
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
            VccInst::AssertRange {
                value,
                min,
                max,
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
                if let Some(range) = state.value_range(*value, ty)
                    && (range.min < *min || range.max > *max)
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        message.clone(),
                    ));
                }
            }
            VccInst::AssertMultipleOf {
                value,
                multiple,
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
                if let Some(range) = state.value_range(*value, ty)
                    && !scalar_range_contains_only_multiple_of(range.min, range.max, *multiple)
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        message.clone(),
                    ));
                }
            }
            VccInst::AssertAllowedValues {
                value,
                allowed,
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
                if let Some(range) = state.value_range(*value, ty)
                    && !scalar_range_contains_only_allowed_values(range.min, range.max, allowed)
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        message.clone(),
                    ));
                }
            }
            VccInst::AssertBitmask {
                value,
                mask,
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
                if let Some(range) = state.value_range(*value, ty)
                    && !scalar_range_contains_only_bitmask(range.min, range.max, *mask)
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        message.clone(),
                    ));
                }
            }
            VccInst::AssertBitCombination { value, requirement } => {
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
                if let Some(range) = state.value_range(*value, ty)
                    && !scalar_range_satisfies_bit_combination(
                        range.min,
                        range.max,
                        *requirement,
                    )
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        requirement.message.to_string(),
                    ));
                }
            }
            VccInst::AssertConstEqIfConstEq {
                value,
                expected,
                when_value,
                when_expected,
                message,
            } => {
                let when_ty = match state.value_type(*when_value) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                if Self::const_scalar_value(*when_value, when_ty) != Some(*when_expected) {
                    return;
                }

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
            VccInst::AssertConstEqIfMaskedConstEq {
                value,
                expected,
                when_value,
                when_mask,
                when_expected,
                message,
            } => {
                let when_ty = match state.value_type(*when_value) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                let Some(when_actual) = Self::const_scalar_value(*when_value, when_ty) else {
                    return;
                };
                if ((when_actual as u64) & (*when_mask as u64)) != *when_expected as u64 {
                    return;
                }

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
            VccInst::AssertCtxFieldLoadGuard { field, guard } => {
                if !state.proves_ctx_field_value_range(&guard.witness_field(), |value| {
                    guard.allows_value(value)
                }) {
                    self.errors.push(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        guard.error(field),
                    ));
                }
            }
            VccInst::AssertCtxFieldAllowedValues {
                field,
                allowed,
                message,
            } => {
                if !state.proves_ctx_field_value_range(field, |value| allowed.contains(&value)) {
                    self.errors.push(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        message.clone(),
                    ));
                }
            }
            VccInst::AssertCtxFieldAllowedValuesUnlessBitSet {
                field,
                allowed,
                unless_value,
                unless_mask,
                message,
            } => {
                let ty = match state.value_type(*unless_value) {
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
                if let Some(range) = state.value_range(*unless_value, ty) {
                    let width = range.max.saturating_sub(range.min);
                    if width <= 64 && (range.min..=range.max).all(|value| value & unless_mask != 0)
                    {
                        return;
                    }
                }
                if !state.proves_ctx_field_value_range(field, |value| allowed.contains(&value)) {
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
                if state.is_released_kfunc_ref(*ptr) {
                    self.errors.push(VccError::new(
                        VccErrorKind::InvalidLoadStore,
                        format!("{op} uses released reference v{}", ptr.0),
                    ));
                    return;
                }
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
                    VccValueType::StalePacketPtr => {
                        self.errors.push(Self::stale_packet_pointer_error(op));
                        return;
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
                } else if matches!(
                    ptr_info.space,
                    VccAddrSpace::Stack(_) | VccAddrSpace::MapValue
                ) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!("{op} size must have bounded upper range"),
                    ));
                }
            }
            VccInst::AssertPtrAccessOrZero { ptr, size, op } => {
                if state.is_released_kfunc_ref(*ptr) {
                    self.errors.push(VccError::new(
                        VccErrorKind::InvalidLoadStore,
                        format!("{op} uses released reference v{}", ptr.0),
                    ));
                    return;
                }
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
                    VccValueType::StalePacketPtr => {
                        self.errors.push(Self::stale_packet_pointer_error(op));
                        return;
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
                    if size_range.min < 0 || size_range.max < 0 {
                        self.errors.push(VccError::new(
                            VccErrorKind::UnsupportedInstruction,
                            format!("{op} size must be >= 0"),
                        ));
                        return;
                    }
                    if size_range.max == 0 {
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
                } else if matches!(
                    ptr_info.space,
                    VccAddrSpace::Stack(_) | VccAddrSpace::MapValue
                ) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!("{op} size must have bounded upper range"),
                    ));
                }
            }
            VccInst::AssertStackSlotBase { ptr, op } => {
                let _ = self.stack_slot_from_reg(state, *ptr, op);
            }
            VccInst::AssertStackSlotZeroIfConstEq {
                ptr,
                when_value,
                when_expected,
                message,
            } => {
                let when_ty = match state.value_type(*when_value) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                if Self::const_scalar_value(*when_value, when_ty) != Some(*when_expected) {
                    return;
                }
                let Some(slot) = self.stack_slot_from_reg(state, *ptr, "helper 'bpf_check_mtu' arg2")
                else {
                    return;
                };
                if let Some(range) = state.stack_slot_value_range(slot)
                    && (range.min > 0 || range.max < 0)
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        message.clone(),
                    ));
                }
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
                    self.errors
                        .push(VccError::new(VccErrorKind::PointerBounds, message.clone()));
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
                        packet_root: None,
                        packet_root_field: None,
                        packet_ctx_field: None,
                        packet_end: false,
                        map_root: None,
                        context_buffer_root: None,
                        context_buffer_end: false,
                        ringbuf_ref: None,
                        kfunc_ref: None,
                    }),
                );
            }
            VccInst::ClearStackSlotValueRanges => {
                state.stack_slot_value_ranges.clear();
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
                        let cond_result_cmp = self
                            .condition_result_comparison(*op, *lhs, lhs_ty, *rhs, rhs_ty, state);
                        let scalar_cmp =
                            self.scalar_const_comparison(*lhs, lhs_ty, *rhs, rhs_ty, *op);
                        let scalar_reg_cmp =
                            self.scalar_reg_comparison(*lhs, lhs_ty, *rhs, rhs_ty, *op);
                        let packet_end_cmp =
                            self.packet_end_comparison(*lhs, lhs_ty, *rhs, rhs_ty, *op);
                        let context_buffer_end_cmp =
                            self.context_buffer_end_comparison(*lhs, lhs_ty, *rhs, rhs_ty, *op);
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
                        } else if let Some(refinement) = cond_result_cmp {
                            state.set_cond_refinement(*dst, refinement);
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
                        } else if let Some((ptr_reg, cmp_op)) = packet_end_cmp {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement::PacketEnd {
                                    ptr_reg,
                                    op: cmp_op,
                                },
                            );
                        } else if let Some((ptr_reg, cmp_op)) = context_buffer_end_cmp {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement::ContextBufferEnd {
                                    ptr_reg,
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
                        let packet_end_cmp =
                            self.packet_end_comparison(*lhs, lhs_ty, *rhs, rhs_ty, *op);
                        let context_buffer_end_cmp =
                            self.context_buffer_end_comparison(*lhs, lhs_ty, *rhs, rhs_ty, *op);
                        let lhs_is_ptr = matches!(lhs_ty, VccValueType::Ptr(_));
                        let rhs_is_ptr = matches!(rhs_ty, VccValueType::Ptr(_));
                        if lhs_is_ptr || rhs_is_ptr {
                            match (lhs_ty, rhs_ty) {
                                (VccValueType::Ptr(lp), VccValueType::Ptr(rp))
                                    if lp.space == VccAddrSpace::Packet
                                        && rp.space == VccAddrSpace::Packet => {}
                                (VccValueType::Ptr(lp), VccValueType::Ptr(rp))
                                    if matches!(
                                        lp.space,
                                        VccAddrSpace::Kernel | VccAddrSpace::KernelBtf
                                    ) && matches!(
                                        rp.space,
                                        VccAddrSpace::Kernel | VccAddrSpace::KernelBtf
                                    ) && context_buffer_end_cmp.is_some() => {}
                                _ => {
                                    self.errors.push(VccError::new(
                                        VccErrorKind::TypeMismatch {
                                            expected: VccTypeClass::Scalar,
                                            actual: if lhs_is_ptr {
                                                lhs_ty.class()
                                            } else {
                                                rhs_ty.class()
                                            },
                                        },
                                        "comparison expects scalar operands",
                                    ));
                                    return;
                                }
                            }
                        } else {
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
                        } else if let Some((ptr_reg, cmp_op)) = packet_end_cmp {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement::PacketEnd {
                                    ptr_reg,
                                    op: cmp_op,
                                },
                            );
                        } else if let Some((ptr_reg, cmp_op)) = context_buffer_end_cmp {
                            state.set_cond_refinement(
                                *dst,
                                VccCondRefinement::ContextBufferEnd {
                                    ptr_reg,
                                    op: cmp_op,
                                },
                            );
                        }
                    }
                    _ => {
                        if matches!(lhs_ty, VccValueType::StalePacketPtr)
                            || matches!(rhs_ty, VccValueType::StalePacketPtr)
                        {
                            self.errors.push(Self::stale_packet_pointer_error("binop"));
                            return;
                        }
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
                if state.is_released_kfunc_ref(*base) {
                    state.mark_released_kfunc_ref(*dst);
                    return;
                }
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
                        packet_root: base_ptr.packet_root,
                        packet_root_field: base_ptr.packet_root_field,
                        packet_ctx_field: None,
                        packet_end: false,
                        map_root: base_ptr.map_root,
                        context_buffer_root: base_ptr.context_buffer_root,
                        context_buffer_end: false,
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
                if state.is_released_kfunc_ref(*ptr) {
                    self.errors.push(VccError::new(
                        VccErrorKind::InvalidLoadStore,
                        format!("load uses released reference v{}", ptr.0),
                    ));
                    return;
                }
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
                        let load_allowed = matches!(
                            ptr_info.space,
                            VccAddrSpace::Stack(_)
                                | VccAddrSpace::MapValue
                                | VccAddrSpace::Packet
                                | VccAddrSpace::Context
                                | VccAddrSpace::KernelBtf
                        ) || (ptr_info.space == VccAddrSpace::Kernel
                            && ptr_info.context_buffer_root.is_some());
                        if !load_allowed {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                format!(
                                    "load requires pointer in [Stack, Map, Packet, Context, guarded ContextBuffer], got {}",
                                    Self::space_name(ptr_info.space)
                                ),
                            ));
                            return;
                        }
                        if ptr_info.space == VccAddrSpace::Packet
                            && ptr_info
                                .bounds
                                .is_none_or(|bounds| bounds.limit == UNKNOWN_PACKET_LIMIT)
                        {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                "load on packet pointers requires a preceding packet end-pointer guard",
                            ));
                            return;
                        }
                        if ptr_info.space == VccAddrSpace::Kernel
                            && ptr_info
                                .bounds
                                .is_none_or(|bounds| bounds.limit == UNKNOWN_CONTEXT_BUFFER_LIMIT)
                        {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                "load on bounded context buffers requires a preceding end-pointer guard",
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
                    VccValueType::StalePacketPtr => {
                        self.errors.push(Self::stale_packet_pointer_error("load"));
                        return;
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
                if state.is_released_kfunc_ref(*ptr) {
                    self.errors.push(VccError::new(
                        VccErrorKind::InvalidLoadStore,
                        format!("store uses released reference v{}", ptr.0),
                    ));
                    return;
                }
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
                        let store_allowed = Self::is_mem_space_allowed(ptr_info.space)
                            || ptr_info.space == VccAddrSpace::Context
                            || (ptr_info.space == VccAddrSpace::Kernel
                                && ptr_info.context_buffer_root.is_some());
                        if !store_allowed {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                format!(
                                    "store requires pointer in [Stack, Map, Packet, Context, guarded ContextBuffer], got {}",
                                    Self::space_name(ptr_info.space)
                                ),
                            ));
                            return;
                        }
                        if ptr_info.space == VccAddrSpace::Packet
                            && ptr_info
                                .bounds
                                .is_none_or(|bounds| bounds.limit == UNKNOWN_PACKET_LIMIT)
                        {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                "store on packet pointers requires a preceding packet end-pointer guard",
                            ));
                            return;
                        }
                        if ptr_info.space == VccAddrSpace::Kernel
                            && ptr_info
                                .bounds
                                .is_none_or(|bounds| bounds.limit == UNKNOWN_CONTEXT_BUFFER_LIMIT)
                        {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                "store on bounded context buffers requires a preceding end-pointer guard",
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
                    VccValueType::StalePacketPtr => {
                        self.errors.push(Self::stale_packet_pointer_error("store"));
                        return;
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
                    return;
                }
                if let VccValueType::Ptr(ptr_info) = ptr_ty
                    && let VccAddrSpace::Stack(slot) = ptr_info.space
                {
                    let src_range = state
                        .value_type(*src)
                        .ok()
                        .and_then(|ty| state.value_range(*src, ty));
                    let exact_base = ptr_info
                        .bounds
                        .is_some_and(|bounds| bounds.min == 0 && bounds.max == 0);
                    if exact_base && *offset == 0 && *size == 4 {
                        if let Some(range) = src_range {
                            state.set_stack_slot_value_range(slot, range);
                        } else {
                            state.clear_stack_slot_value_range(slot);
                        }
                    } else {
                        state.clear_stack_slot_value_range(slot);
                    }
                }
            }
            VccInst::Phi { dst, args } => {
                let mut merged: Option<VccValueType> = None;
                let dst_ptr_hint = state.reg_type(*dst).ok().and_then(|ty| match ty {
                    VccValueType::Ptr(info) => Some(info),
                    _ => None,
                });
                for (_, reg) in args {
                    match state.reg_type(*reg) {
                        Ok(ty) => {
                            let ty = Self::phi_arg_type_with_pointer_null_hint(ty, dst_ptr_hint);
                            merged = Some(match merged {
                                None => ty,
                                Some(existing) => state.merge_types(existing, ty),
                            });
                        }
                        Err(err) => self.errors.push(err),
                    }
                }
                let mut ty = merged.unwrap_or(VccValueType::Unknown);
                let released_kfunc_ref = args
                    .iter()
                    .any(|(_, reg)| state.is_released_kfunc_ref(*reg));
                let mut merged_ctx_field: Option<Option<CtxField>> = None;
                for (_, reg) in args {
                    let next = state.ctx_field_source(*reg).cloned();
                    merged_ctx_field = Some(match merged_ctx_field {
                        None => next,
                        Some(existing) if existing == next => existing,
                        _ => None,
                    });
                    if matches!(merged_ctx_field, Some(None)) {
                        break;
                    }
                }
                if let Some(Some(source)) = &merged_ctx_field {
                    ty = Self::ctx_field_phi_type(*dst, ty, source);
                }
                let scalar_alias_root = Self::scalar_alias_root_for_phi(args, state, ty);
                let merged_map_value_source = Self::map_value_source_for_phi(args, state);
                let mut merged_map_fd: Option<Option<MapRef>> = None;
                for (_, reg) in args {
                    let next = state.map_fd_source(*reg).cloned();
                    merged_map_fd = Some(match merged_map_fd {
                        None => next,
                        Some(existing) if existing == next => existing,
                        _ => None,
                    });
                    if matches!(merged_map_fd, Some(None)) {
                        break;
                    }
                }
                state.set_reg(*dst, ty);
                if let Some(root) = scalar_alias_root
                    && root != *dst
                {
                    state.set_scalar_alias(*dst, root);
                }
                if released_kfunc_ref {
                    state.mark_released_kfunc_ref(*dst);
                    return;
                }
                if let Some(Some(map)) = merged_map_fd {
                    state.set_map_fd_source(*dst, map);
                }
                match merged_map_value_source {
                    PhiMapValueSource::None => {}
                    PhiMapValueSource::Known(source) => {
                        state.set_map_lookup_source(*dst, source.map, source.key);
                    }
                    PhiMapValueSource::KnownMap(map) => {
                        state.set_ambiguous_map_lookup_source_with_map(*dst, map);
                    }
                    PhiMapValueSource::Ambiguous => {
                        state.set_ambiguous_map_lookup_source(*dst);
                    }
                }
                if let Some(Some(source)) = merged_ctx_field {
                    state.set_ctx_field_source(*dst, Some(source));
                }
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
            VccInst::InvalidatePacketPointers => {
                state.invalidate_packet_pointers();
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
            VccInst::KfuncRelease {
                call,
                ptr,
                kind,
                arg_idx,
            } => {
                if let VccValue::Reg(reg) = ptr
                    && state.is_released_kfunc_ref(*reg)
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!("{call} arg{} reference already released", arg_idx),
                    ));
                    return;
                }
                let ty = match state.value_type(*ptr) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                match ty {
                    VccValueType::Ptr(info)
                        if matches!(info.space, VccAddrSpace::Kernel | VccAddrSpace::KernelBtf) =>
                    {
                        if let Err(err) = self.require_non_null_ptr(info, "kfunc release") {
                            self.errors.push(err);
                            return;
                        }
                        if let Some(ref_id) = info.kfunc_ref {
                            if !state.is_live_kfunc_ref(ref_id) {
                                self.errors.push(VccError::new(
                                    VccErrorKind::PointerBounds,
                                    format!("{call} arg{} reference already released", arg_idx),
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
                                        "{call} arg{} expects {} reference, got {} reference",
                                        arg_idx, expected, actual
                                    ),
                                ));
                            }
                        } else {
                            self.errors.push(VccError::new(
                                VccErrorKind::PointerBounds,
                                format!("{call} arg{} pointer is not tracked", arg_idx),
                            ));
                        }
                    }
                    VccValueType::Ptr(_) => {
                        let expected = kind.label();
                        self.errors.push(VccError::new(
                            VccErrorKind::PointerBounds,
                            format!(
                                "{call} arg{} requires kernel {} reference pointer",
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
                            format!("{call} arg{} requires pointer operand", arg_idx),
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
                let Some(slot) =
                    self.stack_slot_from_reg(state, *flags, "kfunc 'bpf_local_irq_save' arg0")
                else {
                    return;
                };
                state.acquire_local_irq_disable_slot(slot);
            }
            VccInst::LocalIrqDisableRelease { flags } => {
                let Some(slot) =
                    self.stack_slot_from_reg(state, *flags, "kfunc 'bpf_local_irq_restore' arg0")
                else {
                    return;
                };
                if !state.release_local_irq_disable_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_local_irq_restore' requires a matching bpf_local_irq_save",
                    ));
                }
            }
            VccInst::ResSpinLockAcquire { lock } => {
                let identity = state.res_spin_lock_identity(*lock);
                if !state.acquire_res_spin_lock(identity) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_res_spin_lock' cannot acquire an already-held resource spin lock",
                    ));
                }
            }
            VccInst::ResSpinLockRelease { lock } => {
                let identity = state.res_spin_lock_identity(*lock);
                if !state.release_res_spin_lock(identity) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_res_spin_unlock' requires a matching bpf_res_spin_lock",
                    ));
                }
            }
            VccInst::BpfSpinLockAcquire { lock } => {
                let identity = state.bpf_spin_lock_identity(*lock);
                if !state.acquire_bpf_spin_lock(identity) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "helper 'bpf_spin_lock' cannot acquire a second bpf_spin_lock",
                    ));
                }
            }
            VccInst::BpfSpinLockRelease { lock } => {
                let identity = state.bpf_spin_lock_identity(*lock);
                if !state.release_bpf_spin_lock(identity) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "helper 'bpf_spin_unlock' requires a matching bpf_spin_lock",
                    ));
                }
            }
            VccInst::KernelLockRejectIfHeld { call } => {
                if let Some(lock) = state.live_kernel_lock_description() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!("{} cannot be called while {} is held", call, lock),
                    ));
                }
            }
            VccInst::BpfSpinLockRequireHeld { root, message } => {
                if !state.has_bpf_spin_lock_for_map_root(*root) {
                    self.errors
                        .push(VccError::new(VccErrorKind::PointerBounds, message.clone()));
                }
            }
            VccInst::ResSpinLockIrqsaveAcquire { lock, flags } => {
                let Some(slot) = self.stack_slot_from_reg(
                    state,
                    *flags,
                    "kfunc 'bpf_res_spin_lock_irqsave' arg1",
                ) else {
                    return;
                };
                let identity = state.res_spin_lock_identity(*lock);
                if !state.acquire_res_spin_lock_irqsave(identity, slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_res_spin_lock_irqsave' cannot acquire an already-held resource spin lock",
                    ));
                }
            }
            VccInst::ResSpinLockIrqsaveRelease { lock, flags } => {
                let Some(slot) = self.stack_slot_from_reg(
                    state,
                    *flags,
                    "kfunc 'bpf_res_spin_unlock_irqrestore' arg1",
                ) else {
                    return;
                };
                let identity = state.res_spin_lock_identity(*lock);
                if !state.release_res_spin_lock_irqsave(identity, slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "kfunc 'bpf_res_spin_unlock_irqrestore' requires a matching bpf_res_spin_lock_irqsave",
                    ));
                }
            }
            VccInst::IterLifecycle {
                iter,
                kfunc,
                family,
                op,
            } => {
                let op_label = format!("kfunc '{}' arg0", kfunc);
                let Some(slot) = self.stack_slot_from_reg(state, *iter, &op_label) else {
                    return;
                };
                if let Err(failure) = Self::apply_iter_lifecycle_op(state, *family, *op, slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        iter_lifecycle_error_message(kfunc, *family, failure),
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
                if state.is_dynptr_slot_maybe_initialized(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "kfunc '{}' arg{} requires uninitialized dynptr stack object slot",
                            kfunc, arg_idx
                        ),
                    ));
                    return;
                }
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
            VccInst::DynptrDeinitialize {
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
                    return;
                }
                state.deinitialize_dynptr_slot(slot);
            }
            VccInst::DynptrMarkMaybeInitialized {
                ptr,
                kfunc,
                arg_idx,
            } => {
                let op = format!("kfunc '{}' arg{}", kfunc, arg_idx);
                let Some(slot) = self.stack_slot_from_reg(state, *ptr, &op) else {
                    return;
                };
                state.mark_dynptr_slot_maybe_initialized(slot);
            }
            VccInst::HelperDynptrMarkInitialized {
                ptr,
                helper,
                arg_idx,
            } => {
                let op = format!("helper '{}' arg{}", helper, arg_idx);
                let Some(slot) = self.stack_slot_from_reg(state, *ptr, &op) else {
                    return;
                };
                if state.is_dynptr_slot_maybe_initialized(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "helper '{}' arg{} requires uninitialized dynptr stack object slot",
                            helper, arg_idx
                        ),
                    ));
                    return;
                }
                state.initialize_dynptr_slot(slot);
            }
            VccInst::HelperDynptrRequireInitialized {
                ptr,
                helper,
                arg_idx,
            } => {
                let op = format!("helper '{}' arg{}", helper, arg_idx);
                let Some(slot) = self.stack_slot_from_reg(state, *ptr, &op) else {
                    return;
                };
                if state.is_released_ringbuf_dynptr_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "helper '{}' arg{} ringbuf dynptr reservation already released",
                            helper, arg_idx
                        ),
                    ));
                    return;
                }
                if !state.is_dynptr_slot_initialized(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "helper '{}' arg{} requires initialized dynptr stack object",
                            helper, arg_idx
                        ),
                    ));
                }
            }
            VccInst::HelperRingbufDynptrAcquire {
                ptr,
                helper,
                arg_idx,
            } => {
                let op = format!("helper '{}' arg{}", helper, arg_idx);
                let Some(slot) = self.stack_slot_from_reg(state, *ptr, &op) else {
                    return;
                };
                if state.is_dynptr_slot_maybe_initialized(slot)
                    || state.has_live_ringbuf_dynptr_slot(slot)
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "helper '{}' arg{} requires uninitialized dynptr stack object slot",
                            helper, arg_idx
                        ),
                    ));
                    return;
                }
                state.initialize_dynptr_slot(slot);
                state.acquire_ringbuf_dynptr_slot(slot);
            }
            VccInst::HelperRingbufDynptrRelease {
                ptr,
                helper,
                arg_idx,
            } => {
                let op = format!("helper '{}' arg{}", helper, arg_idx);
                let Some(slot) = self.stack_slot_from_reg(state, *ptr, &op) else {
                    return;
                };
                if state.is_released_ringbuf_dynptr_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "helper '{}' arg{} ringbuf dynptr reservation already released",
                            helper, arg_idx
                        ),
                    ));
                    return;
                }
                if !state.is_dynptr_slot_initialized(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "helper '{}' arg{} requires initialized dynptr stack object",
                            helper, arg_idx
                        ),
                    ));
                    return;
                }
                if !state.has_ringbuf_dynptr_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "helper '{}' arg{} requires live ringbuf dynptr reservation",
                            helper, arg_idx
                        ),
                    ));
                    return;
                }
                state.release_ringbuf_dynptr_slot(slot);
                state.deinitialize_dynptr_slot(slot);
            }
            VccInst::DynptrCopy {
                src,
                dst,
                kfunc,
                src_arg_idx,
                dst_arg_idx,
                move_semantics,
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
                    return;
                }
                if state.is_dynptr_slot_maybe_initialized(dst_slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "kfunc '{}' arg{} requires uninitialized dynptr stack object slot",
                            kfunc, dst_arg_idx
                        ),
                    ));
                    return;
                }
                if !state.is_dynptr_slot_initialized(src_slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "kfunc '{}' arg{} requires initialized dynptr stack object",
                            kfunc, src_arg_idx
                        ),
                    ));
                    return;
                }
                if *move_semantics {
                    state.deinitialize_dynptr_slot(src_slot);
                }
                state.initialize_dynptr_slot(dst_slot);
                state.copy_ringbuf_dynptr_slot(src_slot, dst_slot, *move_semantics);
            }
            VccInst::UnknownStackObjectInit {
                ptr,
                type_name,
                type_id,
                kfunc,
                arg_idx,
            } => {
                let op = format!("kfunc '{}' arg{}", kfunc, arg_idx);
                let Some(slot) = self.stack_slot_from_reg(state, *ptr, &op) else {
                    return;
                };
                if state.has_live_unknown_stack_object_slot(slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "kfunc '{}' arg{} requires uninitialized {} stack object slot",
                            kfunc, arg_idx, type_name
                        ),
                    ));
                    return;
                }
                state.initialize_unknown_stack_object_slot(slot, type_name, *type_id);
            }
            VccInst::UnknownStackObjectRequireInitialized {
                ptr,
                type_name,
                type_id,
                kfunc,
                arg_idx,
            } => {
                let op = format!("kfunc '{}' arg{}", kfunc, arg_idx);
                let Some(slot) = self.stack_slot_from_reg(state, *ptr, &op) else {
                    return;
                };
                if !state.has_unknown_stack_object_slot(slot, type_name, *type_id) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "kfunc '{}' arg{} requires initialized {} stack object",
                            kfunc, arg_idx, type_name
                        ),
                    ));
                }
            }
            VccInst::UnknownStackObjectDestroy {
                ptr,
                type_name,
                type_id,
                kfunc,
                arg_idx,
            } => {
                let op = format!("kfunc '{}' arg{}", kfunc, arg_idx);
                let Some(slot) = self.stack_slot_from_reg(state, *ptr, &op) else {
                    return;
                };
                if !state.release_unknown_stack_object_slot(slot, type_name, *type_id) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "kfunc '{}' arg{} requires initialized {} stack object",
                            kfunc, arg_idx, type_name
                        ),
                    ));
                }
            }
            VccInst::UnknownStackObjectMarkMaybeInitialized {
                ptr,
                type_name,
                type_id,
                kfunc,
                arg_idx,
            } => {
                let op = format!("kfunc '{}' arg{}", kfunc, arg_idx);
                let Some(slot) = self.stack_slot_from_reg(state, *ptr, &op) else {
                    return;
                };
                state.mark_unknown_stack_object_slot_maybe_initialized(
                    slot, type_name, *type_id,
                );
            }
            VccInst::UnknownStackObjectCopy {
                src,
                dst,
                type_name,
                type_id,
                kfunc,
                src_arg_idx,
                dst_arg_idx,
                move_semantics,
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
                    return;
                }
                if !state.has_unknown_stack_object_slot(src_slot, type_name, *type_id) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "kfunc '{}' arg{} requires initialized {} stack object",
                            kfunc, src_arg_idx, type_name
                        ),
                    ));
                    return;
                }
                if state.has_live_unknown_stack_object_slot(dst_slot) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "kfunc '{}' arg{} requires uninitialized {} stack object slot",
                            kfunc, dst_arg_idx, type_name
                        ),
                    ));
                    return;
                }
                if *move_semantics
                    && !state.release_unknown_stack_object_slot(src_slot, type_name, *type_id)
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "kfunc '{}' arg{} requires initialized {} stack object",
                            kfunc, src_arg_idx, type_name
                        ),
                    ));
                    return;
                }
                state.initialize_unknown_stack_object_slot(dst_slot, type_name, *type_id);
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
                    VccValueType::Ptr(info)
                        if matches!(info.space, VccAddrSpace::Kernel | VccAddrSpace::KernelBtf) =>
                    {
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
                if let VccValue::Reg(reg) = ptr
                    && state.is_released_kfunc_ref(*reg)
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "helper {} arg{} reference already released",
                            helper_id, arg_idx
                        ),
                    ));
                    return;
                }
                let ty = match state.value_type(*ptr) {
                    Ok(ty) => ty,
                    Err(err) => {
                        self.errors.push(err);
                        return;
                    }
                };
                if let VccValueType::Ptr(info) = ty
                    && matches!(info.space, VccAddrSpace::Kernel | VccAddrSpace::KernelBtf)
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
            VccInst::KptrXchgTransfer {
                dst,
                src,
                dst_slot_kind,
            } => {
                if let VccValue::Reg(src_reg) = src
                    && state.is_released_kfunc_ref(*src_reg)
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "helper 194 arg1 reference already released",
                    ));
                    return;
                }
                let mut returned_ref_kind = *dst_slot_kind;
                let mut tracks_returned_ref = dst_slot_kind.is_some();
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
                    let src_kind = state.kfunc_ref_kind(ref_id);
                    if let (Some(expected), Some(actual)) = (*dst_slot_kind, src_kind)
                        && expected != actual
                    {
                        self.errors.push(VccError::new(
                            VccErrorKind::PointerBounds,
                            format!(
                                "helper 194 arg1 stores {} reference into {} kptr slot",
                                actual.label(),
                                expected.label()
                            ),
                        ));
                        return;
                    }
                    returned_ref_kind = returned_ref_kind.or(src_kind);
                    tracks_returned_ref = true;
                    state.invalidate_kfunc_ref(ref_id);
                }
                if tracks_returned_ref {
                    state.set_live_kfunc_ref(*dst, true, returned_ref_kind);
                }
                if tracks_returned_ref
                    && let Ok(VccValueType::Ptr(mut dst_info)) = state.reg_type(*dst)
                {
                    dst_info.kfunc_ref = Some(*dst);
                    state.set_reg(*dst, VccValueType::Ptr(dst_info));
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
                        format!(
                            "{op} expects pointer in [Stack], got {}",
                            Self::space_name(space)
                        ),
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
                    if ty.class() != VccTypeClass::Scalar
                        && ty.class() != VccTypeClass::Bool
                        && ty.class() != VccTypeClass::Ptr
                    {
                        self.errors.push(VccError::new(
                            VccErrorKind::TypeMismatch {
                                expected: VccTypeClass::Bool,
                                actual: ty.class(),
                            },
                            "branch condition expects scalar or pointer",
                        ));
                    }
                }
                Err(err) => self.errors.push(err),
            },
            VccTerminator::Return { value } => {
                self.check_required_return_range(*value, state);
                if let Some(value) = value {
                    if let Err(err) = state.value_type(*value) {
                        self.errors.push(err);
                    }
                }
                let returned_ringbuf_ref = self.allowed_returned_ringbuf_ref(*value, state);
                if state.has_live_ringbuf_refs_except(returned_ringbuf_ref) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased ringbuf record reference at function exit",
                    ));
                }
                let returned_kfunc_ref = self.allowed_returned_kfunc_ref(*value, state);
                if state.has_live_kfunc_refs_except(returned_kfunc_ref) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased kfunc reference at function exit",
                    ));
                }
                if state.has_live_rcu_read_lock_except(self.allowed_rcu_depth()) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased RCU read lock at function exit",
                    ));
                }
                if state.has_live_preempt_disable_except(self.allowed_preempt_depth()) {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased preempt disable at function exit",
                    ));
                }
                let allowed_local_irq_slots = self.allowed_local_irq_slots(state);
                if state.has_live_local_irq_disable_except_slots(&allowed_local_irq_slots) {
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
                if state.has_live_bpf_spin_lock() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased bpf spin lock at function exit",
                    ));
                }
                if state.has_live_res_spin_lock_irqsave() {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        "unreleased res spin lock irqsave at function exit",
                    ));
                }
                self.check_live_iter_families_at_return(state);
                let allowed_ringbuf_dynptr_slots = self.allowed_ringbuf_dynptr_slots(state);
                if let Some(slot) =
                    state.first_live_ringbuf_dynptr_slot_except_slots(&allowed_ringbuf_dynptr_slots)
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "unreleased ringbuf dynptr reservation at function exit: stack slot {}",
                            slot.0
                        ),
                    ));
                }
                let allowed_unknown_stack_object_slots =
                    self.allowed_unknown_stack_object_slots(state);
                if let Some((slot, type_name)) = state
                    .first_live_unknown_stack_object_except_slots(
                        &allowed_unknown_stack_object_slots,
                    )
                {
                    self.errors.push(VccError::new(
                        VccErrorKind::PointerBounds,
                        format!(
                            "unreleased unknown stack object at function exit: {} in stack slot {}",
                            type_name, slot.0
                        ),
                    ));
                }
            }
        }
    }

    fn required_return_range_message(required: ScalarValueRange) -> String {
        if required.min == required.max {
            format!("callback return must be {}", required.min)
        } else {
            format!(
                "callback return must be in range {}..={}",
                required.min, required.max
            )
        }
    }

    fn check_required_return_range(&mut self, value: Option<VccValue>, state: &VccState) {
        let Some(required) = self
            .current_summary
            .as_ref()
            .and_then(|summary| summary.required_return_range())
        else {
            return;
        };
        let message = Self::required_return_range_message(required);
        let Some(value) = value else {
            self.errors.push(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                format!("{}; missing callback return value", message),
            ));
            return;
        };
        let ty = match state.value_type(value) {
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
                format!("{}; got non-scalar return", message),
            ));
            return;
        }
        let Some(range) = state.value_range(value, ty) else {
            self.errors.push(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                message,
            ));
            return;
        };
        if !required.contains(range.min, range.max) {
            self.errors.push(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                message,
            ));
        }
    }

    fn stale_packet_pointer_error(op: &str) -> VccError {
        VccError::new(
            VccErrorKind::InvalidLoadStore,
            format!(
                "{op} uses stale packet pointer after a packet-mutating helper; reload ctx.data/data_end before access"
            ),
        )
    }

    fn ctx_field_phi_type(reg: VccReg, ty: VccValueType, field: &CtxField) -> VccValueType {
        let VccValueType::Ptr(mut info) = ty else {
            return ty;
        };
        match field {
            CtxField::Data if info.space == VccAddrSpace::Packet => {
                info.bounds = Some(VccBounds {
                    min: 0,
                    max: 0,
                    limit: UNKNOWN_PACKET_LIMIT,
                });
                info.packet_root = Some(reg);
                info.packet_root_field = Some(VccPacketCtxField::Data);
                info.packet_ctx_field = Some(VccPacketCtxField::Data);
                info.packet_end = false;
            }
            CtxField::DataMeta if info.space == VccAddrSpace::Packet => {
                info.bounds = Some(VccBounds {
                    min: 0,
                    max: 0,
                    limit: UNKNOWN_PACKET_LIMIT,
                });
                info.packet_root = Some(reg);
                info.packet_root_field = Some(VccPacketCtxField::DataMeta);
                info.packet_ctx_field = Some(VccPacketCtxField::DataMeta);
                info.packet_end = false;
            }
            CtxField::DataEnd if info.space == VccAddrSpace::Packet => {
                info.packet_root = None;
                info.packet_root_field = None;
                info.packet_ctx_field = Some(VccPacketCtxField::DataEnd);
                info.packet_end = true;
            }
            CtxField::SockoptOptval if info.space == VccAddrSpace::Kernel => {
                info.bounds = Some(VccBounds {
                    min: 0,
                    max: 0,
                    limit: UNKNOWN_CONTEXT_BUFFER_LIMIT,
                });
                info.context_buffer_root = Some(reg);
                info.context_buffer_end = false;
            }
            CtxField::SockoptOptvalEnd if info.space == VccAddrSpace::Kernel => {
                info.context_buffer_root = None;
                info.context_buffer_end = true;
            }
            _ => {}
        }
        VccValueType::Ptr(info)
    }

    fn scalar_alias_root_for_phi(
        args: &[(VccBlockId, VccReg)],
        state: &VccState,
        ty: VccValueType,
    ) -> Option<VccReg> {
        if !matches!(
            ty.class(),
            VccTypeClass::Scalar | VccTypeClass::Bool
        ) {
            return None;
        }
        let mut root = None;
        for (_, reg) in args {
            let next = state.scalar_alias_root(*reg);
            root = Some(match root {
                None => next,
                Some(existing) if existing == next => existing,
                _ => return None,
            });
        }
        root
    }

    fn phi_arg_type_with_pointer_null_hint(
        ty: VccValueType,
        dst_ptr_hint: Option<VccPointerInfo>,
    ) -> VccValueType {
        if matches!(
            ty,
            VccValueType::Scalar {
                range: Some(VccRange { min: 0, max: 0 })
            }
        ) && dst_ptr_hint.is_some()
        {
            return VccValueType::Ptr(null_wildcard_ptr_info());
        }
        ty
    }

    fn allowed_returned_kfunc_ref(
        &self,
        value: Option<VccValue>,
        state: &VccState,
    ) -> Option<VccReg> {
        let expected_kind = self
            .current_summary
            .as_ref()
            .and_then(|summary| summary.kfunc_ref_return_kind())?;
        let VccValue::Reg(reg) = value? else {
            return None;
        };
        let VccValueType::Ptr(info) = state.reg_type(reg).ok()? else {
            return None;
        };
        if !matches!(info.space, VccAddrSpace::Kernel | VccAddrSpace::KernelBtf) {
            return None;
        }
        let ref_id = info.kfunc_ref?;
        if state.is_live_kfunc_ref(ref_id) && state.kfunc_ref_kind(ref_id) == Some(expected_kind) {
            Some(ref_id)
        } else {
            None
        }
    }

    fn allowed_rcu_depth(&self) -> u32 {
        self.current_summary
            .as_ref()
            .map(|summary| summary.rcu_read_lock_delta().max(0) as u32)
            .unwrap_or(0)
    }

    fn allowed_preempt_depth(&self) -> u32 {
        self.current_summary
            .as_ref()
            .map(|summary| summary.preempt_disable_delta().max(0) as u32)
            .unwrap_or(0)
    }

    fn allowed_local_irq_slots(&self, state: &VccState) -> HashMap<StackSlotId, u32> {
        let mut allowed = HashMap::new();
        let Some(summary) = self.current_summary.as_ref() else {
            return allowed;
        };
        for idx in 0..5 {
            let delta = summary.local_irq_delta_arg(idx).max(0) as u32;
            if delta == 0 {
                continue;
            }
            let Ok(VccValueType::Ptr(ptr)) = state.reg_type(VccReg(idx as u32)) else {
                continue;
            };
            if let VccAddrSpace::Stack(slot) = ptr.space {
                let entry = allowed.entry(slot).or_insert(0u32);
                *entry = entry.saturating_add(delta);
            }
        }
        allowed
    }

    fn check_live_iter_families_at_return(&mut self, state: &VccState) {
        for family in [
            KfuncIterFamily::TaskVma,
            KfuncIterFamily::Task,
            KfuncIterFamily::ScxDsq,
            KfuncIterFamily::Num,
            KfuncIterFamily::Bits,
            KfuncIterFamily::Css,
            KfuncIterFamily::CssTask,
            KfuncIterFamily::Dmabuf,
            KfuncIterFamily::KmemCache,
        ] {
            let allowed_slots = self.allowed_iter_slots(state, family);
            if state.has_live_iter_family_except_slots(family, &allowed_slots) {
                self.errors.push(VccError::new(
                    VccErrorKind::PointerBounds,
                    format!("unreleased {} iterator at function exit", iter_exit_label(family)),
                ));
            }
        }
    }

    fn allowed_iter_slots(
        &self,
        state: &VccState,
        family: KfuncIterFamily,
    ) -> HashMap<StackSlotId, u32> {
        let mut allowed = HashMap::new();
        let Some(summary) = self.current_summary.as_ref() else {
            return allowed;
        };
        for idx in 0..5 {
            let Some(delta) = summary.iter_delta_arg(idx) else {
                continue;
            };
            if delta.family != family || delta.delta <= 0 {
                continue;
            }
            let Ok(VccValueType::Ptr(ptr)) = state.reg_type(VccReg(idx as u32)) else {
                continue;
            };
            if let VccAddrSpace::Stack(slot) = ptr.space {
                let entry = allowed.entry(slot).or_insert(0u32);
                *entry = entry.saturating_add(delta.delta as u32);
            }
        }
        allowed
    }

    fn allowed_ringbuf_dynptr_slots(&self, state: &VccState) -> HashMap<StackSlotId, u32> {
        let mut allowed = HashMap::new();
        let Some(summary) = self.current_summary.as_ref() else {
            return allowed;
        };
        for idx in 0..5 {
            let delta = summary.ringbuf_dynptr_delta_arg(idx).max(0) as u32;
            if delta == 0 {
                continue;
            }
            let Ok(VccValueType::Ptr(ptr)) = state.reg_type(VccReg(idx as u32)) else {
                continue;
            };
            if let VccAddrSpace::Stack(slot) = ptr.space {
                let entry = allowed.entry(slot).or_insert(0u32);
                *entry = entry.saturating_add(delta);
            }
        }
        allowed
    }

    fn allowed_unknown_stack_object_slots(&self, state: &VccState) -> HashMap<StackSlotId, u32> {
        let mut allowed = HashMap::new();
        let Some(summary) = self.current_summary.as_ref() else {
            return allowed;
        };
        for idx in 0..5 {
            let mut delta = summary
                .unknown_stack_object_delta_arg(idx)
                .map(|delta| delta.delta.max(0) as u32)
                .unwrap_or(0);
            if summary.unknown_stack_object_required_arg(idx).is_some() {
                delta = delta.saturating_add(1);
            }
            if summary
                .unknown_stack_object_maybe_initialized_arg(idx)
                .is_some()
            {
                delta = delta.saturating_add(1);
            }
            if delta == 0 {
                continue;
            }
            let Ok(VccValueType::Ptr(ptr)) = state.reg_type(VccReg(idx as u32)) else {
                continue;
            };
            if let VccAddrSpace::Stack(slot) = ptr.space {
                let entry = allowed.entry(slot).or_insert(0u32);
                *entry = entry.saturating_add(delta);
            }
        }
        allowed
    }

    fn allowed_returned_ringbuf_ref(
        &self,
        value: Option<VccValue>,
        state: &VccState,
    ) -> Option<VccReg> {
        if !self
            .current_summary
            .as_ref()
            .is_some_and(|summary| summary.returns_ringbuf_record())
        {
            return None;
        }
        let VccValue::Reg(reg) = value? else {
            return None;
        };
        let VccValueType::Ptr(info) = state.reg_type(reg).ok()? else {
            return None;
        };
        if info.space != VccAddrSpace::RingBuf {
            return None;
        }
        let ref_id = info.ringbuf_ref?;
        state.is_live_ringbuf_ref(ref_id).then_some(ref_id)
    }

    fn map_value_source_for_phi(
        args: &[(VccBlockId, VccReg)],
        state: &VccState,
    ) -> PhiMapValueSource {
        let mut source: Option<VccMapLookupSource> = None;
        let mut source_map: Option<MapRef> = None;
        let mut exact_key_source = true;
        for (_, reg) in args {
            let next_source = state.map_value_source(*reg).cloned();
            let next_map = if state.map_value_source_is_ambiguous(*reg) {
                let Some(map) = state.map_value_ambiguous_map_source(*reg).cloned() else {
                    return PhiMapValueSource::Ambiguous;
                };
                exact_key_source = false;
                map
            } else if let Some(source) = next_source.as_ref() {
                source.map.clone()
            } else {
                return PhiMapValueSource::None;
            };
            match &source_map {
                Some(existing) if *existing != next_map => return PhiMapValueSource::Ambiguous,
                None => source_map = Some(next_map.clone()),
                _ => {}
            }
            if exact_key_source {
                source = match (source, next_source) {
                    (None, Some(next)) => Some(next),
                    (Some(existing), Some(next))
                        if existing.map == next.map
                            && state.map_lookup_keys_may_alias(existing.key, next.key) =>
                    {
                        Some(existing)
                    }
                    _ => {
                        exact_key_source = false;
                        None
                    }
                };
            }
        }
        if exact_key_source {
            source
                .map(PhiMapValueSource::Known)
                .unwrap_or(PhiMapValueSource::None)
        } else {
            source_map
                .map(PhiMapValueSource::KnownMap)
                .unwrap_or(PhiMapValueSource::None)
        }
    }
}

enum PhiMapValueSource {
    None,
    Known(VccMapLookupSource),
    KnownMap(MapRef),
    Ambiguous,
}

fn typed_null_copy_type(ty: VccValueType) -> Option<VccValueType> {
    match ty {
        VccValueType::Ptr(_) => Some(VccValueType::Ptr(null_wildcard_ptr_info())),
        _ => None,
    }
}
