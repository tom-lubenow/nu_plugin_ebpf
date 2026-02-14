use super::*;

pub(in crate::compiler::verifier_types) fn refine_on_branch(
    state: &VerifierState,
    guard: Option<Guard>,
    take_true: bool,
) -> VerifierState {
    let mut next = state.clone();
    if let Some(guard) = guard {
        match guard {
            Guard::Ptr {
                ptr,
                true_is_non_null,
            } => {
                let wants_non_null = if take_true {
                    true_is_non_null
                } else {
                    !true_is_non_null
                };
                let ctx_field_source = next.ctx_field_source(ptr).cloned();
                let current = next.get(ptr);
                if let VerifierType::Ptr {
                    space,
                    nullability,
                    bounds,
                    ringbuf_ref,
                    kfunc_ref,
                } = current
                {
                    if (wants_non_null && nullability == Nullability::Null)
                        || (!wants_non_null && nullability == Nullability::NonNull)
                    {
                        next.mark_unreachable();
                        return next;
                    }
                    let nullability = if wants_non_null {
                        Nullability::NonNull
                    } else {
                        Nullability::Null
                    };
                    if !wants_non_null {
                        if let Some(ref_id) = ringbuf_ref {
                            next.set_live_ringbuf_ref(ref_id, false);
                        }
                        if let Some(ref_id) = kfunc_ref {
                            next.set_live_kfunc_ref(ref_id, false, None);
                        }
                    }
                    next.set(
                        ptr,
                        VerifierType::Ptr {
                            space,
                            nullability,
                            bounds,
                            ringbuf_ref,
                            kfunc_ref,
                        },
                    );
                    next.set_ctx_field_source(ptr, ctx_field_source.clone());
                    if let Some(field) = ctx_field_source {
                        next.refine_ctx_field_nullability(&field, nullability);
                    }
                }
            }
            Guard::NonZero {
                reg,
                true_is_non_zero,
            } => {
                let wants_non_zero = if take_true {
                    true_is_non_zero
                } else {
                    !true_is_non_zero
                };
                if wants_non_zero {
                    if let ValueRange::Known { min, max } = next.get_range(reg) {
                        let new_range = if min == 0 && max > 0 {
                            ValueRange::Known { min: 1, max }
                        } else if max == 0 && min < 0 {
                            ValueRange::Known { min, max: -1 }
                        } else {
                            ValueRange::Known { min, max }
                        };
                        next.set_range(reg, new_range);
                    }
                    next.set_non_zero(reg, true);
                    next.set_not_equal_const(reg, 0);
                } else {
                    next.set_range(reg, ValueRange::Known { min: 0, max: 0 });
                    next.set_non_zero(reg, false);
                    next.clear_not_equal_const(reg);
                }
            }
            Guard::Range { reg, op, value } => {
                let Some(effective_op) = effective_branch_compare(op, take_true) else {
                    return next;
                };
                let current = next.get_range(reg);
                let excluded = next.not_equal_consts(reg).to_vec();
                if !range_can_satisfy_const_compare(current, &excluded, effective_op, value) {
                    next.mark_unreachable();
                    return next;
                }
                let new_range = refine_range(current, op, value, take_true);
                next.set_range(reg, new_range);
                match effective_op {
                    BinOpKind::Eq => next.clear_not_equal_const(reg),
                    BinOpKind::Ne => next.set_not_equal_const(reg, value),
                    _ => next.retain_not_equal_in_range(reg, new_range),
                }
                let range_excludes_zero =
                    matches!(new_range, ValueRange::Known { min, max } if min > 0 || max < 0);
                next.set_non_zero(reg, next.is_non_zero(reg) || range_excludes_zero);
            }
            Guard::RangeCmp { lhs, rhs, op } => {
                let lhs_range = next.get_range(lhs);
                let rhs_range = next.get_range(rhs);
                let Some(effective_op) = effective_branch_compare(op, take_true) else {
                    return next;
                };
                if !ranges_can_satisfy_compare(lhs_range, rhs_range, effective_op) {
                    next.mark_unreachable();
                    return next;
                }
                let (new_lhs, new_rhs) = refine_compare_ranges(lhs_range, rhs_range, op, take_true);
                next.set_range(lhs, new_lhs);
                next.set_range(rhs, new_rhs);
                next.retain_not_equal_in_range(lhs, new_lhs);
                next.retain_not_equal_in_range(rhs, new_rhs);
                let lhs_excludes_zero =
                    matches!(new_lhs, ValueRange::Known { min, max } if min > 0 || max < 0);
                next.set_non_zero(lhs, next.is_non_zero(lhs) || lhs_excludes_zero);
                let rhs_excludes_zero =
                    matches!(new_rhs, ValueRange::Known { min, max } if min > 0 || max < 0);
                next.set_non_zero(rhs, next.is_non_zero(rhs) || rhs_excludes_zero);
            }
        }
    }
    next
}
