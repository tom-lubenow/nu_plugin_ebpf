use super::*;

pub(super) fn refine_on_branch(
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
                    if let Some(slot) = next.ranges.get_mut(reg.0 as usize) {
                        if let ValueRange::Known { min, max } = *slot {
                            let new_range = if min == 0 && max > 0 {
                                ValueRange::Known { min: 1, max }
                            } else if max == 0 && min < 0 {
                                ValueRange::Known { min, max: -1 }
                            } else {
                                ValueRange::Known { min, max }
                            };
                            *slot = new_range;
                        }
                    }
                    if let Some(slot) = next.non_zero.get_mut(reg.0 as usize) {
                        *slot = true;
                    }
                    next.set_not_equal_const(reg, 0);
                } else {
                    if let Some(slot) = next.ranges.get_mut(reg.0 as usize) {
                        *slot = ValueRange::Known { min: 0, max: 0 };
                    }
                    if let Some(slot) = next.non_zero.get_mut(reg.0 as usize) {
                        *slot = false;
                    }
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
                if let Some(slot) = next.ranges.get_mut(reg.0 as usize) {
                    *slot = new_range;
                }
                match effective_op {
                    BinOpKind::Eq => next.clear_not_equal_const(reg),
                    BinOpKind::Ne => next.set_not_equal_const(reg, value),
                    _ => next.retain_not_equal_in_range(reg, new_range),
                }
                let range_excludes_zero =
                    matches!(new_range, ValueRange::Known { min, max } if min > 0 || max < 0);
                if let Some(slot) = next.non_zero.get_mut(reg.0 as usize) {
                    *slot = *slot || range_excludes_zero;
                }
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
                if let Some(slot) = next.ranges.get_mut(lhs.0 as usize) {
                    *slot = new_lhs;
                }
                if let Some(slot) = next.ranges.get_mut(rhs.0 as usize) {
                    *slot = new_rhs;
                }
                next.retain_not_equal_in_range(lhs, new_lhs);
                next.retain_not_equal_in_range(rhs, new_rhs);
                let lhs_excludes_zero =
                    matches!(new_lhs, ValueRange::Known { min, max } if min > 0 || max < 0);
                if let Some(slot) = next.non_zero.get_mut(lhs.0 as usize) {
                    *slot = *slot || lhs_excludes_zero;
                }
                let rhs_excludes_zero =
                    matches!(new_rhs, ValueRange::Known { min, max } if min > 0 || max < 0);
                if let Some(slot) = next.non_zero.get_mut(rhs.0 as usize) {
                    *slot = *slot || rhs_excludes_zero;
                }
            }
        }
    }
    next
}
pub(super) fn guard_from_compare(
    op: BinOpKind,
    lhs: &MirValue,
    rhs: &MirValue,
    state: &VerifierState,
) -> Option<Guard> {
    match (lhs, rhs) {
        (MirValue::VReg(v), MirValue::Const(c)) => guard_from_compare_reg_const(op, *v, *c, state),
        (MirValue::Const(c), MirValue::VReg(v)) => {
            guard_from_compare_reg_const(swap_compare(op)?, *v, *c, state)
        }
        (MirValue::VReg(lhs), MirValue::VReg(rhs)) => {
            let op = match op {
                BinOpKind::Eq
                | BinOpKind::Ne
                | BinOpKind::Lt
                | BinOpKind::Le
                | BinOpKind::Gt
                | BinOpKind::Ge => op,
                _ => return None,
            };
            let lhs_ty = state.get(*lhs);
            let rhs_ty = state.get(*rhs);
            if matches!(lhs_ty, VerifierType::Ptr { .. })
                || matches!(rhs_ty, VerifierType::Ptr { .. })
            {
                return None;
            }
            Some(Guard::RangeCmp {
                lhs: *lhs,
                rhs: *rhs,
                op,
            })
        }
        _ => None,
    }
}

pub(super) fn guard_from_compare_reg_const(
    op: BinOpKind,
    reg: VReg,
    value: i64,
    state: &VerifierState,
) -> Option<Guard> {
    let op = match op {
        BinOpKind::Eq
        | BinOpKind::Ne
        | BinOpKind::Lt
        | BinOpKind::Le
        | BinOpKind::Gt
        | BinOpKind::Ge => op,
        _ => return None,
    };

    let ty = state.get(reg);
    if matches!(ty, VerifierType::Ptr { .. }) {
        if value == 0 && matches!(op, BinOpKind::Eq | BinOpKind::Ne) {
            return Some(Guard::Ptr {
                ptr: reg,
                true_is_non_null: matches!(op, BinOpKind::Ne),
            });
        }
        return None;
    }

    if value == 0 && matches!(op, BinOpKind::Eq | BinOpKind::Ne) {
        return Some(Guard::NonZero {
            reg,
            true_is_non_zero: matches!(op, BinOpKind::Ne),
        });
    }

    Some(Guard::Range { reg, op, value })
}

pub(super) fn swap_compare(op: BinOpKind) -> Option<BinOpKind> {
    Some(match op {
        BinOpKind::Eq => BinOpKind::Eq,
        BinOpKind::Ne => BinOpKind::Ne,
        BinOpKind::Lt => BinOpKind::Gt,
        BinOpKind::Le => BinOpKind::Ge,
        BinOpKind::Gt => BinOpKind::Lt,
        BinOpKind::Ge => BinOpKind::Le,
        _ => return None,
    })
}

pub(super) fn negate_compare(op: BinOpKind) -> Option<BinOpKind> {
    Some(match op {
        BinOpKind::Eq => BinOpKind::Ne,
        BinOpKind::Ne => BinOpKind::Eq,
        BinOpKind::Lt => BinOpKind::Ge,
        BinOpKind::Le => BinOpKind::Gt,
        BinOpKind::Gt => BinOpKind::Le,
        BinOpKind::Ge => BinOpKind::Lt,
        _ => return None,
    })
}

pub(super) fn invert_guard(guard: Guard) -> Option<Guard> {
    match guard {
        Guard::Ptr {
            ptr,
            true_is_non_null,
        } => Some(Guard::Ptr {
            ptr,
            true_is_non_null: !true_is_non_null,
        }),
        Guard::NonZero {
            reg,
            true_is_non_zero,
        } => Some(Guard::NonZero {
            reg,
            true_is_non_zero: !true_is_non_zero,
        }),
        Guard::Range { reg, op, value } => Some(Guard::Range {
            reg,
            op: negate_compare(op)?,
            value,
        }),
        Guard::RangeCmp { lhs, rhs, op } => Some(Guard::RangeCmp {
            lhs,
            rhs,
            op: negate_compare(op)?,
        }),
    }
}

pub(super) fn effective_branch_compare(op: BinOpKind, take_true: bool) -> Option<BinOpKind> {
    if take_true {
        Some(op)
    } else {
        negate_compare(op)
    }
}

pub(super) fn range_may_equal(range: ValueRange, value: i64) -> bool {
    match range {
        ValueRange::Known { min, max } => value >= min && value <= max,
        ValueRange::Unknown => true,
    }
}

pub(super) fn range_can_satisfy_const_compare(
    range: ValueRange,
    excluded: &[i64],
    op: BinOpKind,
    value: i64,
) -> bool {
    match op {
        BinOpKind::Eq => {
            if excluded.contains(&value) {
                return false;
            }
            range_may_equal(range, value)
        }
        BinOpKind::Ne => match range {
            ValueRange::Known { min, max } => !(min == max && min == value),
            ValueRange::Unknown => true,
        },
        BinOpKind::Lt => match range {
            ValueRange::Known { min, .. } => min < value,
            ValueRange::Unknown => true,
        },
        BinOpKind::Le => match range {
            ValueRange::Known { min, .. } => min <= value,
            ValueRange::Unknown => true,
        },
        BinOpKind::Gt => match range {
            ValueRange::Known { max, .. } => max > value,
            ValueRange::Unknown => true,
        },
        BinOpKind::Ge => match range {
            ValueRange::Known { max, .. } => max >= value,
            ValueRange::Unknown => true,
        },
        _ => true,
    }
}

pub(super) fn ranges_can_satisfy_compare(lhs: ValueRange, rhs: ValueRange, op: BinOpKind) -> bool {
    let Some((lhs_min, lhs_max)) = range_bounds(lhs) else {
        return true;
    };
    let Some((rhs_min, rhs_max)) = range_bounds(rhs) else {
        return true;
    };

    match op {
        BinOpKind::Eq => lhs_min <= rhs_max && rhs_min <= lhs_max,
        BinOpKind::Ne => !(lhs_min == lhs_max && rhs_min == rhs_max && lhs_min == rhs_min),
        BinOpKind::Lt => lhs_min < rhs_max,
        BinOpKind::Le => lhs_min <= rhs_max,
        BinOpKind::Gt => lhs_max > rhs_min,
        BinOpKind::Ge => lhs_max >= rhs_min,
        _ => true,
    }
}

pub(super) fn refine_range(
    current: ValueRange,
    op: BinOpKind,
    value: i64,
    take_true: bool,
) -> ValueRange {
    let op = if take_true {
        op
    } else {
        let Some(negated) = negate_compare(op) else {
            return current;
        };
        negated
    };

    if matches!(op, BinOpKind::Ne) {
        return match current {
            ValueRange::Known { min, max } => {
                if value < min || value > max {
                    ValueRange::Known { min, max }
                } else if min == max {
                    ValueRange::Unknown
                } else if value == min {
                    ValueRange::Known {
                        min: min.saturating_add(1),
                        max,
                    }
                } else if value == max {
                    ValueRange::Known {
                        min,
                        max: max.saturating_sub(1),
                    }
                } else {
                    ValueRange::Known { min, max }
                }
            }
            ValueRange::Unknown => ValueRange::Unknown,
        };
    }

    let (min, max) = match op {
        BinOpKind::Eq => (Some(value), Some(value)),
        BinOpKind::Lt => (None, Some(value.saturating_sub(1))),
        BinOpKind::Le => (None, Some(value)),
        BinOpKind::Gt => (Some(value.saturating_add(1)), None),
        BinOpKind::Ge => (Some(value), None),
        _ => return current,
    };

    intersect_range(current, min, max)
}

pub(super) fn refine_compare_ranges(
    lhs: ValueRange,
    rhs: ValueRange,
    op: BinOpKind,
    take_true: bool,
) -> (ValueRange, ValueRange) {
    let op = if take_true {
        op
    } else {
        let Some(negated) = negate_compare(op) else {
            return (lhs, rhs);
        };
        negated
    };

    let lhs_bounds = range_bounds(lhs);
    let rhs_bounds = range_bounds(rhs);

    match op {
        BinOpKind::Eq => {
            let lhs = match rhs_bounds {
                Some((min, max)) => intersect_range(lhs, Some(min), Some(max)),
                None => lhs,
            };
            let rhs = match lhs_bounds {
                Some((min, max)) => intersect_range(rhs, Some(min), Some(max)),
                None => rhs,
            };
            (lhs, rhs)
        }
        BinOpKind::Ne => {
            let lhs = if let Some((min, max)) = rhs_bounds {
                if min == max {
                    refine_range(lhs, BinOpKind::Ne, min, true)
                } else {
                    lhs
                }
            } else {
                lhs
            };
            let rhs = if let Some((min, max)) = lhs_bounds {
                if min == max {
                    refine_range(rhs, BinOpKind::Ne, min, true)
                } else {
                    rhs
                }
            } else {
                rhs
            };
            (lhs, rhs)
        }
        BinOpKind::Lt => {
            let lhs = match rhs_bounds {
                Some((_, rhs_max)) => {
                    let max = rhs_max.saturating_sub(1);
                    intersect_range(lhs, None, Some(max))
                }
                None => lhs,
            };
            let rhs = match lhs_bounds {
                Some((lhs_min, _)) => {
                    let min = lhs_min.saturating_add(1);
                    intersect_range(rhs, Some(min), None)
                }
                None => rhs,
            };
            (lhs, rhs)
        }
        BinOpKind::Le => {
            let lhs = match rhs_bounds {
                Some((_, rhs_max)) => intersect_range(lhs, None, Some(rhs_max)),
                None => lhs,
            };
            let rhs = match lhs_bounds {
                Some((lhs_min, _)) => intersect_range(rhs, Some(lhs_min), None),
                None => rhs,
            };
            (lhs, rhs)
        }
        BinOpKind::Gt => {
            let lhs = match rhs_bounds {
                Some((rhs_min, _)) => {
                    let min = rhs_min.saturating_add(1);
                    intersect_range(lhs, Some(min), None)
                }
                None => lhs,
            };
            let rhs = match lhs_bounds {
                Some((_, lhs_max)) => {
                    let max = lhs_max.saturating_sub(1);
                    intersect_range(rhs, None, Some(max))
                }
                None => rhs,
            };
            (lhs, rhs)
        }
        BinOpKind::Ge => {
            let lhs = match rhs_bounds {
                Some((rhs_min, _)) => intersect_range(lhs, Some(rhs_min), None),
                None => lhs,
            };
            let rhs = match lhs_bounds {
                Some((_, lhs_max)) => intersect_range(rhs, None, Some(lhs_max)),
                None => rhs,
            };
            (lhs, rhs)
        }
        _ => (lhs, rhs),
    }
}

pub(super) fn range_bounds(range: ValueRange) -> Option<(i64, i64)> {
    match range {
        ValueRange::Known { min, max } => Some((min, max)),
        ValueRange::Unknown => None,
    }
}

pub(super) fn intersect_range(
    current: ValueRange,
    min: Option<i64>,
    max: Option<i64>,
) -> ValueRange {
    if min.is_none() && max.is_none() {
        return current;
    }
    match current {
        ValueRange::Known {
            min: cur_min,
            max: cur_max,
        } => {
            let min = min.map(|v| cur_min.max(v)).unwrap_or(cur_min);
            let max = max.map(|v| cur_max.min(v)).unwrap_or(cur_max);
            if min <= max {
                ValueRange::Known { min, max }
            } else {
                ValueRange::Known {
                    min: cur_min,
                    max: cur_max,
                }
            }
        }
        ValueRange::Unknown => {
            let min = min.unwrap_or(i64::MIN);
            let max = max.unwrap_or(i64::MAX);
            if min <= max {
                ValueRange::Known { min, max }
            } else {
                ValueRange::Unknown
            }
        }
    }
}
