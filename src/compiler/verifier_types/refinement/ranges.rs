use super::*;

pub(in crate::compiler::verifier_types) fn range_may_equal(range: ValueRange, value: i64) -> bool {
    match range {
        ValueRange::Known { min, max } => value >= min && value <= max,
        ValueRange::Unknown => true,
    }
}

pub(in crate::compiler::verifier_types) fn range_can_satisfy_const_compare(
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

pub(in crate::compiler::verifier_types) fn ranges_can_satisfy_compare(
    lhs: ValueRange,
    rhs: ValueRange,
    op: BinOpKind,
) -> bool {
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

pub(in crate::compiler::verifier_types) fn refine_range(
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

pub(in crate::compiler::verifier_types) fn refine_compare_ranges(
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

pub(in crate::compiler::verifier_types) fn range_bounds(range: ValueRange) -> Option<(i64, i64)> {
    match range {
        ValueRange::Known { min, max } => Some((min, max)),
        ValueRange::Unknown => None,
    }
}

pub(in crate::compiler::verifier_types) fn intersect_range(
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
