use super::*;

pub(super) fn value_range(value: &MirValue, state: &VerifierState) -> ValueRange {
    match value {
        MirValue::Const(c) => ValueRange::Known { min: *c, max: *c },
        MirValue::VReg(v) => {
            let mut range = state.get_range(*v);
            if state.is_non_zero(*v) {
                range = match range {
                    ValueRange::Known { min, max } => {
                        if min < 0 && max > 0 {
                            ValueRange::Unknown
                        } else if min == 0 && max > 0 {
                            ValueRange::Known { min: 1, max }
                        } else if max == 0 && min < 0 {
                            ValueRange::Known { min, max: -1 }
                        } else if min == 0 && max == 0 {
                            ValueRange::Unknown
                        } else {
                            ValueRange::Known { min, max }
                        }
                    }
                    ValueRange::Unknown => ValueRange::Unknown,
                };
            }
            range
        }
        MirValue::StackSlot(_) => ValueRange::Unknown,
    }
}
pub(super) fn join_range(a: ValueRange, b: ValueRange) -> ValueRange {
    match (a, b) {
        (
            ValueRange::Known {
                min: a_min,
                max: a_max,
            },
            ValueRange::Known {
                min: b_min,
                max: b_max,
            },
        ) => ValueRange::Known {
            min: a_min.min(b_min),
            max: a_max.max(b_max),
        },
        _ => ValueRange::Unknown,
    }
}

pub(super) fn range_add(a: ValueRange, b: ValueRange) -> ValueRange {
    match (a, b) {
        (
            ValueRange::Known {
                min: a_min,
                max: a_max,
            },
            ValueRange::Known {
                min: b_min,
                max: b_max,
            },
        ) => ValueRange::Known {
            min: a_min.saturating_add(b_min),
            max: a_max.saturating_add(b_max),
        },
        _ => ValueRange::Unknown,
    }
}

pub(super) fn range_sub(a: ValueRange, b: ValueRange) -> ValueRange {
    match (a, b) {
        (
            ValueRange::Known {
                min: a_min,
                max: a_max,
            },
            ValueRange::Known {
                min: b_min,
                max: b_max,
            },
        ) => ValueRange::Known {
            min: a_min.saturating_sub(b_max),
            max: a_max.saturating_sub(b_min),
        },
        _ => ValueRange::Unknown,
    }
}

pub(super) fn range_for_binop(
    op: BinOpKind,
    lhs: &MirValue,
    rhs: &MirValue,
    state: &VerifierState,
) -> ValueRange {
    let lhs_range = value_range(lhs, state);
    let rhs_range = value_range(rhs, state);
    match op {
        BinOpKind::Add => range_add(lhs_range, rhs_range),
        BinOpKind::Sub => range_sub(lhs_range, rhs_range),
        BinOpKind::Mul => range_mul(lhs_range, rhs_range),
        BinOpKind::Div => range_div(lhs_range, rhs_range),
        BinOpKind::Mod => range_mod(lhs_range, rhs_range),
        BinOpKind::Shl => range_shift(lhs_range, rhs_range, true),
        BinOpKind::Shr => range_shift(lhs_range, rhs_range, false),
        BinOpKind::And => range_and(lhs_range, rhs_range),
        BinOpKind::Or => range_or(lhs_range, rhs_range),
        BinOpKind::Xor => range_xor(lhs_range, rhs_range),
        _ => ValueRange::Unknown,
    }
}

pub(super) fn range_for_phi(args: &[(BlockId, VReg)], state: &VerifierState) -> ValueRange {
    let mut merged = None;
    for (_, vreg) in args {
        let range = state.get_range(*vreg);
        merged = Some(match merged {
            None => range,
            Some(current) => join_range(current, range),
        });
    }
    merged.unwrap_or(ValueRange::Unknown)
}

pub(super) fn clamp_i128_to_i64(value: i128) -> i64 {
    if value > i64::MAX as i128 {
        i64::MAX
    } else if value < i64::MIN as i128 {
        i64::MIN
    } else {
        value as i64
    }
}

pub(super) fn range_mul(a: ValueRange, b: ValueRange) -> ValueRange {
    match (a, b) {
        (
            ValueRange::Known {
                min: a_min,
                max: a_max,
            },
            ValueRange::Known {
                min: b_min,
                max: b_max,
            },
        ) => {
            let candidates = [
                (a_min as i128) * (b_min as i128),
                (a_min as i128) * (b_max as i128),
                (a_max as i128) * (b_min as i128),
                (a_max as i128) * (b_max as i128),
            ];
            let mut min = i128::MAX;
            let mut max = i128::MIN;
            for val in candidates {
                min = min.min(val);
                max = max.max(val);
            }
            ValueRange::Known {
                min: clamp_i128_to_i64(min),
                max: clamp_i128_to_i64(max),
            }
        }
        _ => ValueRange::Unknown,
    }
}

pub(super) fn range_shift(lhs: ValueRange, rhs: ValueRange, is_left: bool) -> ValueRange {
    let (lhs_min, lhs_max, rhs_min, rhs_max) = match (lhs, rhs) {
        (
            ValueRange::Known {
                min: lhs_min,
                max: lhs_max,
            },
            ValueRange::Known {
                min: rhs_min,
                max: rhs_max,
            },
        ) => (lhs_min, lhs_max, rhs_min, rhs_max),
        _ => return ValueRange::Unknown,
    };

    if rhs_min < 0 || rhs_max > 63 {
        return ValueRange::Unknown;
    }

    let mut min = i128::MAX;
    let mut max = i128::MIN;
    let lhs_vals = [lhs_min, lhs_max];
    let rhs_vals = [rhs_min, rhs_max];
    for lhs_val in lhs_vals {
        for rhs_val in rhs_vals {
            let shifted = if is_left {
                (lhs_val as i128) << rhs_val
            } else {
                (lhs_val as i128) >> rhs_val
            };
            min = min.min(shifted);
            max = max.max(shifted);
        }
    }

    ValueRange::Known {
        min: clamp_i128_to_i64(min),
        max: clamp_i128_to_i64(max),
    }
}

pub(super) fn range_div(lhs: ValueRange, rhs: ValueRange) -> ValueRange {
    match (lhs, rhs) {
        (
            ValueRange::Known {
                min: lhs_min,
                max: lhs_max,
            },
            ValueRange::Known {
                min: rhs_min,
                max: rhs_max,
            },
        ) => {
            if rhs_min <= 0 && rhs_max >= 0 {
                return ValueRange::Unknown;
            }
            let candidates = [
                (lhs_min as i128) / (rhs_min as i128),
                (lhs_min as i128) / (rhs_max as i128),
                (lhs_max as i128) / (rhs_min as i128),
                (lhs_max as i128) / (rhs_max as i128),
            ];
            let mut min = i128::MAX;
            let mut max = i128::MIN;
            for val in candidates {
                min = min.min(val);
                max = max.max(val);
            }
            ValueRange::Known {
                min: clamp_i128_to_i64(min),
                max: clamp_i128_to_i64(max),
            }
        }
        _ => ValueRange::Unknown,
    }
}

pub(super) fn range_mod(lhs: ValueRange, rhs: ValueRange) -> ValueRange {
    match (lhs, rhs) {
        (
            ValueRange::Known {
                min: lhs_min,
                max: _lhs_max,
            },
            ValueRange::Known {
                min: rhs_min,
                max: rhs_max,
            },
        ) => {
            if rhs_min <= 0 || rhs_max <= 0 {
                return ValueRange::Unknown;
            }
            if lhs_min < 0 {
                return ValueRange::Unknown;
            }
            let max_mod = rhs_max.saturating_sub(1);
            ValueRange::Known {
                min: 0,
                max: max_mod,
            }
        }
        _ => ValueRange::Unknown,
    }
}

pub(super) fn range_and(lhs: ValueRange, rhs: ValueRange) -> ValueRange {
    let (lhs_min, lhs_max, rhs_min, rhs_max) = match (lhs, rhs) {
        (
            ValueRange::Known {
                min: lhs_min,
                max: lhs_max,
            },
            ValueRange::Known {
                min: rhs_min,
                max: rhs_max,
            },
        ) => (lhs_min, lhs_max, rhs_min, rhs_max),
        _ => return ValueRange::Unknown,
    };
    if lhs_min == lhs_max && rhs_min == rhs_max {
        let val = lhs_min & rhs_min;
        return ValueRange::Known { min: val, max: val };
    }
    if lhs_min < 0 || rhs_min < 0 {
        return ValueRange::Unknown;
    }
    let mask = mask_for_max(lhs_max) & mask_for_max(rhs_max);
    let max = lhs_max.min(rhs_max).min(mask as i64);
    ValueRange::Known { min: 0, max }
}

pub(super) fn range_or(lhs: ValueRange, rhs: ValueRange) -> ValueRange {
    let (lhs_min, lhs_max, rhs_min, rhs_max) = match (lhs, rhs) {
        (
            ValueRange::Known {
                min: lhs_min,
                max: lhs_max,
            },
            ValueRange::Known {
                min: rhs_min,
                max: rhs_max,
            },
        ) => (lhs_min, lhs_max, rhs_min, rhs_max),
        _ => return ValueRange::Unknown,
    };
    if lhs_min == lhs_max && rhs_min == rhs_max {
        let val = lhs_min | rhs_min;
        return ValueRange::Known { min: val, max: val };
    }
    if lhs_min < 0 || rhs_min < 0 {
        return ValueRange::Unknown;
    }
    let mask = mask_for_max(lhs_max) | mask_for_max(rhs_max);
    let max = (mask as i64).min(lhs_max.saturating_add(rhs_max));
    ValueRange::Known { min: 0, max }
}

pub(super) fn range_xor(lhs: ValueRange, rhs: ValueRange) -> ValueRange {
    let (lhs_min, lhs_max, rhs_min, rhs_max) = match (lhs, rhs) {
        (
            ValueRange::Known {
                min: lhs_min,
                max: lhs_max,
            },
            ValueRange::Known {
                min: rhs_min,
                max: rhs_max,
            },
        ) => (lhs_min, lhs_max, rhs_min, rhs_max),
        _ => return ValueRange::Unknown,
    };
    if lhs_min == lhs_max && rhs_min == rhs_max {
        let val = lhs_min ^ rhs_min;
        return ValueRange::Known { min: val, max: val };
    }
    if lhs_min < 0 || rhs_min < 0 {
        return ValueRange::Unknown;
    }
    let mask = mask_for_max(lhs_max) | mask_for_max(rhs_max);
    let max = (mask as i64).min(lhs_max.saturating_add(rhs_max));
    ValueRange::Known { min: 0, max }
}

pub(super) fn mask_for_max(max: i64) -> u64 {
    if max <= 0 {
        return 0;
    }
    let max = max as u64;
    if max == u64::MAX {
        return u64::MAX;
    }
    let bit = 64 - max.leading_zeros();
    if bit >= 64 {
        u64::MAX
    } else {
        (1u64 << bit) - 1
    }
}

pub(super) fn ptr_type_for_phi(
    args: &[(BlockId, VReg)],
    state: &VerifierState,
) -> Option<VerifierType> {
    let mut merged: Option<VerifierType> = None;
    for (_, vreg) in args {
        let ty = state.get(*vreg);
        if !matches!(ty, VerifierType::Ptr { .. }) {
            return None;
        }
        merged = Some(match merged {
            None => ty,
            Some(existing) => join_type(existing, ty),
        });
    }
    merged
}
