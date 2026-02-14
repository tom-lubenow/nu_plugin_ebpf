use super::*;

pub(in crate::compiler::verifier_types) fn range_add(a: ValueRange, b: ValueRange) -> ValueRange {
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

pub(in crate::compiler::verifier_types) fn range_sub(a: ValueRange, b: ValueRange) -> ValueRange {
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

pub(in crate::compiler::verifier_types) fn range_mul(a: ValueRange, b: ValueRange) -> ValueRange {
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

pub(in crate::compiler::verifier_types) fn range_shift(
    lhs: ValueRange,
    rhs: ValueRange,
    is_left: bool,
) -> ValueRange {
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

pub(in crate::compiler::verifier_types) fn range_div(
    lhs: ValueRange,
    rhs: ValueRange,
) -> ValueRange {
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

pub(in crate::compiler::verifier_types) fn range_mod(
    lhs: ValueRange,
    rhs: ValueRange,
) -> ValueRange {
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
