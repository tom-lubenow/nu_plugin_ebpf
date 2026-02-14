use super::*;

pub(in crate::compiler::verifier_types) fn range_and(
    lhs: ValueRange,
    rhs: ValueRange,
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

pub(in crate::compiler::verifier_types) fn range_or(
    lhs: ValueRange,
    rhs: ValueRange,
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

pub(in crate::compiler::verifier_types) fn range_xor(
    lhs: ValueRange,
    rhs: ValueRange,
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

pub(in crate::compiler::verifier_types) fn mask_for_max(max: i64) -> u64 {
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
