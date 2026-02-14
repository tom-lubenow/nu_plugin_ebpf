use super::*;

pub(in crate::compiler::verifier_types) fn value_range(
    value: &MirValue,
    state: &VerifierState,
) -> ValueRange {
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

pub(in crate::compiler::verifier_types) fn join_range(a: ValueRange, b: ValueRange) -> ValueRange {
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

pub(in crate::compiler::verifier_types) fn range_for_binop(
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

pub(in crate::compiler::verifier_types) fn range_for_phi(
    args: &[(BlockId, VReg)],
    state: &VerifierState,
) -> ValueRange {
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

pub(in crate::compiler::verifier_types) fn clamp_i128_to_i64(value: i128) -> i64 {
    if value > i64::MAX as i128 {
        i64::MAX
    } else if value < i64::MIN as i128 {
        i64::MIN
    } else {
        value as i64
    }
}

pub(in crate::compiler::verifier_types) fn ptr_type_for_phi(
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
