use super::*;
use crate::compiler::mir::UnaryOpKind;

pub(super) fn apply_copy_inst(
    dst: VReg,
    src: &MirValue,
    slot_sizes: &HashMap<StackSlotId, i64>,
    state: &mut VerifierState,
) {
    let ty = value_type(src, state, slot_sizes);
    let range = value_range(src, state);
    let src_ctx_field = match src {
        MirValue::VReg(vreg) => state.ctx_field_source(*vreg).cloned(),
        _ => None,
    };
    let src_guard = match src {
        MirValue::VReg(vreg) => state.guard(*vreg),
        _ => None,
    };
    let src_non_zero = match src {
        MirValue::VReg(vreg) => state.is_non_zero(*vreg),
        MirValue::Const(value) => *value != 0,
        _ => false,
    };
    let src_not_equal = match src {
        MirValue::VReg(vreg) => state.not_equal_consts(*vreg).to_vec(),
        MirValue::Const(value) if *value != 0 => vec![0],
        _ => Vec::new(),
    };
    state.set_with_range(dst, ty, range);
    state.set_ctx_field_source(dst, src_ctx_field);
    if src_non_zero {
        state.set_non_zero(dst, true);
    }
    for excluded in src_not_equal {
        state.set_not_equal_const(dst, excluded);
    }
    if let Some(guard) = src_guard {
        state.set_guard(dst, guard);
    }
}

pub(super) fn apply_binop_inst(
    dst: VReg,
    op: BinOpKind,
    lhs: &MirValue,
    rhs: &MirValue,
    slot_sizes: &HashMap<StackSlotId, i64>,
    state: &mut VerifierState,
) {
    if matches!(
        op,
        BinOpKind::Eq
            | BinOpKind::Ne
            | BinOpKind::Lt
            | BinOpKind::Le
            | BinOpKind::Gt
            | BinOpKind::Ge
    ) {
        state.set_with_range(
            dst,
            VerifierType::Bool,
            ValueRange::Known { min: 0, max: 1 },
        );
        if let Some(guard) = guard_from_compare(op, lhs, rhs, state) {
            state.set_guard(dst, guard);
        }
        return;
    }

    if let Some(ty) = pointer_arith_result(op, lhs, rhs, state, slot_sizes) {
        state.set(dst, ty);
        return;
    }

    let range = range_for_binop(op, lhs, rhs, state);
    state.set_with_range(dst, VerifierType::Scalar, range);
}

pub(super) fn apply_unary_inst(
    dst: VReg,
    op: UnaryOpKind,
    src: &MirValue,
    state: &mut VerifierState,
) {
    let ty = match op {
        UnaryOpKind::Not => VerifierType::Bool,
        _ => VerifierType::Scalar,
    };
    let guard = if matches!(op, UnaryOpKind::Not) {
        if let MirValue::VReg(src_reg) = src {
            state.guard(*src_reg).and_then(invert_guard)
        } else {
            None
        }
    } else {
        None
    };
    let range = if matches!(op, UnaryOpKind::Not) {
        ValueRange::Known { min: 0, max: 1 }
    } else {
        ValueRange::Unknown
    };
    state.set_with_range(dst, ty, range);
    if let Some(guard) = guard {
        state.set_guard(dst, guard);
    }
}

pub(super) fn apply_typed_dst_inst(
    dst: VReg,
    types: &HashMap<VReg, MirType>,
    state: &mut VerifierState,
) {
    let ty = types
        .get(&dst)
        .map(verifier_type_from_mir)
        .unwrap_or(VerifierType::Scalar);
    state.set_with_range(dst, ty, ValueRange::Unknown);
}

pub(super) fn apply_phi_inst(
    dst: VReg,
    args: &[(BlockId, VReg)],
    types: &HashMap<VReg, MirType>,
    state: &mut VerifierState,
) {
    let mut merged_guard: Option<Option<Guard>> = None;
    for (_, reg) in args {
        let next = state.guard(*reg);
        merged_guard = Some(match merged_guard {
            None => next,
            Some(existing) if existing == next => existing,
            _ => None,
        });
        if matches!(merged_guard, Some(None)) {
            break;
        }
    }
    let phi_guard = merged_guard.flatten();

    let ty = types
        .get(&dst)
        .map(verifier_type_from_mir)
        .unwrap_or(VerifierType::Scalar);
    let range = range_for_phi(args, state);
    let ty = ptr_type_for_phi(args, state).unwrap_or(ty);
    state.set_with_range(dst, ty, range);
    if let Some(guard) = phi_guard {
        state.set_guard(dst, guard);
    }
}
