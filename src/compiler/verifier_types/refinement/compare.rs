use super::*;

pub(in crate::compiler::verifier_types) fn guard_from_compare(
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
                return bounded_end_guard(op, *lhs, *rhs, state);
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

pub(in crate::compiler::verifier_types) fn guard_from_compare_reg_const(
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

fn bounded_end_guard(op: BinOpKind, lhs: VReg, rhs: VReg, state: &VerifierState) -> Option<Guard> {
    let lhs_ty = state.get(lhs);
    let rhs_ty = state.get(rhs);

    let make_packet_guard = |ptr: VReg, normalized_op: BinOpKind| match normalized_op {
        BinOpKind::Le | BinOpKind::Lt | BinOpKind::Ge | BinOpKind::Gt => Some(Guard::PacketEnd {
            ptr,
            op: normalized_op,
        }),
        _ => None,
    };
    let make_context_buffer_guard = |ptr: VReg, normalized_op: BinOpKind| match normalized_op {
        BinOpKind::Le | BinOpKind::Lt | BinOpKind::Ge | BinOpKind::Gt => {
            Some(Guard::ContextBufferEnd {
                ptr,
                op: normalized_op,
            })
        }
        _ => None,
    };
    let packet_end_matches = |ptr_bounds: PtrBounds, end_reg: VReg| {
        let PtrOrigin::Packet(root) = ptr_bounds.origin() else {
            return false;
        };
        match state.ctx_field_source(root) {
            Some(CtxField::Data) => state.ctx_field_source(end_reg) == Some(&CtxField::DataEnd),
            Some(CtxField::DataMeta) => state.ctx_field_source(end_reg) == Some(&CtxField::Data),
            _ => false,
        }
    };

    match (lhs_ty, rhs_ty) {
        (
            VerifierType::Ptr {
                space: AddressSpace::Packet,
                bounds: Some(bounds),
                ..
            },
            VerifierType::Ptr {
                space: AddressSpace::Packet,
                ..
            },
        ) if matches!(bounds.origin(), PtrOrigin::Packet(_)) && packet_end_matches(bounds, rhs) => {
            make_packet_guard(lhs, op)
        }
        (
            VerifierType::Ptr {
                space: AddressSpace::Packet,
                ..
            },
            VerifierType::Ptr {
                space: AddressSpace::Packet,
                bounds: Some(bounds),
                ..
            },
        ) if matches!(bounds.origin(), PtrOrigin::Packet(_)) && packet_end_matches(bounds, lhs) => {
            make_packet_guard(rhs, swap_compare(op)?)
        }
        (
            VerifierType::Ptr {
                space: AddressSpace::Kernel,
                bounds: Some(bounds),
                ..
            },
            VerifierType::Ptr {
                space: AddressSpace::Kernel,
                ..
            },
        ) if matches!(bounds.origin(), PtrOrigin::ContextBuffer(_))
            && state.ctx_field_source(rhs) == Some(&CtxField::SockoptOptvalEnd) =>
        {
            let PtrOrigin::ContextBuffer(root) = bounds.origin() else {
                unreachable!();
            };
            if state.ctx_field_source(root) != Some(&CtxField::SockoptOptval) {
                return None;
            }
            make_context_buffer_guard(lhs, op)
        }
        (
            VerifierType::Ptr {
                space: AddressSpace::Kernel,
                ..
            },
            VerifierType::Ptr {
                space: AddressSpace::Kernel,
                bounds: Some(bounds),
                ..
            },
        ) if matches!(bounds.origin(), PtrOrigin::ContextBuffer(_))
            && state.ctx_field_source(lhs) == Some(&CtxField::SockoptOptvalEnd) =>
        {
            let PtrOrigin::ContextBuffer(root) = bounds.origin() else {
                unreachable!();
            };
            if state.ctx_field_source(root) != Some(&CtxField::SockoptOptval) {
                return None;
            }
            make_context_buffer_guard(rhs, swap_compare(op)?)
        }
        _ => None,
    }
}

pub(in crate::compiler::verifier_types) fn swap_compare(op: BinOpKind) -> Option<BinOpKind> {
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

pub(in crate::compiler::verifier_types) fn negate_compare(op: BinOpKind) -> Option<BinOpKind> {
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

pub(in crate::compiler::verifier_types) fn invert_guard(guard: Guard) -> Option<Guard> {
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
        Guard::PacketEnd { ptr, op } => Some(Guard::PacketEnd {
            ptr,
            op: negate_compare(op)?,
        }),
        Guard::ContextBufferEnd { ptr, op } => Some(Guard::ContextBufferEnd {
            ptr,
            op: negate_compare(op)?,
        }),
    }
}

pub(in crate::compiler::verifier_types) fn effective_branch_compare(
    op: BinOpKind,
    take_true: bool,
) -> Option<BinOpKind> {
    if take_true {
        Some(op)
    } else {
        negate_compare(op)
    }
}
