use super::*;
use crate::compiler::mir::UnaryOpKind;

pub(super) fn apply_copy_inst(
    dst: VReg,
    src: &MirValue,
    types: &HashMap<VReg, MirType>,
    slot_sizes: &HashMap<StackSlotId, i64>,
    state: &mut VerifierState,
) {
    let ty = match src {
        MirValue::Const(0) => typed_null_copy_type(dst, types, state)
            .unwrap_or_else(|| value_type(src, state, slot_sizes)),
        _ => value_type(src, state, slot_sizes),
    };
    let range = value_range(src, state);
    let src_ctx_field = match src {
        MirValue::VReg(vreg) => state.ctx_field_source(*vreg).cloned(),
        _ => None,
    };
    let src_map_fd = match src {
        MirValue::VReg(vreg) => state.map_fd_source(*vreg).cloned(),
        _ => None,
    };
    let src_map_value_source = match src {
        MirValue::VReg(vreg) => state.map_value_source(*vreg).cloned(),
        _ => None,
    };
    let src_map_value_ambiguous = match src {
        MirValue::VReg(vreg) => state.map_value_source_is_ambiguous(*vreg),
        _ => false,
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
    let src_released_kfunc_ref =
        matches!(src, MirValue::VReg(vreg) if state.is_released_kfunc_ref(*vreg));
    let src_scalar_alias = match src {
        MirValue::VReg(vreg) if matches!(ty, VerifierType::Scalar | VerifierType::Bool) => {
            Some(*vreg)
        }
        _ => None,
    };
    state.set_with_range(dst, ty, range);
    if let Some(src_vreg) = src_scalar_alias {
        state.set_scalar_alias(dst, src_vreg);
    }
    if src_released_kfunc_ref {
        state.mark_released_kfunc_ref(dst);
        return;
    }
    state.set_ctx_field_source(dst, src_ctx_field);
    if let Some(map) = src_map_fd {
        state.set_map_fd_source(dst, &map);
    }
    if src_map_value_ambiguous {
        state.set_ambiguous_map_lookup_source(dst);
    } else if let Some(source) = src_map_value_source {
        state.set_map_lookup_source(dst, &source.map, source.key);
    }
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

pub(super) fn apply_phi_edge_inst(
    dst: VReg,
    src: VReg,
    types: &HashMap<VReg, MirType>,
    state: &mut VerifierState,
) {
    let src_ty = state.get(src);
    let ty =
        phi_edge_type_with_null_hint(src_ty, state.get_range(src), dst, types).unwrap_or(src_ty);
    let range = state.get_range(src);
    let src_ctx_field = state.ctx_field_source(src).cloned();
    let src_map_fd = state.map_fd_source(src).cloned();
    let src_map_value_source = state.map_value_source(src).cloned();
    let src_map_value_ambiguous = state.map_value_source_is_ambiguous(src);
    let src_guard = state.guard(src);
    let src_non_zero = state.is_non_zero(src);
    let src_not_equal = state.not_equal_consts(src).to_vec();
    let src_released_kfunc_ref = state.is_released_kfunc_ref(src);
    let src_scalar_alias = matches!(ty, VerifierType::Scalar | VerifierType::Bool).then_some(src);

    state.set_with_range(dst, ty, range);
    if let Some(src_vreg) = src_scalar_alias {
        state.set_scalar_alias(dst, src_vreg);
    }
    if src_released_kfunc_ref {
        state.mark_released_kfunc_ref(dst);
        return;
    }
    state.set_ctx_field_source(dst, src_ctx_field);
    if let Some(map) = src_map_fd {
        state.set_map_fd_source(dst, &map);
    }
    if src_map_value_ambiguous {
        state.set_ambiguous_map_lookup_source(dst);
    } else if let Some(source) = src_map_value_source {
        state.set_map_lookup_source(dst, &source.map, source.key);
    }
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

fn typed_null_copy_type(
    dst: VReg,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
) -> Option<VerifierType> {
    match types.get(&dst).map(verifier_type_from_mir) {
        Some(VerifierType::Ptr { space, .. }) => Some(VerifierType::Ptr {
            space,
            nullability: Nullability::Null,
            bounds: None,
            ringbuf_ref: None,
            kfunc_ref: None,
        }),
        _ => match state.get(dst) {
            VerifierType::Ptr { space, .. } => Some(VerifierType::Ptr {
                space,
                nullability: Nullability::Null,
                bounds: None,
                ringbuf_ref: None,
                kfunc_ref: None,
            }),
            _ => None,
        },
    }
}

fn phi_edge_type_with_null_hint(
    src_ty: VerifierType,
    src_range: ValueRange,
    dst: VReg,
    types: &HashMap<VReg, MirType>,
) -> Option<VerifierType> {
    if !matches!(src_ty, VerifierType::Scalar | VerifierType::Bool)
        || !matches!(src_range, ValueRange::Known { min: 0, max: 0 })
    {
        return None;
    }
    let VerifierType::Ptr { space, .. } = types
        .get(&dst)
        .map(verifier_type_from_mir)
        .unwrap_or(VerifierType::Unknown)
    else {
        return None;
    };
    Some(VerifierType::Ptr {
        space,
        nullability: Nullability::Null,
        bounds: None,
        ringbuf_ref: None,
        kfunc_ref: None,
    })
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

    if matches!(op, BinOpKind::Add | BinOpKind::Sub)
        && (released_kfunc_ref_value(lhs, state) || released_kfunc_ref_value(rhs, state))
    {
        state.mark_released_kfunc_ref(dst);
        return;
    }

    let range = range_for_binop(op, lhs, rhs, state);
    state.set_with_range(dst, VerifierType::Scalar, range);
    if let Some(src) = scalar_identity_source(op, lhs, rhs, state, slot_sizes) {
        state.set_scalar_alias(dst, src);
    }
}

fn scalar_identity_source(
    op: BinOpKind,
    lhs: &MirValue,
    rhs: &MirValue,
    state: &VerifierState,
    slot_sizes: &HashMap<StackSlotId, i64>,
) -> Option<VReg> {
    let is_scalar = |reg| {
        matches!(
            value_type(&MirValue::VReg(reg), state, slot_sizes),
            VerifierType::Scalar | VerifierType::Bool
        )
    };
    match (op, lhs, rhs) {
        (BinOpKind::Add, MirValue::VReg(reg), MirValue::Const(0))
        | (BinOpKind::Add, MirValue::Const(0), MirValue::VReg(reg))
        | (BinOpKind::Sub, MirValue::VReg(reg), MirValue::Const(0))
            if is_scalar(*reg) =>
        {
            Some(*reg)
        }
        _ => None,
    }
}

fn released_kfunc_ref_value(value: &MirValue, state: &VerifierState) -> bool {
    matches!(value, MirValue::VReg(vreg) if state.is_released_kfunc_ref(*vreg))
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
            state
                .guard(*src_reg)
                .and_then(invert_guard)
                .or_else(|| match state.get(*src_reg) {
                    VerifierType::Ptr { .. } => Some(Guard::Ptr {
                        ptr: *src_reg,
                        true_is_non_null: false,
                    }),
                    VerifierType::Scalar | VerifierType::Bool => Some(Guard::NonZero {
                        reg: *src_reg,
                        true_is_non_zero: false,
                    }),
                    VerifierType::Uninit | VerifierType::Unknown | VerifierType::StalePacketPtr => {
                        None
                    }
                })
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

pub(super) fn apply_loop_header_inst(
    dst: VReg,
    start: i64,
    step: i64,
    limit: i64,
    types: &HashMap<VReg, MirType>,
    state: &mut VerifierState,
) {
    let ty = types
        .get(&dst)
        .map(verifier_type_from_mir)
        .unwrap_or(VerifierType::Scalar);
    let (min, max) = if step >= 0 {
        let max = if start < limit {
            limit.saturating_sub(1)
        } else {
            start
        };
        (start, max)
    } else {
        let min = if start > limit {
            limit.saturating_add(1)
        } else {
            start
        };
        (min, start)
    };
    state.set_with_range(dst, ty, ValueRange::Known { min, max });
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

    let ty = types
        .get(&dst)
        .map(verifier_type_from_mir)
        .unwrap_or(VerifierType::Scalar);
    let range = range_for_phi(args, state);
    let mut ty = ptr_type_for_phi_with_hint(args, state, ty).unwrap_or(ty);
    if let Some(Some(source)) = &merged_ctx_field {
        ty = ctx_field_phi_type(dst, ty, source);
    }
    let scalar_alias_root = scalar_alias_root_for_phi(args, state, ty);
    let released_kfunc_ref = args
        .iter()
        .any(|(_, reg)| state.is_released_kfunc_ref(*reg));
    let merged_map_value_source = map_value_source_for_phi(args, state);
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
    state.set_with_range(dst, ty, range);
    if let Some(root) = scalar_alias_root
        && root != dst
    {
        state.set_scalar_alias(dst, root);
    }
    if released_kfunc_ref {
        state.mark_released_kfunc_ref(dst);
        return;
    }
    if let Some(Some(map)) = merged_map_fd {
        state.set_map_fd_source(dst, &map);
    }
    match merged_map_value_source {
        PhiMapValueSource::None => {}
        PhiMapValueSource::Known(source) => {
            state.set_map_lookup_source(dst, &source.map, source.key);
        }
        PhiMapValueSource::Ambiguous => {
            state.set_ambiguous_map_lookup_source(dst);
        }
    }
    if let Some(Some(source)) = merged_ctx_field {
        state.set_ctx_field_source(dst, Some(source));
    }
    if let Some(guard) = phi_guard {
        state.set_guard(dst, guard);
    }
}

fn ptr_type_for_phi_with_hint(
    args: &[(BlockId, VReg)],
    state: &VerifierState,
    dst_ty: VerifierType,
) -> Option<VerifierType> {
    let dst_null_ptr = match dst_ty {
        VerifierType::Ptr { space, .. } => Some(VerifierType::Ptr {
            space,
            nullability: Nullability::Null,
            bounds: None,
            ringbuf_ref: None,
            kfunc_ref: None,
        }),
        _ => None,
    };
    let mut merged: Option<VerifierType> = None;
    for (_, vreg) in args {
        let ty = match state.get(*vreg) {
            ty @ VerifierType::Ptr { .. } => ty,
            VerifierType::Scalar | VerifierType::Bool
                if matches!(state.get_range(*vreg), ValueRange::Known { min: 0, max: 0 }) =>
            {
                dst_null_ptr?
            }
            _ => return None,
        };
        merged = Some(match merged {
            None => ty,
            Some(existing) => join_type(existing, ty),
        });
    }
    merged
}

fn scalar_alias_root_for_phi(
    args: &[(BlockId, VReg)],
    state: &VerifierState,
    ty: VerifierType,
) -> Option<VReg> {
    if !matches!(ty, VerifierType::Scalar | VerifierType::Bool) {
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

fn map_value_source_for_phi(args: &[(BlockId, VReg)], state: &VerifierState) -> PhiMapValueSource {
    let mut source: Option<MapLookupSource> = None;
    for (_, reg) in args {
        if state.map_value_source_is_ambiguous(*reg) {
            return PhiMapValueSource::Ambiguous;
        }
        let Some(next) = state.map_value_source(*reg).cloned() else {
            return PhiMapValueSource::None;
        };
        source = Some(match source {
            None => next,
            Some(existing)
                if existing.map == next.map
                    && state.map_lookup_keys_may_alias(existing.key, next.key) =>
            {
                existing
            }
            _ => return PhiMapValueSource::Ambiguous,
        });
    }
    source
        .map(PhiMapValueSource::Known)
        .unwrap_or(PhiMapValueSource::None)
}

enum PhiMapValueSource {
    None,
    Known(MapLookupSource),
    Ambiguous,
}

fn ctx_field_phi_type(dst: VReg, ty: VerifierType, field: &CtxField) -> VerifierType {
    let VerifierType::Ptr {
        space,
        nullability,
        bounds,
        ringbuf_ref,
        kfunc_ref,
    } = ty
    else {
        return ty;
    };

    let bounds =
        match (field, space, bounds) {
            (CtxField::Data | CtxField::DataMeta, AddressSpace::Packet, None) => Some(
                PtrBounds::new(PtrOrigin::Packet(dst), 0, 0, UNKNOWN_PACKET_LIMIT),
            ),
            (CtxField::SockoptOptval, AddressSpace::Kernel, None) => Some(PtrBounds::new(
                PtrOrigin::ContextBuffer(dst),
                0,
                0,
                UNKNOWN_CONTEXT_BUFFER_LIMIT,
            )),
            _ => bounds,
        };

    VerifierType::Ptr {
        space,
        nullability,
        bounds,
        ringbuf_ref,
        kfunc_ref,
    }
}
