use super::*;
use crate::compiler::mir::UnaryOpKind;

mod calls;
mod maps;

use calls::*;
use maps::*;

pub(super) fn apply_inst(
    inst: &MirInst,
    types: &HashMap<VReg, MirType>,
    slot_sizes: &HashMap<StackSlotId, i64>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    match inst {
        MirInst::Copy { dst, src } => {
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
            state.set_with_range(*dst, ty, range);
            state.set_ctx_field_source(*dst, src_ctx_field);
            if src_non_zero {
                state.set_non_zero(*dst, true);
            }
            for excluded in src_not_equal {
                state.set_not_equal_const(*dst, excluded);
            }
            if let Some(guard) = src_guard {
                state.set_guard(*dst, guard);
            }
        }
        MirInst::Load {
            dst, ptr, offset, ..
        } => {
            apply_load_inst(*dst, *ptr, *offset, types, state, errors);
        }
        MirInst::Store {
            ptr, offset, ty, ..
        } => {
            apply_store_inst(*ptr, *offset, ty, state, errors);
        }
        MirInst::LoadSlot {
            dst,
            slot,
            offset,
            ty,
        } => {
            apply_load_slot_inst(*dst, *slot, *offset, ty, types, slot_sizes, state, errors);
        }
        MirInst::StoreSlot {
            slot, offset, ty, ..
        } => {
            apply_store_slot_inst(*slot, *offset, ty, slot_sizes, errors);
        }
        MirInst::BinOp { dst, op, lhs, rhs } => {
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
                    *dst,
                    VerifierType::Bool,
                    ValueRange::Known { min: 0, max: 1 },
                );
                if let Some(guard) = guard_from_compare(*op, lhs, rhs, state) {
                    state.set_guard(*dst, guard);
                }
            } else {
                if let Some(ty) = pointer_arith_result(*op, lhs, rhs, state, slot_sizes) {
                    state.set(*dst, ty);
                } else {
                    let range = range_for_binop(*op, lhs, rhs, state);
                    state.set_with_range(*dst, VerifierType::Scalar, range);
                }
            }
        }
        MirInst::UnaryOp { op, .. } => {
            let ty = match op {
                UnaryOpKind::Not => VerifierType::Bool,
                _ => VerifierType::Scalar,
            };
            if let Some(dst) = inst.def() {
                let guard = if matches!(op, UnaryOpKind::Not) {
                    if let MirInst::UnaryOp { src, .. } = inst {
                        if let MirValue::VReg(src_reg) = src {
                            state.guard(*src_reg).and_then(invert_guard)
                        } else {
                            None
                        }
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
        }
        MirInst::CallHelper { dst, helper, args } => {
            apply_call_helper_inst(*dst, *helper, args, types, slot_sizes, state, errors);
        }
        MirInst::CallKfunc {
            dst, kfunc, args, ..
        } => {
            apply_call_kfunc_inst(*dst, kfunc, args, types, state, errors);
        }
        MirInst::CallSubfn { dst, args, .. } => {
            apply_call_subfn_inst(*dst, args, types, state, errors);
        }
        MirInst::StrCmp { dst, .. }
        | MirInst::StopTimer { dst, .. }
        | MirInst::LoopHeader { counter: dst, .. }
        | MirInst::Phi { dst, .. } => {
            let phi_guard = if let MirInst::Phi { args, .. } = inst {
                let mut merged: Option<Option<Guard>> = None;
                for (_, reg) in args {
                    let next = state.guard(*reg);
                    merged = Some(match merged {
                        None => next,
                        Some(existing) if existing == next => existing,
                        _ => None,
                    });
                    if matches!(merged, Some(None)) {
                        break;
                    }
                }
                merged.flatten()
            } else {
                None
            };
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            let range = if let MirInst::Phi { args, .. } = inst {
                range_for_phi(args, state)
            } else {
                ValueRange::Unknown
            };
            let ty = if let MirInst::Phi { args, .. } = inst {
                ptr_type_for_phi(args, state).unwrap_or(ty)
            } else {
                ty
            };
            state.set_with_range(*dst, ty, range);
            if let Some(guard) = phi_guard {
                state.set_guard(*dst, guard);
            }
        }
        MirInst::MapLookup { dst, map, key } => {
            apply_map_lookup_inst(*dst, map, *key, types, state, errors);
        }
        MirInst::ListNew { dst, buffer, .. } => {
            apply_list_new_inst(*dst, *buffer, slot_sizes, state);
        }
        MirInst::ListLen { dst, list } => {
            apply_list_len_inst(*dst, *list, types, state, errors);
        }
        MirInst::ListGet { dst, list, .. } => {
            apply_list_get_inst(*dst, *list, types, state, errors);
        }
        MirInst::LoadCtxField { dst, field, slot } => {
            apply_load_ctx_field_inst(*dst, field, *slot, types, slot_sizes, state);
        }
        MirInst::ReadStr {
            ptr, user_space, ..
        } => {
            apply_read_str_inst(*ptr, *user_space, state, errors);
        }
        MirInst::EmitEvent { data, size } => {
            apply_emit_event_inst(*data, *size, state, errors);
        }
        MirInst::EmitRecord { fields } => {
            apply_emit_record_inst(fields, types, state, errors);
        }
        MirInst::MapUpdate {
            map,
            key,
            val,
            flags,
        } => {
            apply_map_update_inst(map, *key, *val, *flags, types, state, errors);
        }
        MirInst::MapDelete { map, key } => {
            apply_map_delete_inst(map, *key, types, state, errors);
        }
        MirInst::Histogram { .. }
        | MirInst::StartTimer
        | MirInst::TailCall { .. }
        | MirInst::Jump { .. }
        | MirInst::Branch { .. }
        | MirInst::Return { .. }
        | MirInst::LoopBack { .. }
        | MirInst::Placeholder => {}
        MirInst::ListPush { list, .. } => {
            apply_list_push_inst(*list, state, errors);
        }
        MirInst::StringAppend { dst_len, .. } | MirInst::IntToString { dst_len, .. } => {
            apply_string_len_write_inst(*dst_len, state, errors);
        }
        MirInst::RecordStore { val, ty, .. } => {
            apply_record_store_inst(val, ty, state, errors);
        }
    }
}

pub(super) fn apply_load_inst(
    dst: VReg,
    ptr: VReg,
    offset: i32,
    types: &HashMap<VReg, MirType>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let access_size = types.get(&dst).map(|ty| ty.size()).unwrap_or(8);
    check_ptr_access(
        ptr,
        "load",
        &[AddressSpace::Stack, AddressSpace::Map],
        offset,
        access_size,
        state,
        errors,
    );
    let ty = types
        .get(&dst)
        .map(verifier_type_from_mir)
        .unwrap_or(VerifierType::Scalar);
    state.set(dst, ty);
}

pub(super) fn apply_store_inst(
    ptr: VReg,
    offset: i32,
    ty: &MirType,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let access_size = ty.size();
    check_ptr_access(
        ptr,
        "store",
        &[AddressSpace::Stack, AddressSpace::Map],
        offset,
        access_size,
        state,
        errors,
    );
}

pub(super) fn apply_load_slot_inst(
    dst: VReg,
    slot: StackSlotId,
    offset: i32,
    ty: &MirType,
    types: &HashMap<VReg, MirType>,
    slot_sizes: &HashMap<StackSlotId, i64>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    check_slot_access(slot, offset, ty.size(), slot_sizes, "load slot", errors);
    let dst_ty = types
        .get(&dst)
        .map(verifier_type_from_mir)
        .unwrap_or(VerifierType::Scalar);
    state.set(dst, dst_ty);
}

pub(super) fn apply_store_slot_inst(
    slot: StackSlotId,
    offset: i32,
    ty: &MirType,
    slot_sizes: &HashMap<StackSlotId, i64>,
    errors: &mut Vec<VerifierTypeError>,
) {
    check_slot_access(slot, offset, ty.size(), slot_sizes, "store slot", errors);
}

pub(super) fn apply_list_new_inst(
    dst: VReg,
    buffer: StackSlotId,
    slot_sizes: &HashMap<StackSlotId, i64>,
    state: &mut VerifierState,
) {
    let bounds = slot_sizes.get(&buffer).copied().map(|limit| PtrBounds {
        origin: PtrOrigin::Stack(buffer),
        min: 0,
        max: 0,
        limit,
    });
    state.set(
        dst,
        VerifierType::Ptr {
            space: AddressSpace::Stack,
            nullability: Nullability::NonNull,
            bounds,
            ringbuf_ref: None,
            kfunc_ref: None,
        },
    );
}

pub(super) fn apply_list_len_inst(
    dst: VReg,
    list: VReg,
    types: &HashMap<VReg, MirType>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    require_ptr_with_space(list, "list", &[AddressSpace::Stack], state, errors);
    let ty = types
        .get(&dst)
        .map(verifier_type_from_mir)
        .unwrap_or(VerifierType::Scalar);
    state.set(dst, ty);
}

pub(super) fn apply_list_get_inst(
    dst: VReg,
    list: VReg,
    types: &HashMap<VReg, MirType>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    require_ptr_with_space(list, "list", &[AddressSpace::Stack], state, errors);
    let ty = types
        .get(&dst)
        .map(verifier_type_from_mir)
        .unwrap_or(VerifierType::Scalar);
    state.set(dst, ty);
}

pub(super) fn apply_load_ctx_field_inst(
    dst: VReg,
    field: &CtxField,
    slot: Option<StackSlotId>,
    types: &HashMap<VReg, MirType>,
    slot_sizes: &HashMap<StackSlotId, i64>,
    state: &mut VerifierState,
) {
    let mut ty = state.find_ctx_field_type(field).unwrap_or_else(|| {
        types
            .get(&dst)
            .map(verifier_type_from_mir)
            .unwrap_or(VerifierType::Scalar)
    });
    if let (
        VerifierType::Ptr {
            space: AddressSpace::Stack,
            nullability,
            ..
        },
        Some(slot),
    ) = (ty, slot)
    {
        let bounds = slot_sizes.get(&slot).copied().map(|limit| PtrBounds {
            origin: PtrOrigin::Stack(slot),
            min: 0,
            max: 0,
            limit,
        });
        ty = VerifierType::Ptr {
            space: AddressSpace::Stack,
            nullability,
            bounds,
            ringbuf_ref: None,
            kfunc_ref: None,
        };
    }
    state.set(dst, ty);
    state.set_ctx_field_source(dst, Some(field.clone()));
}

pub(super) fn apply_read_str_inst(
    ptr: VReg,
    user_space: bool,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let allowed = if user_space {
        &[AddressSpace::User][..]
    } else {
        &[AddressSpace::Kernel, AddressSpace::Map, AddressSpace::Stack][..]
    };
    require_ptr_with_space(ptr, "read_str", allowed, state, errors);
}

pub(super) fn apply_emit_event_inst(
    data: VReg,
    size: usize,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if size <= 8 {
        return;
    }
    require_ptr_with_space(
        data,
        "emit",
        &[AddressSpace::Stack, AddressSpace::Map],
        state,
        errors,
    );
}

pub(super) fn apply_emit_record_inst(
    fields: &[crate::compiler::mir::RecordFieldDef],
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    for field in fields {
        if let Some(MirType::Array { .. }) | Some(MirType::Ptr { .. }) = types.get(&field.value) {
            require_ptr_with_space(
                field.value,
                "emit record",
                &[AddressSpace::Stack, AddressSpace::Map],
                state,
                errors,
            );
        }
    }
}

pub(super) fn apply_list_push_inst(
    list: VReg,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    require_ptr_with_space(list, "list", &[AddressSpace::Stack], state, errors);
}

pub(super) fn apply_string_len_write_inst(
    dst_len: VReg,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let ty = state.get(dst_len);
    if matches!(ty, VerifierType::Uninit) {
        errors.push(VerifierTypeError::new(format!(
            "string length uses uninitialized v{}",
            dst_len.0
        )));
    }
}

pub(super) fn apply_record_store_inst(
    val: &MirValue,
    ty: &MirType,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if !matches!(ty, MirType::Array { .. } | MirType::Ptr { .. }) {
        return;
    }
    if let MirValue::VReg(vreg) = val {
        require_ptr_with_space(
            *vreg,
            "record store",
            &[AddressSpace::Stack, AddressSpace::Map],
            state,
            errors,
        );
    }
}

pub(super) fn check_uses_initialized(
    inst: &MirInst,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    for used in inst.uses() {
        if matches!(state.get(used), VerifierType::Uninit) {
            errors.push(VerifierTypeError::new(format!(
                "instruction uses uninitialized v{}",
                used.0
            )));
        }
    }
}

pub(super) fn pointer_arith_result(
    op: BinOpKind,
    lhs: &MirValue,
    rhs: &MirValue,
    state: &VerifierState,
    slot_sizes: &HashMap<StackSlotId, i64>,
) -> Option<VerifierType> {
    if !matches!(op, BinOpKind::Add | BinOpKind::Sub) {
        return None;
    }

    let lhs_ty = value_type(lhs, state, slot_sizes);
    let rhs_ty = value_type(rhs, state, slot_sizes);

    let (ptr_ty, offset, is_add) = match op {
        BinOpKind::Add => match (&lhs_ty, &rhs_ty) {
            (VerifierType::Ptr { .. }, VerifierType::Scalar | VerifierType::Bool) => {
                (lhs_ty, rhs, true)
            }
            (VerifierType::Scalar | VerifierType::Bool, VerifierType::Ptr { .. }) => {
                (rhs_ty, lhs, true)
            }
            _ => return None,
        },
        BinOpKind::Sub => match (&lhs_ty, &rhs_ty) {
            (VerifierType::Ptr { .. }, VerifierType::Scalar | VerifierType::Bool) => {
                (lhs_ty, rhs, false)
            }
            _ => return None,
        },
        _ => return None,
    };

    let offset_range = value_range(offset, state);

    if let VerifierType::Ptr {
        space,
        nullability,
        bounds,
        ringbuf_ref,
        kfunc_ref,
    } = ptr_ty
    {
        let bounds = match (bounds, offset_range) {
            (Some(bounds), ValueRange::Known { min, max }) => {
                let (min_delta, max_delta) = if is_add { (min, max) } else { (-max, -min) };
                Some(PtrBounds {
                    origin: bounds.origin,
                    min: bounds.min.saturating_add(min_delta),
                    max: bounds.max.saturating_add(max_delta),
                    limit: bounds.limit,
                })
            }
            _ => None,
        };
        return Some(VerifierType::Ptr {
            space,
            nullability,
            bounds,
            ringbuf_ref,
            kfunc_ref,
        });
    }

    None
}
