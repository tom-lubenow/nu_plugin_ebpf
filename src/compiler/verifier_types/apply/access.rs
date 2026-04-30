use super::*;
use crate::compiler::mir::CtxStoreTarget;

fn scalar_value_range_for_type(types: &HashMap<VReg, MirType>, dst: VReg) -> ValueRange {
    types
        .get(&dst)
        .and_then(MirType::scalar_value_range)
        .map(|(min, max)| ValueRange::Known { min, max })
        .unwrap_or(ValueRange::Unknown)
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
    if let VerifierType::Ptr {
        space: AddressSpace::Kernel,
        bounds,
        ..
    } = state.get(ptr)
    {
        match bounds.map(|bounds| bounds.origin()) {
            Some(PtrOrigin::ContextBuffer(_) | PtrOrigin::KernelBtf(_)) => {}
            _ => errors.push(VerifierTypeError::new(
                "load on kernel pointers requires bounded context-buffer or trusted BTF provenance",
            )),
        }
    }
    check_ptr_access(
        ptr,
        "load",
        &[
            AddressSpace::Stack,
            AddressSpace::Map,
            AddressSpace::Packet,
            AddressSpace::Context,
            AddressSpace::Kernel,
        ],
        offset,
        access_size,
        state,
        errors,
    );
    let mut ty = types
        .get(&dst)
        .map(verifier_type_from_mir)
        .unwrap_or(VerifierType::Scalar);
    let trusted_btf_load = matches!(
        state.get(ptr),
        VerifierType::Ptr {
            space: AddressSpace::Kernel,
            bounds: Some(bounds),
            ..
        } if matches!(bounds.origin(), PtrOrigin::KernelBtf(_))
    );
    if trusted_btf_load
        && let VerifierType::Ptr {
            space: AddressSpace::Kernel,
            ringbuf_ref,
            kfunc_ref,
            ..
        } = ty
    {
        ty = VerifierType::Ptr {
            space: AddressSpace::Kernel,
            nullability: Nullability::NonNull,
            bounds: Some(PtrBounds::new(
                PtrOrigin::KernelBtf(dst),
                0,
                0,
                UNKNOWN_KERNEL_BTF_LIMIT,
            )),
            ringbuf_ref,
            kfunc_ref,
        };
    }
    state.set_with_range(dst, ty, scalar_value_range_for_type(types, dst));
}

pub(super) fn apply_store_inst(
    ptr: VReg,
    offset: i32,
    ty: &MirType,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let access_size = ty.size();
    if let VerifierType::Ptr {
        space: AddressSpace::Kernel,
        bounds,
        ..
    } = state.get(ptr)
    {
        match bounds.map(|bounds| bounds.origin()) {
            Some(PtrOrigin::ContextBuffer(_)) => {}
            _ => errors.push(VerifierTypeError::new(
                "store on kernel pointers requires bounded context-buffer provenance",
            )),
        }
    }
    check_ptr_access(
        ptr,
        "store",
        &[
            AddressSpace::Stack,
            AddressSpace::Map,
            AddressSpace::Packet,
            AddressSpace::Kernel,
        ],
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
    state.set_with_range(dst, dst_ty, scalar_value_range_for_type(types, dst));
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
    let bounds = slot_sizes
        .get(&buffer)
        .copied()
        .map(|limit| PtrBounds::new(PtrOrigin::Stack(buffer), 0, 0, limit));
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
    probe_ctx: Option<&ProbeContext>,
    types: &HashMap<VReg, MirType>,
    slot_sizes: &HashMap<StackSlotId, i64>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if let Some(ctx) = probe_ctx {
        if let Err(err) = ctx.validate_load_ctx_field(field) {
            errors.push(VerifierTypeError::new(err.to_string()));
        } else if let Some(guard) = ctx.ctx_field_load_guard(field) {
            if !state.proves_ctx_field_value_range(&guard.witness_field(), |value| {
                guard.allows_value(value)
            }) {
                errors.push(VerifierTypeError::new(guard.error(field)));
            }
        }
    }
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
        let bounds = slot_sizes
            .get(&slot)
            .copied()
            .map(|limit| PtrBounds::new(PtrOrigin::Stack(slot), 0, 0, limit));
        ty = VerifierType::Ptr {
            space: AddressSpace::Stack,
            nullability,
            bounds,
            ringbuf_ref: None,
            kfunc_ref: None,
        };
    }
    if matches!(field, CtxField::Data | CtxField::DataMeta) {
        match ty {
            VerifierType::Ptr {
                space: AddressSpace::Packet,
                nullability,
                bounds: None,
                ..
            } => {
                ty = VerifierType::Ptr {
                    space: AddressSpace::Packet,
                    nullability,
                    bounds: Some(PtrBounds::new(
                        PtrOrigin::Packet(dst),
                        0,
                        0,
                        UNKNOWN_PACKET_LIMIT,
                    )),
                    ringbuf_ref: None,
                    kfunc_ref: None,
                };
            }
            VerifierType::Ptr {
                space: AddressSpace::Packet,
                ..
            } => {}
            _ => {}
        }
    }
    if matches!(field, CtxField::SockoptOptval) {
        match ty {
            VerifierType::Ptr {
                space: AddressSpace::Kernel,
                nullability,
                bounds: None,
                ..
            } => {
                ty = VerifierType::Ptr {
                    space: AddressSpace::Kernel,
                    nullability,
                    bounds: Some(PtrBounds::new(
                        PtrOrigin::ContextBuffer(dst),
                        0,
                        0,
                        UNKNOWN_CONTEXT_BUFFER_LIMIT,
                    )),
                    ringbuf_ref: None,
                    kfunc_ref: None,
                };
            }
            VerifierType::Ptr {
                space: AddressSpace::Kernel,
                ..
            } => {}
            _ => {}
        }
    }
    if ProbeContext::resolve_ctx_field_pointer_is_non_null(probe_ctx, field)
        && let VerifierType::Ptr {
            space,
            bounds,
            ringbuf_ref,
            kfunc_ref,
            ..
        } = ty
    {
        ty = VerifierType::Ptr {
            space,
            nullability: Nullability::NonNull,
            bounds,
            ringbuf_ref,
            kfunc_ref,
        };
    }
    if ProbeContext::resolve_ctx_field_is_trusted_btf_kernel_pointer(probe_ctx, field)
        && let VerifierType::Ptr {
            space: AddressSpace::Kernel,
            ringbuf_ref,
            kfunc_ref,
            ..
        } = ty
    {
        ty = VerifierType::Ptr {
            space: AddressSpace::Kernel,
            nullability: Nullability::NonNull,
            bounds: Some(PtrBounds::new(
                PtrOrigin::KernelBtf(dst),
                0,
                0,
                UNKNOWN_KERNEL_BTF_LIMIT,
            )),
            ringbuf_ref,
            kfunc_ref,
        };
    }
    if ProbeContext::resolve_ctx_field_is_raw_context_pointer(probe_ctx, field)
        && let VerifierType::Ptr {
            space,
            bounds,
            ringbuf_ref,
            kfunc_ref,
            ..
        } = ty
    {
        ty = VerifierType::Ptr {
            space,
            nullability: Nullability::NonNull,
            bounds,
            ringbuf_ref,
            kfunc_ref,
        };
    }
    state.set_with_range(dst, ty, scalar_value_range_for_type(types, dst));
    state.set_ctx_field_source(dst, Some(field.clone()));
}

pub(super) fn apply_store_ctx_field_inst(
    target: &CtxStoreTarget,
    val: &MirValue,
    ty: &MirType,
    probe_ctx: Option<&ProbeContext>,
    state: &VerifierState,
    slot_sizes: &HashMap<StackSlotId, i64>,
    errors: &mut Vec<VerifierTypeError>,
) {
    if *ty != target.value_type() {
        errors.push(VerifierTypeError::new(target.type_error_message(ty)));
    }
    match probe_ctx {
        Some(ctx) => {
            if let Err(err) = ctx.validate_ctx_store_target(target) {
                errors.push(VerifierTypeError::new(err.to_string()));
            }
        }
        None => errors.push(VerifierTypeError::new(target.missing_context_error())),
    }
    let val_ty = value_type(val, state, slot_sizes);
    if !matches!(
        val_ty,
        VerifierType::Scalar | VerifierType::Bool | VerifierType::Unknown
    ) {
        errors.push(VerifierTypeError::new(format!(
            "writable context fields require an integer-compatible scalar value, got {:?}",
            val_ty
        )));
    }
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
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let needs_ptr = types.get(&data).is_some_and(|ty| {
        matches!(
            ty,
            MirType::Ptr { .. } | MirType::Array { .. } | MirType::Struct { .. }
        )
    });
    if size <= 8 && !needs_ptr {
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
        let value_ty = types.get(&field.value);
        let value_is_ptr_like = matches!(
            value_ty,
            Some(MirType::Array { .. } | MirType::Ptr { .. } | MirType::Struct { .. })
        );
        if mir_requires_pointer_value(&field.ty) || value_is_ptr_like {
            check_ptr_access(
                field.value,
                "emit record",
                &[AddressSpace::Stack, AddressSpace::Map],
                0,
                record_pointer_access_size(&field.ty, value_ty),
                state,
                errors,
            );
        }
    }
}

fn mir_requires_pointer_value(ty: &MirType) -> bool {
    matches!(ty, MirType::Array { .. } | MirType::Struct { .. }) || ty.size() > 8
}

fn record_pointer_access_size(field_ty: &MirType, value_ty: Option<&MirType>) -> usize {
    match value_ty {
        Some(MirType::Ptr { pointee, .. })
            if matches!(
                pointee.as_ref(),
                MirType::Array { .. } | MirType::Struct { .. }
            ) =>
        {
            pointee.size().max(1)
        }
        _ => field_ty.size().max(1),
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

pub(super) fn apply_histogram_inst(
    value: VReg,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    match state.get(value) {
        VerifierType::Scalar | VerifierType::Bool => {}
        other => errors.push(VerifierTypeError::new(format!(
            "histogram expects scalar, got {:?}",
            other
        ))),
    }
}

pub(super) fn apply_record_store_inst(
    val: &MirValue,
    ty: &MirType,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if !mir_requires_pointer_value(ty) {
        return;
    }
    match val {
        MirValue::VReg(vreg) => {
            check_ptr_access(
                *vreg,
                "record store",
                &[AddressSpace::Stack, AddressSpace::Map],
                0,
                record_pointer_access_size(ty, types.get(vreg)),
                state,
                errors,
            );
        }
        MirValue::StackSlot(_) => {}
        MirValue::Const(_) => {
            errors.push(VerifierTypeError::new(
                "record store requires pointer value".to_string(),
            ));
        }
    }
}
