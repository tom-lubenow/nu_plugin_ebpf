use super::*;

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
