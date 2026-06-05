use super::*;

pub(super) fn apply_map_lookup_inst(
    dst: VReg,
    map: &MapRef,
    key: VReg,
    types: &HashMap<VReg, MirType>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if !map.kind.supports_generic_map_op(MapOpKind::Lookup) {
        errors.push(VerifierTypeError::new(
            map.kind.generic_map_op_error(MapOpKind::Lookup, &map.name),
        ));
    }
    check_map_operand_scalar_size(key, "map key", types, errors);
    check_map_key_access(map, key, types, state, errors);

    if map.kind.is_map_in_map() {
        state.set(
            dst,
            VerifierType::Ptr {
                space: AddressSpace::Kernel,
                nullability: Nullability::MaybeNull,
                bounds: None,
                ringbuf_ref: None,
                kfunc_ref: None,
            },
        );
        return;
    }

    let limit = match map_value_limit(map) {
        Some(limit) => Some(limit),
        None => map_value_limit_from_dst_type(types.get(&dst), "map lookup value type", errors),
    };
    let bounds = limit.map(|limit| PtrBounds::new(PtrOrigin::Map(dst), 0, 0, limit));
    state.set(
        dst,
        VerifierType::Ptr {
            space: AddressSpace::Map,
            nullability: Nullability::MaybeNull,
            bounds,
            ringbuf_ref: None,
            kfunc_ref: None,
        },
    );
    state.set_map_lookup_source(dst, map, key);
}

pub(super) fn apply_map_lookup_dynamic_inst(
    dst: VReg,
    map_ptr: VReg,
    inner_map: &MapRef,
    key: VReg,
    types: &HashMap<VReg, MirType>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if !inner_map.kind.supports_generic_map_op(MapOpKind::Lookup) {
        errors.push(VerifierTypeError::new(
            inner_map
                .kind
                .generic_map_op_error(MapOpKind::Lookup, &inner_map.name),
        ));
    }
    let _ = require_ptr_with_space(
        map_ptr,
        "dynamic map lookup",
        &[AddressSpace::Kernel],
        state,
        errors,
    );
    check_map_operand_scalar_size(key, "map key", types, errors);
    check_map_key_access(inner_map, key, types, state, errors);

    let limit = match map_value_limit(inner_map) {
        Some(limit) => Some(limit),
        None => {
            map_value_limit_from_dst_type(types.get(&dst), "dynamic map lookup value type", errors)
        }
    };
    let bounds = limit.map(|limit| PtrBounds::new(PtrOrigin::Map(dst), 0, 0, limit));
    state.set(
        dst,
        VerifierType::Ptr {
            space: AddressSpace::Map,
            nullability: Nullability::MaybeNull,
            bounds,
            ringbuf_ref: None,
            kfunc_ref: None,
        },
    );
}

pub(super) fn apply_global_load_inst(
    dst: VReg,
    ty: &MirType,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let bounds = verifier_limit_from_size(ty.size(), "global value type", errors)
        .map(|limit| PtrBounds::new(PtrOrigin::Map(dst), 0, 0, limit));
    state.set(
        dst,
        VerifierType::Ptr {
            space: AddressSpace::Map,
            nullability: Nullability::NonNull,
            bounds,
            ringbuf_ref: None,
            kfunc_ref: None,
        },
    );
}

pub(super) fn apply_map_update_inst(
    map: &MapRef,
    key: VReg,
    val: VReg,
    _flags: u64,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if !map.kind.supports_generic_map_op(MapOpKind::Update) {
        errors.push(VerifierTypeError::new(
            map.kind.generic_map_op_error(MapOpKind::Update, &map.name),
        ));
    }
    check_map_operand_scalar_size(key, "map key", types, errors);
    check_map_operand_scalar_size(val, "map value", types, errors);
    check_map_key_access(map, key, types, state, errors);
    check_map_value_access(val, types, state, errors);
}

pub(super) fn apply_map_update_dynamic_inst(
    map_ptr: VReg,
    inner_map: &MapRef,
    key: VReg,
    val: VReg,
    _flags: u64,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if !inner_map.kind.supports_generic_map_op(MapOpKind::Update) {
        errors.push(VerifierTypeError::new(
            inner_map
                .kind
                .generic_map_op_error(MapOpKind::Update, &inner_map.name),
        ));
    }
    let _ = require_ptr_with_space(
        map_ptr,
        "dynamic map update",
        &[AddressSpace::Kernel],
        state,
        errors,
    );
    check_map_operand_scalar_size(key, "map key", types, errors);
    check_map_operand_scalar_size(val, "map value", types, errors);
    check_map_key_access(inner_map, key, types, state, errors);
    check_map_value_access(val, types, state, errors);
}

pub(super) fn apply_map_delete_inst(
    map: &MapRef,
    key: VReg,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if !map.kind.supports_generic_map_op(MapOpKind::Delete) {
        errors.push(VerifierTypeError::new(
            map.kind.generic_map_op_error(MapOpKind::Delete, &map.name),
        ));
    }
    check_map_operand_scalar_size(key, "map key", types, errors);
    check_map_key_access(map, key, types, state, errors);
}

pub(super) fn apply_map_delete_dynamic_inst(
    map_ptr: VReg,
    inner_map: &MapRef,
    key: VReg,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if !inner_map.kind.supports_generic_map_op(MapOpKind::Delete) {
        errors.push(VerifierTypeError::new(
            inner_map
                .kind
                .generic_map_op_error(MapOpKind::Delete, &inner_map.name),
        ));
    }
    let _ = require_ptr_with_space(
        map_ptr,
        "dynamic map delete",
        &[AddressSpace::Kernel],
        state,
        errors,
    );
    check_map_operand_scalar_size(key, "map key", types, errors);
    check_map_key_access(inner_map, key, types, state, errors);
}

pub(super) fn apply_map_push_inst(
    map: &MapRef,
    val: VReg,
    _flags: u64,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if !map.kind.supports_generic_map_op(MapOpKind::Push) {
        errors.push(VerifierTypeError::new(
            map.kind.generic_map_op_error(MapOpKind::Push, &map.name),
        ));
    }
    check_map_operand_scalar_size(val, "map value", types, errors);
    check_map_value_access(val, types, state, errors);
}

fn check_map_key_access(
    map: &MapRef,
    key: VReg,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if map.name == STRING_COUNTER_MAP_NAME {
        check_ptr_access(
            key,
            "map key",
            &[AddressSpace::Stack, AddressSpace::Map],
            0,
            16,
            state,
            errors,
        );
        return;
    }

    if map.name == BYTES_COUNTER_MAP_NAME {
        let access_size = match types.get(&key) {
            Some(MirType::Ptr { pointee, .. }) => pointee.size().max(1),
            Some(ty) => ty.size().max(1),
            None => 1,
        };
        check_ptr_access(
            key,
            "map key",
            &[AddressSpace::Stack, AddressSpace::Map],
            0,
            access_size,
            state,
            errors,
        );
        return;
    }

    if let VerifierType::Ptr { .. } = state.get(key) {
        check_ptr_access(
            key,
            "map key",
            &[AddressSpace::Stack, AddressSpace::Map],
            0,
            map_operand_access_size(key, types),
            state,
            errors,
        );
    }
}

fn check_map_value_access(
    val: VReg,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if let VerifierType::Ptr { .. } = state.get(val) {
        check_ptr_access(
            val,
            "map value",
            &[AddressSpace::Stack, AddressSpace::Map],
            0,
            map_operand_access_size(val, types),
            state,
            errors,
        );
    }
}

fn map_operand_access_size(vreg: VReg, types: &HashMap<VReg, MirType>) -> usize {
    match types.get(&vreg) {
        Some(MirType::Ptr { pointee, .. }) => pointee.size().max(1),
        Some(ty) => ty.size().max(1),
        None => 1,
    }
}
