use super::*;

pub(super) fn apply_map_lookup_inst(
    dst: VReg,
    map: &MapRef,
    key: VReg,
    types: &HashMap<VReg, MirType>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if !supports_generic_map_kind(map.kind) {
        errors.push(VerifierTypeError::new(format!(
            "map operations do not support map kind {:?} for '{}'",
            map.kind, map.name
        )));
    }
    check_map_operand_scalar_size(key, "map key", types, errors);
    check_map_key_access(map, key, types, state, errors);

    let bounds = map_value_limit(map)
        .or_else(|| map_value_limit_from_dst_type(types.get(&dst)))
        .map(|limit| PtrBounds::new(PtrOrigin::Map, 0, 0, limit));
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

pub(super) fn apply_global_load_inst(dst: VReg, ty: &MirType, state: &mut VerifierState) {
    let bounds = if ty.size() == 0 {
        None
    } else {
        Some(PtrBounds::new(
            PtrOrigin::Map,
            0,
            0,
            ty.size().saturating_sub(1) as i64,
        ))
    };
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
    flags: u64,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if !supports_generic_map_kind(map.kind) {
        errors.push(VerifierTypeError::new(format!(
            "map operations do not support map kind {:?} for '{}'",
            map.kind, map.name
        )));
    }
    if flags > i32::MAX as u64 {
        errors.push(VerifierTypeError::new(format!(
            "map update flags {} exceed supported 32-bit immediate range",
            flags
        )));
    }
    check_map_operand_scalar_size(key, "map key", types, errors);
    check_map_operand_scalar_size(val, "map value", types, errors);
    check_map_key_access(map, key, types, state, errors);
}

pub(super) fn apply_map_delete_inst(
    map: &MapRef,
    key: VReg,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    if !supports_generic_map_kind(map.kind) {
        errors.push(VerifierTypeError::new(format!(
            "map operations do not support map kind {:?} for '{}'",
            map.kind, map.name
        )));
    } else if matches!(map.kind, MapKind::Array | MapKind::PerCpuArray) {
        errors.push(VerifierTypeError::new(format!(
            "map delete is not supported for array map kind {:?} ('{}')",
            map.kind, map.name
        )));
    }
    check_map_operand_scalar_size(key, "map key", types, errors);
    check_map_key_access(map, key, types, state, errors);
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
        require_ptr_with_space(
            key,
            "map key",
            &[AddressSpace::Stack, AddressSpace::Map],
            state,
            errors,
        );
    }
}
