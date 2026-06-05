use super::*;

pub(super) fn map_value_limit(map: &MapRef) -> Option<i64> {
    match map.name.as_str() {
        COUNTER_MAP_NAME
        | STRING_COUNTER_MAP_NAME
        | BYTES_COUNTER_MAP_NAME
        | HISTOGRAM_MAP_NAME
        | TIMESTAMP_MAP_NAME => Some(8 - 1),
        KSTACK_MAP_NAME | USTACK_MAP_NAME => Some((127 * 8) - 1),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct VerifierMapLayoutSpec {
    kind: MapKind,
    key_size: u32,
    value_size: u32,
    value_size_defaulted: bool,
}

pub(super) fn is_builtin_map_name(name: &str) -> bool {
    matches!(
        name,
        RINGBUF_MAP_NAME
            | COUNTER_MAP_NAME
            | STRING_COUNTER_MAP_NAME
            | BYTES_COUNTER_MAP_NAME
            | HISTOGRAM_MAP_NAME
            | TIMESTAMP_MAP_NAME
            | KSTACK_MAP_NAME
            | USTACK_MAP_NAME
    )
}

pub(super) fn is_counter_map_name(name: &str) -> bool {
    matches!(
        name,
        COUNTER_MAP_NAME | STRING_COUNTER_MAP_NAME | BYTES_COUNTER_MAP_NAME
    )
}

pub(super) fn check_counter_map_kind(
    map: &MapRef,
    seen: &mut HashMap<String, MapKind>,
    errors: &mut Vec<VerifierTypeError>,
) {
    if !is_counter_map_name(&map.name) {
        return;
    }
    if !map.kind.supports_builtin_counter_map() {
        errors.push(VerifierTypeError::new(format!(
            "map '{}' only supports hash/per-cpu-hash kinds, got {}",
            map.name, map.kind
        )));
        return;
    }
    if let Some(existing) = seen.get(&map.name) {
        if *existing != map.kind {
            errors.push(VerifierTypeError::new(format!(
                "map '{}' used with conflicting kinds: {} vs {}",
                map.name, existing, map.kind
            )));
        }
    } else {
        seen.insert(map.name.clone(), map.kind);
    }
}

pub(super) fn infer_map_operand_size(
    vreg: VReg,
    what: &str,
    types: &HashMap<VReg, MirType>,
    errors: &mut Vec<VerifierTypeError>,
) -> Option<usize> {
    match types.get(&vreg) {
        Some(MirType::Ptr { pointee, .. }) => Some(pointee.size().max(1)),
        Some(ty) => {
            let size = match ty.size() {
                0 => 8,
                n => n,
            };
            if size > 8 {
                errors.push(VerifierTypeError::new(format!(
                    "{what} v{} has size {} bytes and must be passed as a pointer",
                    vreg.0, size
                )));
                None
            } else {
                Some(size)
            }
        }
        None => Some(8),
    }
}

pub(super) fn infer_map_lookup_value_size(
    dst: VReg,
    map: &MapRef,
    types: &HashMap<VReg, MirType>,
    generic_map_value_types: &HashMap<MapRef, MirType>,
) -> usize {
    if let Some(ty) = generic_map_value_types.get(map) {
        return ty.size().max(1);
    }
    match types.get(&dst) {
        Some(MirType::Ptr { pointee, .. }) => pointee.size().max(1),
        _ => 8,
    }
}

pub(super) fn register_generic_map_layout_spec(
    map: &MapRef,
    key_size: usize,
    value_size: Option<usize>,
    specs: &mut HashMap<String, VerifierMapLayoutSpec>,
    errors: &mut Vec<VerifierTypeError>,
) {
    if is_builtin_map_name(&map.name) {
        return;
    }
    if !map.kind.supports_any_generic_map_op() {
        errors.push(VerifierTypeError::new(format!(
            "map operations do not support map kind {} for '{}'",
            map.kind, map.name
        )));
        return;
    }

    let inferred_key_size = if map.kind.is_keyless_map() {
        0
    } else if map.kind.is_array_index_map() {
        4
    } else {
        match checked_map_layout_size(map, "key", key_size, false, errors) {
            Some(size) => size,
            None => return,
        }
    };
    let (inferred_value_size, defaulted) = match value_size {
        Some(size) => {
            let Some(size) = checked_map_layout_size(map, "value", size, false, errors) else {
                return;
            };
            (size, false)
        }
        None => (8, true),
    };

    match specs.get_mut(&map.name) {
        Some(spec) => {
            if spec.kind != map.kind {
                errors.push(VerifierTypeError::new(format!(
                    "map '{}' used with conflicting kinds: {} vs {}",
                    map.name, spec.kind, map.kind
                )));
                return;
            }
            if spec.key_size != inferred_key_size {
                errors.push(VerifierTypeError::new(format!(
                    "map '{}' used with conflicting key sizes: {} vs {}",
                    map.name, spec.key_size, inferred_key_size
                )));
                return;
            }
            if spec.value_size != inferred_value_size {
                if spec.value_size_defaulted && !defaulted {
                    spec.value_size = inferred_value_size;
                    spec.value_size_defaulted = false;
                } else if !(defaulted && !spec.value_size_defaulted) {
                    errors.push(VerifierTypeError::new(format!(
                        "map '{}' used with conflicting value sizes: {} vs {}",
                        map.name, spec.value_size, inferred_value_size
                    )));
                }
            }
        }
        None => {
            specs.insert(
                map.name.clone(),
                VerifierMapLayoutSpec {
                    kind: map.kind,
                    key_size: inferred_key_size,
                    value_size: inferred_value_size,
                    value_size_defaulted: defaulted,
                },
            );
        }
    }
}

fn checked_map_layout_size(
    map: &MapRef,
    role: &str,
    size: usize,
    allow_zero: bool,
    errors: &mut Vec<VerifierTypeError>,
) -> Option<u32> {
    let normalized = if allow_zero { size } else { size.max(1) };
    match u32::try_from(normalized) {
        Ok(size) => Some(size),
        Err(_) => {
            errors.push(VerifierTypeError::new(format!(
                "map '{}' {} size {} exceeds the u32 eBPF map definition range",
                map.name, role, normalized
            )));
            None
        }
    }
}

pub(super) fn check_generic_map_layout_constraints(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
    generic_map_value_types: &HashMap<MapRef, MirType>,
) -> Vec<VerifierTypeError> {
    let mut specs: HashMap<String, VerifierMapLayoutSpec> = HashMap::new();
    let mut counter_kinds: HashMap<String, MapKind> = HashMap::new();
    let mut errors = Vec::new();

    for block in &func.blocks {
        for inst in &block.instructions {
            match inst {
                MirInst::MapLookup { dst, map, key } => {
                    if !map.kind.supports_generic_map_op(MapOpKind::Lookup) {
                        errors.push(VerifierTypeError::new(
                            map.kind.generic_map_op_error(MapOpKind::Lookup, &map.name),
                        ));
                        continue;
                    }
                    check_counter_map_kind(map, &mut counter_kinds, &mut errors);
                    let Some(key_size) =
                        infer_map_operand_size(*key, "map key", types, &mut errors)
                    else {
                        continue;
                    };
                    let value_size = if map.kind.is_map_in_map() {
                        4
                    } else {
                        infer_map_lookup_value_size(*dst, map, types, generic_map_value_types)
                    };
                    register_generic_map_layout_spec(
                        map,
                        key_size,
                        Some(value_size),
                        &mut specs,
                        &mut errors,
                    );
                }
                MirInst::MapLookupDynamic { inner_map, key, .. } => {
                    if !inner_map.kind.supports_generic_map_op(MapOpKind::Lookup) {
                        errors.push(VerifierTypeError::new(
                            inner_map
                                .kind
                                .generic_map_op_error(MapOpKind::Lookup, &inner_map.name),
                        ));
                        continue;
                    }
                    let _ = infer_map_operand_size(*key, "map key", types, &mut errors);
                }
                MirInst::MapUpdate { map, key, val, .. } => {
                    if !map.kind.supports_generic_map_op(MapOpKind::Update) {
                        errors.push(VerifierTypeError::new(
                            map.kind.generic_map_op_error(MapOpKind::Update, &map.name),
                        ));
                        continue;
                    }
                    check_counter_map_kind(map, &mut counter_kinds, &mut errors);
                    let Some(key_size) =
                        infer_map_operand_size(*key, "map key", types, &mut errors)
                    else {
                        continue;
                    };
                    let Some(value_size) =
                        infer_map_operand_size(*val, "map value", types, &mut errors)
                    else {
                        continue;
                    };
                    register_generic_map_layout_spec(
                        map,
                        key_size,
                        Some(value_size),
                        &mut specs,
                        &mut errors,
                    );
                }
                MirInst::MapUpdateDynamic {
                    inner_map,
                    key,
                    val,
                    ..
                } => {
                    if !inner_map.kind.supports_generic_map_op(MapOpKind::Update) {
                        errors.push(VerifierTypeError::new(
                            inner_map
                                .kind
                                .generic_map_op_error(MapOpKind::Update, &inner_map.name),
                        ));
                        continue;
                    }
                    let Some(key_size) =
                        infer_map_operand_size(*key, "map key", types, &mut errors)
                    else {
                        continue;
                    };
                    let Some(value_size) =
                        infer_map_operand_size(*val, "map value", types, &mut errors)
                    else {
                        continue;
                    };
                    register_generic_map_layout_spec(
                        inner_map,
                        key_size,
                        Some(value_size),
                        &mut specs,
                        &mut errors,
                    );
                }
                MirInst::MapDelete { map, key } => {
                    if !map.kind.supports_generic_map_op(MapOpKind::Delete) {
                        errors.push(VerifierTypeError::new(
                            map.kind.generic_map_op_error(MapOpKind::Delete, &map.name),
                        ));
                        continue;
                    }
                    check_counter_map_kind(map, &mut counter_kinds, &mut errors);
                    let Some(key_size) =
                        infer_map_operand_size(*key, "map key", types, &mut errors)
                    else {
                        continue;
                    };
                    register_generic_map_layout_spec(map, key_size, None, &mut specs, &mut errors);
                }
                MirInst::MapDeleteDynamic { inner_map, key, .. } => {
                    if !inner_map.kind.supports_generic_map_op(MapOpKind::Delete) {
                        errors.push(VerifierTypeError::new(
                            inner_map
                                .kind
                                .generic_map_op_error(MapOpKind::Delete, &inner_map.name),
                        ));
                        continue;
                    }
                    let Some(key_size) =
                        infer_map_operand_size(*key, "map key", types, &mut errors)
                    else {
                        continue;
                    };
                    register_generic_map_layout_spec(
                        inner_map,
                        key_size,
                        None,
                        &mut specs,
                        &mut errors,
                    );
                }
                MirInst::MapPush { map, val, .. } => {
                    if !map.kind.supports_generic_map_op(MapOpKind::Push) {
                        errors.push(VerifierTypeError::new(
                            map.kind.generic_map_op_error(MapOpKind::Push, &map.name),
                        ));
                        continue;
                    }
                    check_counter_map_kind(map, &mut counter_kinds, &mut errors);
                    let Some(value_size) =
                        infer_map_operand_size(*val, "map value", types, &mut errors)
                    else {
                        continue;
                    };
                    register_generic_map_layout_spec(
                        map,
                        0,
                        Some(value_size),
                        &mut specs,
                        &mut errors,
                    );
                }
                _ => {}
            }
        }
    }

    errors
}

pub(super) fn check_map_operand_scalar_size(
    vreg: VReg,
    what: &str,
    types: &HashMap<VReg, MirType>,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(ty) = types.get(&vreg) else {
        return;
    };
    if matches!(ty, MirType::Ptr { .. }) {
        return;
    }
    let size = match ty.size() {
        0 => 8,
        n => n,
    };
    if size > 8 {
        errors.push(VerifierTypeError::new(format!(
            "{what} v{} has size {} bytes and must be passed as a pointer",
            vreg.0, size
        )));
    }
}

pub(super) fn map_value_limit_from_dst_type(dst_ty: Option<&MirType>) -> Option<i64> {
    let pointee = match dst_ty {
        Some(MirType::Ptr { pointee, .. }) => pointee.as_ref(),
        _ => return None,
    };
    if matches!(pointee, MirType::Unknown) {
        return None;
    }
    let size = pointee.size();
    if size == 0 {
        return None;
    }
    Some(size.saturating_sub(1) as i64)
}
