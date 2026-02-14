fn map_value_limit(map_name: &str) -> Option<i64> {
    match map_name {
        COUNTER_MAP_NAME | STRING_COUNTER_MAP_NAME | HISTOGRAM_MAP_NAME | TIMESTAMP_MAP_NAME => {
            Some(8 - 1)
        }
        KSTACK_MAP_NAME | USTACK_MAP_NAME => Some((127 * 8) - 1),
        _ => None,
    }
}

fn supports_generic_map_kind(kind: MapKind) -> bool {
    matches!(
        kind,
        MapKind::Hash | MapKind::Array | MapKind::PerCpuHash | MapKind::PerCpuArray
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VccMapLayoutSpec {
    kind: MapKind,
    key_size: u32,
    value_size: u32,
    value_size_defaulted: bool,
}

fn is_builtin_map_name(name: &str) -> bool {
    matches!(
        name,
        RINGBUF_MAP_NAME
            | COUNTER_MAP_NAME
            | STRING_COUNTER_MAP_NAME
            | HISTOGRAM_MAP_NAME
            | TIMESTAMP_MAP_NAME
            | KSTACK_MAP_NAME
            | USTACK_MAP_NAME
    )
}

fn is_counter_map_name(name: &str) -> bool {
    matches!(name, COUNTER_MAP_NAME | STRING_COUNTER_MAP_NAME)
}

fn check_counter_map_kind(
    map: &crate::compiler::mir::MapRef,
    seen: &mut HashMap<String, MapKind>,
    errors: &mut Vec<VccError>,
) {
    if !is_counter_map_name(&map.name) {
        return;
    }
    if !matches!(map.kind, MapKind::Hash | MapKind::PerCpuHash) {
        errors.push(VccError::new(
            VccErrorKind::UnsupportedInstruction,
            format!(
                "map '{}' only supports Hash/PerCpuHash kinds, got {:?}",
                map.name, map.kind
            ),
        ));
        return;
    }
    if let Some(existing) = seen.get(&map.name) {
        if *existing != map.kind {
            errors.push(VccError::new(
                VccErrorKind::UnsupportedInstruction,
                format!(
                    "map '{}' used with conflicting kinds: {:?} vs {:?}",
                    map.name, existing, map.kind
                ),
            ));
        }
    } else {
        seen.insert(map.name.clone(), map.kind);
    }
}

fn infer_map_operand_size(
    vreg: VReg,
    what: &str,
    types: &HashMap<VReg, MirType>,
    errors: &mut Vec<VccError>,
) -> Option<usize> {
    match types.get(&vreg) {
        Some(MirType::Ptr { pointee, .. }) => Some(pointee.size().max(1)),
        Some(ty) => {
            let size = match ty.size() {
                0 => 8,
                n => n,
            };
            if size > 8 {
                errors.push(VccError::new(
                    VccErrorKind::UnsupportedInstruction,
                    format!(
                        "{what} v{} has size {} bytes and must be passed as a pointer",
                        vreg.0, size
                    ),
                ));
                None
            } else {
                Some(size)
            }
        }
        None => Some(8),
    }
}

fn infer_map_lookup_value_size(dst: VReg, types: &HashMap<VReg, MirType>) -> usize {
    match types.get(&dst) {
        Some(MirType::Ptr { pointee, .. }) => pointee.size().max(1),
        _ => 8,
    }
}

fn register_generic_map_layout_spec(
    map: &crate::compiler::mir::MapRef,
    key_size: usize,
    value_size: Option<usize>,
    specs: &mut HashMap<String, VccMapLayoutSpec>,
    errors: &mut Vec<VccError>,
) {
    if is_builtin_map_name(&map.name) {
        return;
    }
    if !supports_generic_map_kind(map.kind) {
        errors.push(VccError::new(
            VccErrorKind::UnsupportedInstruction,
            format!(
                "map operations do not support map kind {:?} for '{}'",
                map.kind, map.name
            ),
        ));
        return;
    }

    let mut inferred_key_size = key_size.max(1) as u32;
    if matches!(map.kind, MapKind::Array | MapKind::PerCpuArray) {
        inferred_key_size = 4;
    }
    let (inferred_value_size, defaulted) = match value_size {
        Some(size) => (size.max(1) as u32, false),
        None => (8, true),
    };

    match specs.get_mut(&map.name) {
        Some(spec) => {
            if spec.kind != map.kind {
                errors.push(VccError::new(
                    VccErrorKind::UnsupportedInstruction,
                    format!(
                        "map '{}' used with conflicting kinds: {:?} vs {:?}",
                        map.name, spec.kind, map.kind
                    ),
                ));
                return;
            }
            if spec.key_size != inferred_key_size {
                errors.push(VccError::new(
                    VccErrorKind::UnsupportedInstruction,
                    format!(
                        "map '{}' used with conflicting key sizes: {} vs {}",
                        map.name, spec.key_size, inferred_key_size
                    ),
                ));
                return;
            }
            if spec.value_size != inferred_value_size {
                if spec.value_size_defaulted && !defaulted {
                    spec.value_size = inferred_value_size;
                    spec.value_size_defaulted = false;
                } else if !(defaulted && !spec.value_size_defaulted) {
                    errors.push(VccError::new(
                        VccErrorKind::UnsupportedInstruction,
                        format!(
                            "map '{}' used with conflicting value sizes: {} vs {}",
                            map.name, spec.value_size, inferred_value_size
                        ),
                    ));
                }
            }
        }
        None => {
            specs.insert(
                map.name.clone(),
                VccMapLayoutSpec {
                    kind: map.kind,
                    key_size: inferred_key_size,
                    value_size: inferred_value_size,
                    value_size_defaulted: defaulted,
                },
            );
        }
    }
}

fn check_generic_map_layout_constraints(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
) -> Vec<VccError> {
    let mut specs: HashMap<String, VccMapLayoutSpec> = HashMap::new();
    let mut counter_kinds: HashMap<String, MapKind> = HashMap::new();
    let mut errors = Vec::new();

    for block in &func.blocks {
        for inst in &block.instructions {
            match inst {
                MirInst::MapLookup { dst, map, key } => {
                    check_counter_map_kind(map, &mut counter_kinds, &mut errors);
                    let Some(key_size) =
                        infer_map_operand_size(*key, "map key", types, &mut errors)
                    else {
                        continue;
                    };
                    let value_size = infer_map_lookup_value_size(*dst, types);
                    register_generic_map_layout_spec(
                        map,
                        key_size,
                        Some(value_size),
                        &mut specs,
                        &mut errors,
                    );
                }
                MirInst::MapUpdate { map, key, val, .. } => {
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
                MirInst::MapDelete { map, key } => {
                    check_counter_map_kind(map, &mut counter_kinds, &mut errors);
                    let Some(key_size) =
                        infer_map_operand_size(*key, "map key", types, &mut errors)
                    else {
                        continue;
                    };
                    register_generic_map_layout_spec(map, key_size, None, &mut specs, &mut errors);
                }
                _ => {}
            }
        }
    }

    errors
}

fn map_value_limit_from_dst_type(dst_ty: Option<&MirType>) -> Option<i64> {
    let pointee = match dst_ty {
        Some(MirType::Ptr {
            pointee,
            address_space: AddressSpace::Map,
        }) => pointee.as_ref(),
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

