use super::*;

#[test]
fn test_map_lookup_requires_null_check() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst,
        map: MapRef {
            name: "test".to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    let load_dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst: load_dst,
        ptr: dst,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = map_lookup_types(&func, dst);
    let err = verify_mir(&func, &types).expect_err("expected null-check error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("may dereference null"))
    );
}

#[test]
fn test_map_lookup_null_check_ok() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let cond = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst,
        map: MapRef {
            name: "test".to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(dst),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: ok,
        if_false: bad,
    };

    let ok_load = func.alloc_vreg();
    func.block_mut(ok).instructions.push(MirInst::Load {
        dst: ok_load,
        ptr: dst,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(ok).terminator = MirInst::Return { val: None };

    func.block_mut(bad).terminator = MirInst::Return { val: None };

    let types = map_lookup_types(&func, dst);
    verify_mir(&func, &types).expect("expected verifier pass");
}

#[test]
fn test_typed_map_pointer_param_requires_null_check_before_load() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_ptr = func.alloc_vreg();
    func.param_count = 1;
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst,
        ptr: map_ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected null-check error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("may dereference null pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_map_lookup_rejects_unsupported_map_kind() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst,
        map: MapRef {
            name: "events".to_string(),
            kind: MapKind::RingBuf,
        },
        key,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    let err = verify_mir(&func, &types).expect_err("expected unsupported map-kind error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("map operations do not support map kind")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_map_delete_rejects_array_map_kind() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapDelete {
        map: MapRef {
            name: "arr".to_string(),
            kind: MapKind::Array,
        },
        key,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected array delete error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("map delete is not supported for array map kind")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_map_update_rejects_out_of_range_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let val = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: val,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: "m".to_string(),
            kind: MapKind::Hash,
        },
        key,
        val,
        flags: (i32::MAX as u64) + 1,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected map-update flags error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("exceed supported 32-bit immediate range")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_map_lookup_rejects_large_scalar_key_operand() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst,
        map: MapRef {
            name: "m".to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        key,
        MirType::Array {
            elem: Box::new(MirType::U8),
            len: 16,
        },
    );
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected map key size error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("map key v0 has size 16 bytes and must be passed as a pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_map_update_rejects_large_scalar_value_operand() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let val = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: val,
        src: MirValue::Const(2),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: "m".to_string(),
            kind: MapKind::Hash,
        },
        key,
        val,
        flags: 0,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        val,
        MirType::Array {
            elem: Box::new(MirType::U8),
            len: 24,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected map value size error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("map value v1 has size 24 bytes and must be passed as a pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_string_counter_map_requires_pointer_key() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let val = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: val,
        src: MirValue::Const(2),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: STRING_COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Hash,
        },
        key,
        val,
        flags: 0,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected pointer-key error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("map key requires pointer type")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_map_ops_reject_conflicting_map_kinds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key0 = func.alloc_vreg();
    let key1 = func.alloc_vreg();
    let dst0 = func.alloc_vreg();
    let dst1 = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key0,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key1,
        src: MirValue::Const(2),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: dst0,
        map: MapRef {
            name: "m".to_string(),
            kind: MapKind::Hash,
        },
        key: key0,
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: dst1,
        map: MapRef {
            name: "m".to_string(),
            kind: MapKind::Array,
        },
        key: key1,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst0,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(
        dst1,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected map kind conflict");
    assert!(
        err.iter()
            .any(|e| e.message.contains("used with conflicting kinds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_counter_map_rejects_non_hash_kind() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let val = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: val,
        src: MirValue::Const(2),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Array,
        },
        key,
        val,
        flags: 0,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected counter map kind error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("only supports Hash/PerCpuHash kinds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_counter_map_rejects_conflicting_kinds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key0 = func.alloc_vreg();
    let key1 = func.alloc_vreg();
    let val0 = func.alloc_vreg();
    let val1 = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key0,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key1,
        src: MirValue::Const(2),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: val0,
        src: MirValue::Const(3),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: val1,
        src: MirValue::Const(4),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Hash,
        },
        key: key0,
        val: val0,
        flags: 0,
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: COUNTER_MAP_NAME.to_string(),
            kind: MapKind::PerCpuHash,
        },
        key: key1,
        val: val1,
        flags: 0,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected counter map kind conflict");
    assert!(
        err.iter()
            .any(|e| e.message.contains("used with conflicting kinds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_map_ops_reject_conflicting_value_sizes() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key0 = func.alloc_vreg();
    let key1 = func.alloc_vreg();
    let val = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key0,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key1,
        src: MirValue::Const(2),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: val,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: "m".to_string(),
            kind: MapKind::Hash,
        },
        key: key0,
        val,
        flags: 0,
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst,
        map: MapRef {
            name: "m".to_string(),
            kind: MapKind::Hash,
        },
        key: key1,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::I32),
            address_space: AddressSpace::Map,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected map value-size conflict");
    assert!(
        err.iter()
            .any(|e| e.message.contains("used with conflicting value sizes")),
        "unexpected errors: {:?}",
        err
    );
}
