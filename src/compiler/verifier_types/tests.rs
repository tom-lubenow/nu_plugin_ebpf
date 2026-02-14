use super::*;
use crate::compiler::mir::{
    COUNTER_MAP_NAME, MapKind, MapRef, MirType, STRING_COUNTER_MAP_NAME, StackSlotKind,
};

fn map_lookup_types(func: &MirFunction, vreg: VReg) -> HashMap<VReg, MirType> {
    let mut types = HashMap::new();
    for i in 0..func.vreg_count {
        types.insert(VReg(i), MirType::I64);
    }
    types.insert(
        vreg,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types
}

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

#[test]
fn test_helper_pointer_arg_required() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 16, // bpf_get_current_comm(buf, size)
            args: vec![MirValue::Const(0), MirValue::Const(16)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected helper pointer-arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_unknown_helper_rejects_more_than_five_args() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 9999,
            args: vec![
                MirValue::Const(0),
                MirValue::Const(1),
                MirValue::Const(2),
                MirValue::Const(3),
                MirValue::Const(4),
                MirValue::Const(5),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper-argument count rejection");
    assert!(
        err.iter()
            .any(|e| e.message.contains("at most 5 arguments")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_rejects_more_than_five_params() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 6;
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected param-count error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("at most 5 arguments")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_rejects_subfn_calls_with_more_than_five_args() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    let mut args = Vec::new();
    for i in 0..6 {
        let v = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: v,
            src: MirValue::Const(i),
        });
        args.push(v);
    }
    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst,
        subfn: crate::compiler::mir::SubfunctionId(0),
        args,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected subfunction-arg count error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("at most 5 arguments")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_lookup_requires_null_check() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let load_dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::StackSlot(key_slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::VReg(map), MirValue::VReg(key)],
        });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst: load_dst,
        ptr: dst,
        offset: 0,
        ty: MirType::I64,
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
    types.insert(load_dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper null-check error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("may dereference null"))
    );
}

#[test]
fn test_helper_map_lookup_null_check_via_copied_cond_ok() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let load_block = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let cond0 = func.alloc_vreg();
    let cond1 = func.alloc_vreg();
    let load_dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::StackSlot(key_slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ptr,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::VReg(map), MirValue::VReg(key)],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond0,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cond1,
        src: MirValue::VReg(cond0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cond1,
        if_true: load_block,
        if_false: done,
    };

    func.block_mut(load_block).instructions.push(MirInst::Load {
        dst: load_dst,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(load_block).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(load_dst, MirType::I64);

    verify_mir(&func, &types).expect("expected copied null-check guard to pass");
}

#[test]
fn test_helper_map_lookup_rejects_out_of_bounds_key_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key_base = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key_base,
        src: MirValue::StackSlot(key_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: key,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(key_base),
        rhs: MirValue::Const(8),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::VReg(map), MirValue::VReg(key)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper key bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper map_lookup key out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_lookup_rejects_user_map_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(map),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 1, // bpf_map_lookup_elem(map, key)
        args: vec![MirValue::VReg(map), MirValue::StackSlot(key_slot)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper map pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper map_lookup map expects pointer in [Stack]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_update_rejects_map_lookup_value_as_map_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let lookup = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let update_ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: lookup,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(lookup),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: update_ret,
        helper: 2, // bpf_map_update_elem(map, key, value, flags)
        args: vec![
            MirValue::VReg(lookup),
            MirValue::StackSlot(key_slot),
            MirValue::StackSlot(value_slot),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        lookup,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(update_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected map-value pointer map-arg rejection");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper map_update map expects pointer in [Stack]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_reserve_submit_releases_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let submit = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let record = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let submit_ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: record,
            helper: 131, // bpf_ringbuf_reserve(map, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(record),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: submit,
        if_false: done,
    };

    func.block_mut(submit)
        .instructions
        .push(MirInst::CallHelper {
            dst: submit_ret,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
    func.block_mut(submit).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(submit_ret, MirType::I64);
    verify_mir(&func, &types).expect("expected ringbuf reference to be released");
}

#[test]
fn test_helper_ringbuf_reserve_leak_is_rejected() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let leak = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let record = func.alloc_vreg();
    let cond = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: record,
            helper: 131, // bpf_ringbuf_reserve(map, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(record),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: leak,
        if_false: done,
    };

    func.block_mut(leak).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected leak error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased ringbuf record reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_submit_requires_ringbuf_record_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::StackSlot(slot), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected ringbuf pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 132 arg0 expects ringbuf record pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_submit_rejects_double_release() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let submit = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let record = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let submit_ret0 = func.alloc_vreg();
    let submit_ret1 = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: record,
            helper: 131, // bpf_ringbuf_reserve(map, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(record),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: submit,
        if_false: done,
    };

    func.block_mut(submit)
        .instructions
        .push(MirInst::CallHelper {
            dst: submit_ret0,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
    func.block_mut(submit)
        .instructions
        .push(MirInst::CallHelper {
            dst: submit_ret1,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
    func.block_mut(submit).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(submit_ret0, MirType::I64);
    types.insert(submit_ret1, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected double-release error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 132 arg0 expects pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_submit_invalidates_record_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let submit = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let record = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let submit_ret = func.alloc_vreg();
    let load_dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: record,
            helper: 131, // bpf_ringbuf_reserve(map, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(record),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: submit,
        if_false: done,
    };

    func.block_mut(submit)
        .instructions
        .push(MirInst::CallHelper {
            dst: submit_ret,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
    func.block_mut(submit).instructions.push(MirInst::Load {
        dst: load_dst,
        ptr: record,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(submit).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(submit_ret, MirType::I64);
    types.insert(load_dst, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected use-after-release error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("load requires pointer type")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_perf_event_output_rejects_user_ctx_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 25, // bpf_perf_event_output(ctx, map, flags, data, size)
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(map_slot),
            MirValue::Const(0),
            MirValue::StackSlot(data_slot),
            MirValue::Const(8),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper ctx pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper perf_event_output ctx expects pointer in [Kernel]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_get_stackid_rejects_user_ctx_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 27, // bpf_get_stackid(ctx, map, flags)
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(map_slot),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper ctx pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_stackid ctx expects pointer in [Kernel]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_tail_call_rejects_user_ctx_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 12, // bpf_tail_call(ctx, prog_array_map, index)
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(map_slot),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper ctx pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper tail_call ctx expects pointer in [Kernel]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_tail_call_rejects_pointer_index() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let index_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).terminator = MirInst::TailCall {
        prog_map: MapRef {
            name: "jumps".to_string(),
            kind: MapKind::ProgArray,
        },
        index: MirValue::StackSlot(index_slot),
    };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected tail-call index error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("tail_call index expects scalar")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_tail_call_rejects_non_prog_array_map_kind() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    func.block_mut(entry).terminator = MirInst::TailCall {
        prog_map: MapRef {
            name: "not_prog_array".to_string(),
            kind: MapKind::Hash,
        },
        index: MirValue::Const(0),
    };

    let err =
        verify_mir(&func, &HashMap::new()).expect_err("expected non-ProgArray tail_call error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("tail_call requires ProgArray map")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_get_current_comm_requires_positive_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let buf = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 16, // bpf_get_current_comm(buf, size)
            args: vec![MirValue::StackSlot(buf), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected non-positive size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 16 arg1 must be > 0"))
    );
}

#[test]
fn test_helper_get_current_comm_checks_dst_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let buf = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 16, // bpf_get_current_comm(buf, size)
            args: vec![MirValue::StackSlot(buf), MirValue::Const(16)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper dst bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_current_comm dst out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_trace_printk_requires_positive_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let fmt = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 6, // bpf_trace_printk(fmt, fmt_size, ...)
            args: vec![MirValue::StackSlot(fmt), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected non-positive size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 6 arg1 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_trace_printk_checks_fmt_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let fmt = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 6, // bpf_trace_printk(fmt, fmt_size, ...)
            args: vec![MirValue::StackSlot(fmt), MirValue::Const(16)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper fmt bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper trace_printk fmt out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_trace_printk_rejects_user_fmt_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let fmt = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(fmt),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 6, // bpf_trace_printk(fmt, fmt_size, ...)
        args: vec![MirValue::VReg(fmt), MirValue::Const(8)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        fmt,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper fmt pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper trace_printk fmt expects pointer in [Stack, Map]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_get_current_comm_variable_size_range_checks_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let size = func.alloc_vreg();
    func.param_count = 1;
    let ge_one = func.alloc_vreg();
    let le_sixteen = func.alloc_vreg();
    let buf = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ge_one,
        op: BinOpKind::Ge,
        lhs: MirValue::VReg(size),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: ge_one,
        if_true: check_upper,
        if_false: done,
    };

    func.block_mut(check_upper)
        .instructions
        .push(MirInst::BinOp {
            dst: le_sixteen,
            op: BinOpKind::Le,
            lhs: MirValue::VReg(size),
            rhs: MirValue::Const(16),
        });
    func.block_mut(check_upper).terminator = MirInst::Branch {
        cond: le_sixteen,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 16, // bpf_get_current_comm(buf, size)
        args: vec![MirValue::StackSlot(buf), MirValue::VReg(size)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };

    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper dst bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_current_comm dst out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_get_current_comm_variable_size_range_within_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let size = func.alloc_vreg();
    func.param_count = 1;
    let ge_one = func.alloc_vreg();
    let le_eight = func.alloc_vreg();
    let buf = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ge_one,
        op: BinOpKind::Ge,
        lhs: MirValue::VReg(size),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: ge_one,
        if_true: check_upper,
        if_false: done,
    };

    func.block_mut(check_upper)
        .instructions
        .push(MirInst::BinOp {
            dst: le_eight,
            op: BinOpKind::Le,
            lhs: MirValue::VReg(size),
            rhs: MirValue::Const(8),
        });
    func.block_mut(check_upper).terminator = MirInst::Branch {
        cond: le_eight,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 16, // bpf_get_current_comm(buf, size)
        args: vec![MirValue::StackSlot(buf), MirValue::VReg(size)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };

    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected bounded helper size range to pass");
}

#[test]
fn test_helper_probe_read_user_str_rejects_stack_src() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 114, // bpf_probe_read_user_str(dst, size, unsafe_ptr)
            args: vec![
                MirValue::StackSlot(dst_slot),
                MirValue::Const(8),
                MirValue::StackSlot(src_slot),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected user source pointer error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper probe_read src expects pointer in [User]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_output_checks_data_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 130, // bpf_ringbuf_output(map, data, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(data_slot),
                MirValue::Const(16),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper data bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper ringbuf_output data out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_update_rejects_user_key_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call_block = func.alloc_block();
    let exit_block = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(key),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call_block,
        if_false: exit_block,
    };

    func.block_mut(call_block)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 2, // bpf_map_update_elem(map, key, value, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::VReg(key),
                MirValue::StackSlot(value_slot),
                MirValue::Const(0),
            ],
        });
    func.block_mut(call_block).terminator = MirInst::Return { val: None };

    func.block_mut(exit_block).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        key,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected map key pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper map_update key expects pointer in [Stack, Map]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_stack_pointer_non_null() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);
    verify_mir(&func, &types).expect("stack pointer should be non-null");
}

#[test]
fn test_stack_load_out_of_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst,
        ptr,
        offset: 8,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bounds error");
    assert!(err.iter().any(|e| e.message.contains("out of bounds")));
}

#[test]
fn test_stack_pointer_offset_in_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let tmp = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: tmp,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst,
        ptr: tmp,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        tmp,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected in-bounds access");
}

#[test]
fn test_read_str_rejects_non_user_ptr_for_user_space() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ptr = func.alloc_vreg();
    func.param_count = 1;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::ReadStr {
        dst: slot,
        ptr,
        user_space: true,
        max_len: 16,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected user ptr error");
    assert!(err.iter().any(|e| e.message.contains("read_str")));
}

#[test]
fn test_read_str_user_ptr_requires_null_check_for_user_space() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ptr = func.alloc_vreg();
    func.param_count = 1;
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::ReadStr {
        dst: slot,
        ptr,
        user_space: true,
        max_len: 16,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected read_str null-check error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("may dereference null pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_read_str_user_ptr_with_null_check_for_user_space() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ptr = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::ReadStr {
        dst: slot,
        ptr,
        user_space: true,
        max_len: 16,
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );

    verify_mir(&func, &types).expect("expected null-checked read_str user pointer to pass");
}

#[test]
fn test_load_rejects_user_ptr() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ptr = func.alloc_vreg();
    func.param_count = 1;
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Load {
        dst,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected user ptr load error");
    assert!(err.iter().any(|e| e.message.contains("load")));
}

#[test]
fn test_map_value_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let key = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let split_cond = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let off = func.alloc_vreg();
    let tmp_ptr = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: ptr,
        map: MapRef {
            name: COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: ok,
        if_false: bad,
    };

    func.block_mut(ok).instructions.push(MirInst::BinOp {
        dst: split_cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(ok).terminator = MirInst::Branch {
        cond: split_cond,
        if_true: left,
        if_false: right,
    };

    func.block_mut(left).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(left).terminator = MirInst::Jump { target: join };

    func.block_mut(right).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(4),
    });
    func.block_mut(right).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: tmp_ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::VReg(off),
    });
    func.block_mut(join).instructions.push(MirInst::Load {
        dst,
        ptr: tmp_ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    func.block_mut(bad).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(
        tmp_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected map bounds error");
    assert!(err.iter().any(|e| e.message.contains("out of bounds")));
}

#[test]
fn test_unknown_map_uses_pointee_bounds_for_lookup_result() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: ptr,
        map: MapRef {
            name: "custom_map".to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: ok,
        if_false: bad,
    };

    func.block_mut(ok).instructions.push(MirInst::Load {
        dst,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(ok).terminator = MirInst::Return { val: None };
    func.block_mut(bad).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 4,
            }),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected map bounds error");
    assert!(err.iter().any(|e| e.message.contains("out of bounds")));
}

#[test]
fn test_unknown_map_pointee_bounds_allow_in_bounds_access() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: ptr,
        map: MapRef {
            name: "custom_map".to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: ok,
        if_false: bad,
    };

    func.block_mut(ok).instructions.push(MirInst::Load {
        dst,
        ptr,
        offset: 0,
        ty: MirType::I32,
    });
    func.block_mut(ok).terminator = MirInst::Return { val: None };
    func.block_mut(bad).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 8,
            }),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(dst, MirType::I32);

    verify_mir(&func, &types).expect("expected in-bounds access");
}

#[test]
fn test_stack_pointer_offset_via_shift_out_of_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let base = func.alloc_vreg();
    let offset = func.alloc_vreg();
    let tmp = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: base,
        src: MirValue::Const(3),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: offset,
        op: BinOpKind::Shl,
        lhs: MirValue::VReg(base),
        rhs: MirValue::Const(2),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: tmp,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::VReg(offset),
    });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst,
        ptr: tmp,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        tmp,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bounds error");
    assert!(err.iter().any(|e| e.message.contains("out of bounds")));
}

#[test]
fn test_stack_pointer_offset_via_mul_out_of_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let base = func.alloc_vreg();
    let scale = func.alloc_vreg();
    let offset = func.alloc_vreg();
    let tmp = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: base,
        src: MirValue::Const(3),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: scale,
        src: MirValue::Const(4),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: offset,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(base),
        rhs: MirValue::VReg(scale),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: tmp,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::VReg(offset),
    });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst,
        ptr: tmp,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        tmp,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bounds error");
    assert!(err.iter().any(|e| e.message.contains("out of bounds")));
}

#[test]
fn test_pointer_phi_preserves_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let tmp = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let phi_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cond,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: left,
        if_false: right,
    };

    func.block_mut(left).instructions.push(MirInst::Copy {
        dst: tmp,
        src: MirValue::VReg(ptr),
    });
    func.block_mut(left).terminator = MirInst::Jump { target: join };

    func.block_mut(right).instructions.push(MirInst::Copy {
        dst: tmp,
        src: MirValue::VReg(ptr),
    });
    func.block_mut(right).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::Phi {
        dst: phi_ptr,
        args: vec![(left, tmp), (right, tmp)],
    });
    func.block_mut(join).instructions.push(MirInst::Load {
        dst,
        ptr: phi_ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        tmp,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        phi_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected bounds to propagate through phi");
}

#[test]
fn test_div_range_with_non_zero_guard() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let join = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let div = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let offset = func.alloc_vreg();
    let tmp_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: ptr,
        if_true: left,
        if_false: right,
    };

    func.block_mut(left).instructions.push(MirInst::Copy {
        dst: idx,
        src: MirValue::Const(0),
    });
    func.block_mut(left).instructions.push(MirInst::Copy {
        dst: div,
        src: MirValue::Const(0),
    });
    func.block_mut(left).terminator = MirInst::Jump { target: join };

    func.block_mut(right).instructions.push(MirInst::Copy {
        dst: idx,
        src: MirValue::Const(31),
    });
    func.block_mut(right).instructions.push(MirInst::Copy {
        dst: div,
        src: MirValue::Const(4),
    });
    func.block_mut(right).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(div),
        rhs: MirValue::Const(0),
    });
    func.block_mut(join).terminator = MirInst::Branch {
        cond,
        if_true: ok,
        if_false: bad,
    };

    func.block_mut(ok).instructions.push(MirInst::BinOp {
        dst: offset,
        op: BinOpKind::Div,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::VReg(div),
    });
    func.block_mut(ok).instructions.push(MirInst::BinOp {
        dst: tmp_ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::VReg(offset),
    });
    func.block_mut(ok).instructions.push(MirInst::Load {
        dst,
        ptr: tmp_ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(ok).terminator = MirInst::Return { val: None };

    func.block_mut(bad).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        tmp_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bounds error");
    assert!(err.iter().any(|e| e.message.contains("out of bounds")));
}

#[test]
fn test_mod_range_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(2, 1, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let div = func.alloc_vreg();
    let offset = func.alloc_vreg();
    let tmp_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: idx,
        src: MirValue::Const(31),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: div,
        src: MirValue::Const(4),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: offset,
        op: BinOpKind::Mod,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::VReg(div),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: tmp_ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::VReg(offset),
    });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst,
        ptr: tmp_ptr,
        offset: 0,
        ty: MirType::I8,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        tmp_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I8);

    let err = verify_mir(&func, &types).expect_err("expected bounds error");
    assert!(err.iter().any(|e| e.message.contains("out of bounds")));
}

#[test]
fn test_and_or_xor_range_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(8, 1, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let left = func.alloc_vreg();
    let right = func.alloc_vreg();
    let tmp_and = func.alloc_vreg();
    let tmp_or = func.alloc_vreg();
    let tmp_xor = func.alloc_vreg();
    let ptr_and = func.alloc_vreg();
    let ptr_or = func.alloc_vreg();
    let ptr_xor = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: left,
        src: MirValue::Const(15),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: right,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: tmp_and,
        op: BinOpKind::And,
        lhs: MirValue::VReg(left),
        rhs: MirValue::VReg(right),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: tmp_or,
        op: BinOpKind::Or,
        lhs: MirValue::VReg(left),
        rhs: MirValue::VReg(right),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: tmp_xor,
        op: BinOpKind::Xor,
        lhs: MirValue::VReg(left),
        rhs: MirValue::VReg(right),
    });

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ptr_and,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::VReg(tmp_and),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ptr_or,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::VReg(tmp_or),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ptr_xor,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::VReg(tmp_xor),
    });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst,
        ptr: ptr_xor,
        offset: 0,
        ty: MirType::I8,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        ptr_and,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        ptr_or,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        ptr_xor,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I8);

    let err = verify_mir(&func, &types).expect_err("expected bounds error");
    assert!(err.iter().any(|e| e.message.contains("out of bounds")));
}

#[test]
fn test_prune_impossible_const_compare_branch() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let impossible = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let cmp = func.alloc_vreg();
    let tmp_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: idx,
        src: MirValue::Const(5),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cmp,
        op: BinOpKind::Lt,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::Const(4),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cmp,
        if_true: impossible,
        if_false: done,
    };

    func.block_mut(impossible)
        .instructions
        .push(MirInst::BinOp {
            dst: tmp_ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::VReg(idx),
        });
    func.block_mut(impossible).instructions.push(MirInst::Load {
        dst,
        ptr: tmp_ptr,
        offset: 0,
        ty: MirType::I8,
    });
    func.block_mut(impossible).terminator = MirInst::Return { val: None };

    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        tmp_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I8);

    verify_mir(&func, &types).expect("expected impossible branch to be pruned");
}

#[test]
fn test_not_equal_fact_prunes_followup_eq_branch() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let join = func.alloc_block();
    let guarded = func.alloc_block();
    let skip = func.alloc_block();
    let bad = func.alloc_block();
    let ok = func.alloc_block();
    func.entry = entry;

    let cond = func.alloc_vreg();
    func.param_count = 1;

    let slot = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let left_idx = func.alloc_vreg();
    let right_idx = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let neq = func.alloc_vreg();
    let eq = func.alloc_vreg();
    let tmp_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: left,
        if_false: right,
    };

    func.block_mut(left).instructions.push(MirInst::Copy {
        dst: left_idx,
        src: MirValue::Const(0),
    });
    func.block_mut(left).terminator = MirInst::Jump { target: join };

    func.block_mut(right).instructions.push(MirInst::Copy {
        dst: right_idx,
        src: MirValue::Const(2),
    });
    func.block_mut(right).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::Phi {
        dst: idx,
        args: vec![(left, left_idx), (right, right_idx)],
    });
    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: neq,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::Const(1),
    });
    func.block_mut(join).terminator = MirInst::Branch {
        cond: neq,
        if_true: guarded,
        if_false: skip,
    };

    func.block_mut(guarded).instructions.push(MirInst::BinOp {
        dst: eq,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::Const(1),
    });
    func.block_mut(guarded).terminator = MirInst::Branch {
        cond: eq,
        if_true: bad,
        if_false: ok,
    };

    func.block_mut(skip).terminator = MirInst::Return { val: None };

    func.block_mut(bad).instructions.push(MirInst::BinOp {
        dst: tmp_ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(9),
    });
    func.block_mut(bad).instructions.push(MirInst::Load {
        dst,
        ptr: tmp_ptr,
        offset: 0,
        ty: MirType::I8,
    });
    func.block_mut(bad).terminator = MirInst::Return { val: None };

    func.block_mut(ok).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cond, MirType::Bool);
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        tmp_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I8);

    verify_mir(&func, &types).expect("expected impossible == branch to be pruned");
}

#[test]
fn test_multiple_not_equal_facts_prune_followup_eq() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let join = func.alloc_block();
    let after_first = func.alloc_block();
    let after_second = func.alloc_block();
    let skip_first = func.alloc_block();
    let skip_second = func.alloc_block();
    let bad = func.alloc_block();
    let ok = func.alloc_block();
    func.entry = entry;

    let cond = func.alloc_vreg();
    func.param_count = 1;

    let slot = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let left_idx = func.alloc_vreg();
    let right_idx = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let neq1 = func.alloc_vreg();
    let neq3 = func.alloc_vreg();
    let eq1 = func.alloc_vreg();
    let tmp_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: left,
        if_false: right,
    };

    func.block_mut(left).instructions.push(MirInst::Copy {
        dst: left_idx,
        src: MirValue::Const(0),
    });
    func.block_mut(left).terminator = MirInst::Jump { target: join };

    func.block_mut(right).instructions.push(MirInst::Copy {
        dst: right_idx,
        src: MirValue::Const(4),
    });
    func.block_mut(right).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::Phi {
        dst: idx,
        args: vec![(left, left_idx), (right, right_idx)],
    });
    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: neq1,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::Const(1),
    });
    func.block_mut(join).terminator = MirInst::Branch {
        cond: neq1,
        if_true: after_first,
        if_false: skip_first,
    };

    func.block_mut(after_first)
        .instructions
        .push(MirInst::BinOp {
            dst: neq3,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(idx),
            rhs: MirValue::Const(3),
        });
    func.block_mut(after_first).terminator = MirInst::Branch {
        cond: neq3,
        if_true: after_second,
        if_false: skip_second,
    };

    func.block_mut(after_second)
        .instructions
        .push(MirInst::BinOp {
            dst: eq1,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(idx),
            rhs: MirValue::Const(1),
        });
    func.block_mut(after_second).terminator = MirInst::Branch {
        cond: eq1,
        if_true: bad,
        if_false: ok,
    };

    func.block_mut(skip_first).terminator = MirInst::Return { val: None };
    func.block_mut(skip_second).terminator = MirInst::Return { val: None };

    func.block_mut(bad).instructions.push(MirInst::BinOp {
        dst: tmp_ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(9),
    });
    func.block_mut(bad).instructions.push(MirInst::Load {
        dst,
        ptr: tmp_ptr,
        offset: 0,
        ty: MirType::I8,
    });
    func.block_mut(bad).terminator = MirInst::Return { val: None };

    func.block_mut(ok).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cond, MirType::Bool);
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        tmp_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I8);

    verify_mir(&func, &types).expect("expected impossible == branch to be pruned");
}

#[test]
fn test_compare_refines_true_branch_lt() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let join = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let cmp = func.alloc_vreg();
    let tmp_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cond,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: left,
        if_false: right,
    };

    func.block_mut(left).instructions.push(MirInst::Copy {
        dst: idx,
        src: MirValue::Const(0),
    });
    func.block_mut(left).terminator = MirInst::Jump { target: join };

    func.block_mut(right).instructions.push(MirInst::Copy {
        dst: idx,
        src: MirValue::Const(7),
    });
    func.block_mut(right).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: cmp,
        op: BinOpKind::Lt,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::Const(4),
    });
    func.block_mut(join).terminator = MirInst::Branch {
        cond: cmp,
        if_true: ok,
        if_false: bad,
    };

    func.block_mut(ok).instructions.push(MirInst::BinOp {
        dst: tmp_ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::VReg(idx),
    });
    func.block_mut(ok).instructions.push(MirInst::Load {
        dst,
        ptr: tmp_ptr,
        offset: 0,
        ty: MirType::I8,
    });
    func.block_mut(ok).terminator = MirInst::Return { val: None };

    func.block_mut(bad).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        tmp_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I8);

    verify_mir(&func, &types).expect("expected compare to refine range");
}

#[test]
fn test_compare_refines_true_branch_ge() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let join = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let cmp = func.alloc_vreg();
    let offset = func.alloc_vreg();
    let tmp_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cond,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: left,
        if_false: right,
    };

    func.block_mut(left).instructions.push(MirInst::Copy {
        dst: idx,
        src: MirValue::Const(0),
    });
    func.block_mut(left).terminator = MirInst::Jump { target: join };

    func.block_mut(right).instructions.push(MirInst::Copy {
        dst: idx,
        src: MirValue::Const(7),
    });
    func.block_mut(right).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: cmp,
        op: BinOpKind::Ge,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::Const(4),
    });
    func.block_mut(join).terminator = MirInst::Branch {
        cond: cmp,
        if_true: ok,
        if_false: bad,
    };

    func.block_mut(ok).instructions.push(MirInst::BinOp {
        dst: offset,
        op: BinOpKind::Sub,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::Const(4),
    });
    func.block_mut(ok).instructions.push(MirInst::BinOp {
        dst: tmp_ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::VReg(offset),
    });
    func.block_mut(ok).instructions.push(MirInst::Load {
        dst,
        ptr: tmp_ptr,
        offset: 0,
        ty: MirType::I8,
    });
    func.block_mut(ok).terminator = MirInst::Return { val: None };

    func.block_mut(bad).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        tmp_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I8);

    verify_mir(&func, &types).expect("expected compare to refine range");
}

#[test]
fn test_compare_refines_vreg_bound() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let join = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let bound = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let cmp = func.alloc_vreg();
    let tmp_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: bound,
        src: MirValue::Const(4),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cond,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: left,
        if_false: right,
    };

    func.block_mut(left).instructions.push(MirInst::Copy {
        dst: idx,
        src: MirValue::Const(0),
    });
    func.block_mut(left).terminator = MirInst::Jump { target: join };

    func.block_mut(right).instructions.push(MirInst::Copy {
        dst: idx,
        src: MirValue::Const(7),
    });
    func.block_mut(right).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: cmp,
        op: BinOpKind::Lt,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::VReg(bound),
    });
    func.block_mut(join).terminator = MirInst::Branch {
        cond: cmp,
        if_true: ok,
        if_false: bad,
    };

    func.block_mut(ok).instructions.push(MirInst::BinOp {
        dst: tmp_ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::VReg(idx),
    });
    func.block_mut(ok).instructions.push(MirInst::Load {
        dst,
        ptr: tmp_ptr,
        offset: 0,
        ty: MirType::I8,
    });
    func.block_mut(ok).terminator = MirInst::Return { val: None };

    func.block_mut(bad).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        tmp_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I8);

    verify_mir(&func, &types).expect("expected vreg compare to refine range");
}

#[test]
fn test_uninitialized_scalar_use_rejected() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let lhs = func.alloc_vreg();
    let rhs = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: rhs,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(lhs),
        rhs: MirValue::VReg(rhs),
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected uninitialized-use error");
    assert!(err.iter().any(|e| e.message.contains("uninitialized v")));
}

#[test]
fn test_uninitialized_branch_cond_rejected() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let left = func.alloc_block();
    let right = func.alloc_block();
    func.entry = entry;

    let cond = func.alloc_vreg();
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: left,
        if_false: right,
    };
    func.block_mut(left).terminator = MirInst::Return { val: None };
    func.block_mut(right).terminator = MirInst::Return { val: None };

    let types = HashMap::new();
    let err = verify_mir(&func, &types).expect_err("expected uninitialized branch cond error");
    assert!(err.iter().any(|e| e.message.contains("uninitialized v")));
}

#[test]
fn test_helper_kptr_xchg_allows_null_const_arg1() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let dst_ptr = func.alloc_vreg();
    let dst_non_null = func.alloc_vreg();
    let swapped = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: dst_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(dst_ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: dst_non_null,
        if_true: call,
        if_false: done,
    };
    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: swapped,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::Const(0)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(dst_non_null, MirType::Bool);
    types.insert(
        swapped,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    verify_mir(&func, &types).expect("expected kptr_xchg null-pointer arg acceptance");
}

#[test]
fn test_helper_kptr_xchg_rejects_non_null_scalar_arg1() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let dst_ptr = func.alloc_vreg();
    let dst_non_null = func.alloc_vreg();
    let swapped = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: dst_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(dst_ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: dst_non_null,
        if_true: call,
        if_false: done,
    };
    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: swapped,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::Const(1)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(dst_non_null, MirType::Bool);
    types.insert(
        swapped,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected helper pointer-arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 194 arg1 expects pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_kptr_xchg_rejects_non_map_dst_arg0() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let dst_ptr = func.alloc_vreg();
    let swapped = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: swapped,
            helper: BpfHelper::KptrXchg as u32,
            args: vec![MirValue::VReg(dst_ptr), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        swapped,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err =
        verify_mir(&func, &types).expect_err("expected kptr_xchg map-pointer destination error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper kptr_xchg dst expects pointer in [Map]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_kptr_xchg_transfers_reference_and_releases_old_value() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let acquire = func.alloc_block();
    let swap = func.alloc_block();
    let release_old = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let dst_ptr = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let dst_non_null = func.alloc_vreg();
    let swapped = func.alloc_vreg();
    let swapped_non_null = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: dst_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(dst_ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: dst_non_null,
        if_true: acquire,
        if_false: done,
    };

    func.block_mut(acquire).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(acquire)
        .instructions
        .push(MirInst::CallKfunc {
            dst: task,
            kfunc: "bpf_task_from_pid".to_string(),
            btf_id: None,
            args: vec![pid],
        });
    func.block_mut(acquire).instructions.push(MirInst::BinOp {
        dst: task_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(acquire).terminator = MirInst::Branch {
        cond: task_non_null,
        if_true: swap,
        if_false: done,
    };

    func.block_mut(swap).instructions.push(MirInst::CallHelper {
        dst: swapped,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::VReg(task)],
    });
    func.block_mut(swap).instructions.push(MirInst::BinOp {
        dst: swapped_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(swapped),
        rhs: MirValue::Const(0),
    });
    func.block_mut(swap).terminator = MirInst::Branch {
        cond: swapped_non_null,
        if_true: release_old,
        if_false: done,
    };

    func.block_mut(release_old)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![swapped],
        });
    func.block_mut(release_old).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(task_non_null, MirType::Bool);
    types.insert(dst_non_null, MirType::Bool);
    types.insert(
        swapped,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(swapped_non_null, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected kptr_xchg transfer/release semantics");
}

#[test]
fn test_helper_sk_lookup_release_socket_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let lookup = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let ctx = func.alloc_vreg();
    let ctx_non_null = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ctx_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: ctx_non_null,
        if_true: lookup,
        if_false: done,
    };

    func.block_mut(lookup)
        .instructions
        .push(MirInst::CallHelper {
            dst: sock,
            helper: BpfHelper::SkLookupTcp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(tuple_slot),
                MirValue::Const(16),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(lookup).instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(lookup).terminator = MirInst::Branch {
        cond: sock_non_null,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallHelper {
            dst: release_ret,
            helper: BpfHelper::SkRelease as u32,
            args: vec![MirValue::VReg(sock)],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(ctx_non_null, MirType::Bool);
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(sock_non_null, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected sk_lookup/sk_release socket lifetime to verify");
}

#[test]
fn test_helper_sk_release_rejects_non_socket_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let bad_release_ret = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: task_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: task_non_null,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallHelper {
            dst: bad_release_ret,
            helper: BpfHelper::SkRelease as u32,
            args: vec![MirValue::VReg(task)],
        });
    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: cleanup_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(task_non_null, MirType::Bool);
    types.insert(bad_release_ret, MirType::I64);
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected sk_release ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 86 arg0 expects acquired socket reference, got task reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_sk_lookup_leak_is_rejected() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let leak = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let ctx = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sock,
            helper: BpfHelper::SkLookupUdp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(tuple_slot),
                MirValue::Const(16),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: sock_non_null,
        if_true: leak,
        if_false: done,
    };

    func.block_mut(leak).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(sock_non_null, MirType::Bool);

    let err = verify_mir(&func, &types).expect_err("expected leaked socket reference error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("unreleased kfunc reference at function exit")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_unknown_signature_rejected() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let arg = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: arg,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "unknown_kfunc".to_string(),
        btf_id: None,
        args: vec![arg],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(arg, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unknown-kfunc verifier error");
    assert!(err.iter().any(|e| e.message.contains("unknown kfunc")));
}

#[test]
fn test_kfunc_pointer_argument_required() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let scalar = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: scalar,
        src: MirValue::Const(42),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_task_release".to_string(),
        btf_id: None,
        args: vec![scalar],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(scalar, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected kfunc pointer-arg error");
    assert!(err.iter().any(|e| e.message.contains("expects pointer")));
}

#[test]
fn test_kfunc_pointer_argument_requires_kernel_space() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task_ptr = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: acquired,
        kfunc: "bpf_task_acquire".to_string(),
        btf_id: None,
        args: vec![task_ptr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        acquired,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected kernel-pointer kfunc arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_list_push_front_requires_kernel_space() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let stack_ptr = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let off = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_list_push_front_impl".to_string(),
        btf_id: None,
        args: vec![stack_ptr, stack_ptr, meta, off],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        stack_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(meta, MirType::I64);
    types.insert(off, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected kernel-pointer kfunc arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_path_d_path_requires_kernel_path_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let stack_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(32),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_path_d_path".to_string(),
        btf_id: None,
        args: vec![stack_ptr, stack_ptr, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        stack_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected kernel-pointer kfunc arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_rbtree_first_requires_kernel_space() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let stack_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_rbtree_first".to_string(),
        btf_id: None,
        args: vec![stack_ptr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        stack_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected kernel-pointer kfunc arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_cpumask_and_requires_pointer_args() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let cpumask = func.alloc_vreg();
    let scalar = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: scalar,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_cpumask_and".to_string(),
        btf_id: None,
        args: vec![cpumask, scalar, cpumask],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        cpumask,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(scalar, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected cpumask pointer-arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_task_acquire_rejects_cgroup_reference_argument() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let cgid = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let acquired_task = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cgid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![cgid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: acquired_task,
        kfunc: "bpf_task_acquire".to_string(),
        btf_id: None,
        args: vec![cgroup],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cgid, MirType::I64);
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        acquired_task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected kfunc provenance mismatch error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects task reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_get_task_exe_file_rejects_cgroup_reference_argument() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let cgid = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let file = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cgid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![cgid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: file,
        kfunc: "bpf_get_task_exe_file".to_string(),
        btf_id: None,
        args: vec![cgroup],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cgid, MirType::I64);
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        file,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected kfunc provenance mismatch error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects task reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_get_task_exe_file_requires_null_check_for_tracked_task_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let file = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: file,
        kfunc: "bpf_get_task_exe_file".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        file,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected tracked-ref null-check error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 may dereference null pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_task_under_cgroup_rejects_task_reference_for_cgroup_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let verdict = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: verdict,
        kfunc: "bpf_task_under_cgroup".to_string(),
        btf_id: None,
        args: vec![task, task],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(verdict, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected kfunc provenance mismatch error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_task_vma_new_rejects_cgroup_reference_for_task_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let it = func.alloc_vreg();
    let cgid = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let addr = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cgid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: addr,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![cgid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_task_vma_new".to_string(),
        btf_id: None,
        args: vec![it, cgroup, addr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        it,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(cgid, MirType::I64);
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(addr, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected kfunc provenance mismatch error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects task reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_task_acquire_release_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: acquired,
        kfunc: "bpf_task_acquire".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(acquired),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![acquired],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        acquired,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected kfunc reference to be released");
}

#[test]
fn test_kfunc_task_acquire_leak_rejected() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let leak = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    let cond = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: acquired,
        kfunc: "bpf_task_acquire".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(acquired),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: leak,
        if_false: done,
    };

    func.block_mut(leak).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        acquired,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected kfunc reference leak error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased kfunc reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_task_from_pid_release_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected task_from_pid reference to be released");
}

#[test]
fn test_kfunc_task_from_pid_release_semantics_via_copied_cond_with_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond0 = func.alloc_vreg();
    let cond1 = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let then_val = func.alloc_vreg();
    let else_val = func.alloc_vreg();
    let result = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond0,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cond1,
        src: MirValue::VReg(cond0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cond1,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).instructions.push(MirInst::Copy {
        dst: then_val,
        src: MirValue::Const(0),
    });
    func.block_mut(release).terminator = MirInst::Jump { target: join };

    func.block_mut(done).instructions.push(MirInst::Copy {
        dst: else_val,
        src: MirValue::Const(0),
    });
    func.block_mut(done).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::Phi {
        dst: result,
        args: vec![(release, then_val), (done, else_val)],
    });
    func.block_mut(join).terminator = MirInst::Return {
        val: Some(MirValue::VReg(result)),
    };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond0, MirType::Bool);
    types.insert(cond1, MirType::Bool);
    types.insert(release_ret, MirType::I64);
    types.insert(then_val, MirType::I64);
    types.insert(else_val, MirType::I64);
    types.insert(result, MirType::I64);

    verify_mir(&func, &types).expect("expected copied guard to preserve release semantics");
}

#[test]
fn test_kfunc_task_from_pid_release_semantics_via_negated_cond() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let negated = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::UnaryOp {
        dst: negated,
        op: crate::compiler::mir::UnaryOpKind::Not,
        src: MirValue::VReg(cond),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: negated,
        if_true: done,
        if_false: release,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(negated, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected negated guard to preserve release semantics");
}

#[test]
fn test_kfunc_cgroup_from_id_release_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let cgid = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cgid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![cgid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(cgroup),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_cgroup_release".to_string(),
            btf_id: None,
            args: vec![cgroup],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cgid, MirType::I64);
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected cgroup_from_id reference to be released");
}

#[test]
fn test_kfunc_cgroup_release_rejects_task_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_cgroup_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-reference error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("expects acquired cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_get_task_exe_file_put_file_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let file = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: file,
        kfunc: "bpf_get_task_exe_file".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(file),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_put_file".to_string(),
            btf_id: None,
            args: vec![file],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        file,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected file reference to be released");
}

#[test]
fn test_kfunc_put_file_rejects_task_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_put_file".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-reference error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("expects acquired file reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_cpumask_create_release_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let cpumask = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cpumask,
        kfunc: "bpf_cpumask_create".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(cpumask),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_cpumask_release".to_string(),
            btf_id: None,
            args: vec![cpumask],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        cpumask,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected cpumask reference to be released");
}

#[test]
fn test_kfunc_cpumask_release_rejects_task_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_cpumask_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-reference error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("expects acquired cpumask reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_obj_new_release_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let meta = func.alloc_vreg();
    let type_id = func.alloc_vreg();
    let obj = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: type_id,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: obj,
        kfunc: "bpf_obj_new_impl".to_string(),
        btf_id: None,
        args: vec![type_id, meta],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(obj),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_obj_drop_impl".to_string(),
            btf_id: None,
            args: vec![obj, meta],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(meta, MirType::I64);
    types.insert(type_id, MirType::I64);
    types.insert(
        obj,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected object reference to be released");
}

#[test]
fn test_kfunc_obj_drop_rejects_task_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let meta = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_obj_drop_impl".to_string(),
            btf_id: None,
            args: vec![task, meta],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(meta, MirType::I64);
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-reference error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("expects acquired object reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_percpu_obj_new_release_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let meta = func.alloc_vreg();
    let type_id = func.alloc_vreg();
    let obj = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: type_id,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: obj,
        kfunc: "bpf_percpu_obj_new_impl".to_string(),
        btf_id: None,
        args: vec![type_id, meta],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(obj),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_percpu_obj_drop_impl".to_string(),
            btf_id: None,
            args: vec![obj, meta],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(meta, MirType::I64);
    types.insert(type_id, MirType::I64);
    types.insert(
        obj,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected percpu object reference to be released");
}

#[test]
fn test_kfunc_percpu_obj_drop_rejects_task_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let meta = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_percpu_obj_drop_impl".to_string(),
            btf_id: None,
            args: vec![task, meta],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(meta, MirType::I64);
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-reference error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("expects acquired object reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_refcount_acquire_rejects_task_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let meta = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: acquired,
        kfunc: "bpf_refcount_acquire_impl".to_string(),
        btf_id: None,
        args: vec![task, meta],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(meta, MirType::I64);
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        acquired,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected kfunc provenance mismatch error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects object reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_task_release_requires_tracked_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected tracked-reference error");
    assert!(
        err.iter().any(|e| {
            e.message.contains("expects acquired task reference")
                || e.message.contains("expects acquired reference")
                || e.message.contains("reference already released")
        }),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_task_release_rejects_cgroup_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let cgid = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cgid,
        src: MirValue::Const(42),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![cgid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(cgroup),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![cgroup],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cgid, MirType::I64);
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-reference error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("expects acquired task reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_task_release_rejects_mixed_reference_kinds_after_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let task_path = func.alloc_block();
    let cgroup_path = func.alloc_block();
    let join = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let select_cond = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let cgid = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    let release_cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: select_cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: select_cond,
        if_true: task_path,
        if_false: cgroup_path,
    };

    func.block_mut(task_path).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(task_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: acquired,
            kfunc: "bpf_task_from_pid".to_string(),
            btf_id: None,
            args: vec![pid],
        });
    func.block_mut(task_path).terminator = MirInst::Jump { target: join };

    func.block_mut(cgroup_path)
        .instructions
        .push(MirInst::Copy {
            dst: cgid,
            src: MirValue::Const(42),
        });
    func.block_mut(cgroup_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: acquired,
            kfunc: "bpf_cgroup_from_id".to_string(),
            btf_id: None,
            args: vec![cgid],
        });
    func.block_mut(cgroup_path).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: release_cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(acquired),
        rhs: MirValue::Const(0),
    });
    func.block_mut(join).terminator = MirInst::Branch {
        cond: release_cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![acquired],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(select_cond, MirType::Bool);
    types.insert(pid, MirType::I64);
    types.insert(cgid, MirType::I64);
    types.insert(
        acquired,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-kind join release validation");
    assert!(
        err.iter()
            .any(|e| e.message.contains("expects acquired task reference")),
        "unexpected errors: {:?}",
        err
    );
}
