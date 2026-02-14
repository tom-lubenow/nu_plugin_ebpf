use super::*;

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
fn test_read_str_user_ptr_with_null_check_after_reloading_same_ctx_field() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ptr_for_cond = func.alloc_vreg();
    let ptr_for_read = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ptr_for_cond,
            field: CtxField::TracepointField("filename".to_string()),
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr_for_cond),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ptr_for_read,
            field: CtxField::TracepointField("filename".to_string()),
            slot: None,
        });
    func.block_mut(call).instructions.push(MirInst::ReadStr {
        dst: slot,
        ptr: ptr_for_read,
        user_space: true,
        max_len: 16,
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    for ptr in [ptr_for_cond, ptr_for_read] {
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::User,
            },
        );
    }
    types.insert(cond, MirType::Bool);

    verify_mir(&func, &types).expect("expected context-field null check to flow to reloaded field");
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
