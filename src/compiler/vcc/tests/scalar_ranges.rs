use super::*;

#[test]
fn test_verify_mir_uninitialized_scalar_use_rejected() {
    let (mut func, entry) = new_mir_function();
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
    assert!(
        err.iter()
            .any(|e| matches!(e.kind, VccErrorKind::UseOfUninitializedReg(_))),
        "expected uninitialized-register error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_uninitialized_branch_cond_rejected() {
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

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected uninitialized branch cond");
    assert!(
        err.iter()
            .any(|e| matches!(e.kind, VccErrorKind::UseOfUninitializedReg(_))),
        "expected uninitialized-register error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_pointer_phi_preserves_bounds() {
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
fn test_verify_mir_not_equal_fact_prunes_followup_eq_branch() {
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
fn test_verify_mir_multiple_not_equal_facts_prune_followup_eq() {
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
fn test_verify_mir_compare_refines_true_branch_lt() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let join = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();
    func.entry = entry;

    let cond = func.alloc_vreg();
    func.param_count = 1;

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

    verify_mir(&func, &types).expect("expected compare to refine range");
}

#[test]
fn test_verify_mir_compare_refines_true_branch_ge() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let join = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();
    func.entry = entry;

    let cond = func.alloc_vreg();
    func.param_count = 1;

    let slot = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let cmp = func.alloc_vreg();
    let offset = func.alloc_vreg();
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

    verify_mir(&func, &types).expect("expected compare to refine range");
}

#[test]
fn test_verify_mir_compare_refines_vreg_bound() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let join = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();
    func.entry = entry;

    let cond = func.alloc_vreg();
    func.param_count = 1;

    let slot = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let bound = func.alloc_vreg();
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

    verify_mir(&func, &types).expect("expected vreg compare to refine range");
}

#[test]
fn test_verify_mir_div_range_with_non_zero_guard() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let join = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();
    func.entry = entry;

    let split = func.alloc_vreg();
    func.param_count = 1;
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
        cond: split,
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
    types.insert(split, MirType::I64);
    types.insert(
        tmp_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_mod_range_bounds() {
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
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_div_range_in_bounds_allows_ptr_access() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
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
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: offset,
        op: BinOpKind::Div,
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
        tmp_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected bounded division offset to pass");
}

#[test]
fn test_verify_mir_mod_range_in_bounds_allows_ptr_access() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
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

    verify_mir(&func, &types).expect("expected bounded modulo offset to pass");
}

#[test]
fn test_verify_mir_stack_pointer_offset_via_shift_out_of_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let base = func.alloc_vreg();
    let shift = func.alloc_vreg();
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
        dst: shift,
        src: MirValue::Const(2),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: offset,
        op: BinOpKind::Shl,
        lhs: MirValue::VReg(base),
        rhs: MirValue::VReg(shift),
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
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_and_or_xor_range_bounds() {
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
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}
