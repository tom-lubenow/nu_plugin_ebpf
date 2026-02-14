use super::*;
use crate::compiler::mir::BinOpKind;

#[test]
fn test_simple_copy_propagation() {
    // v0 = 42
    // v1 = v0       <- copy
    // v2 = v1 + 1   <- should become v0 + 1
    // return v2
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(42),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::VReg(v0),
    });
    func.block_mut(bb0).instructions.push(MirInst::BinOp {
        dst: v2,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v1),
        rhs: MirValue::Const(1),
    });
    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v2)),
    };

    let cfg = CFG::build(&func);
    let pass = CopyPropagation;
    let changed = pass.run(&mut func, &cfg);

    assert!(changed);

    // The BinOp should now use v0 instead of v1
    match &func.block(bb0).instructions[2] {
        MirInst::BinOp {
            lhs: MirValue::VReg(vreg),
            ..
        } => {
            assert_eq!(*vreg, v0, "Should have propagated v1 -> v0");
        }
        _ => panic!("Expected BinOp"),
    }
}

#[test]
fn test_transitive_copy_propagation() {
    // v0 = 42
    // v1 = v0
    // v2 = v1       <- transitive copy
    // v3 = v2 + 1   <- should become v0 + 1
    // return v3
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();
    let v3 = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(42),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::VReg(v0),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v2,
        src: MirValue::VReg(v1),
    });
    func.block_mut(bb0).instructions.push(MirInst::BinOp {
        dst: v3,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v2),
        rhs: MirValue::Const(1),
    });
    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v3)),
    };

    let cfg = CFG::build(&func);
    let pass = CopyPropagation;
    let changed = pass.run(&mut func, &cfg);

    assert!(changed);

    // The BinOp should now use v0 (resolved transitively through v2 -> v1 -> v0)
    match &func.block(bb0).instructions[3] {
        MirInst::BinOp {
            lhs: MirValue::VReg(vreg),
            ..
        } => {
            assert_eq!(*vreg, v0, "Should have transitively propagated v2 -> v0");
        }
        _ => panic!("Expected BinOp"),
    }
}

#[test]
fn test_propagate_in_terminator() {
    // v0 = 1
    // v1 = v0
    // branch v1 -> bb1, bb2   <- should become branch v0
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::VReg(v0),
    });
    func.block_mut(bb0).terminator = MirInst::Branch {
        cond: v1,
        if_true: bb1,
        if_false: bb2,
    };

    func.block_mut(bb1).terminator = MirInst::Return {
        val: Some(MirValue::Const(1)),
    };
    func.block_mut(bb2).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let cfg = CFG::build(&func);
    let pass = CopyPropagation;
    let changed = pass.run(&mut func, &cfg);

    assert!(changed);

    // The branch condition should now use v0
    match &func.block(bb0).terminator {
        MirInst::Branch { cond, .. } => {
            assert_eq!(*cond, v0, "Should have propagated v1 -> v0 in branch");
        }
        _ => panic!("Expected Branch"),
    }
}

#[test]
fn test_no_propagation_needed() {
    // v0 = 42
    // return v0   <- no copies to propagate
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(42),
    });
    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v0)),
    };

    let cfg = CFG::build(&func);
    let pass = CopyPropagation;
    let changed = pass.run(&mut func, &cfg);

    assert!(!changed, "No vreg-to-vreg copies, so no changes");
}

#[test]
fn test_multiple_uses_propagated() {
    // v0 = 42
    // v1 = v0
    // v2 = v1 + v1   <- both uses should be propagated
    // return v2
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(42),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::VReg(v0),
    });
    func.block_mut(bb0).instructions.push(MirInst::BinOp {
        dst: v2,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v1),
        rhs: MirValue::VReg(v1),
    });
    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v2)),
    };

    let cfg = CFG::build(&func);
    let pass = CopyPropagation;
    let changed = pass.run(&mut func, &cfg);

    assert!(changed);

    // Both lhs and rhs should now use v0
    match &func.block(bb0).instructions[2] {
        MirInst::BinOp {
            lhs: MirValue::VReg(lhs_vreg),
            rhs: MirValue::VReg(rhs_vreg),
            ..
        } => {
            assert_eq!(*lhs_vreg, v0, "LHS should be propagated to v0");
            assert_eq!(*rhs_vreg, v0, "RHS should be propagated to v0");
        }
        _ => panic!("Expected BinOp with two VReg operands"),
    }
}

#[test]
fn test_propagate_in_return() {
    // v0 = 42
    // v1 = v0
    // return v1   <- should become return v0
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(42),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::VReg(v0),
    });
    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v1)),
    };

    let cfg = CFG::build(&func);
    let pass = CopyPropagation;
    let changed = pass.run(&mut func, &cfg);

    assert!(changed);

    // Return should now use v0
    match &func.block(bb0).terminator {
        MirInst::Return {
            val: Some(MirValue::VReg(vreg)),
        } => {
            assert_eq!(*vreg, v0, "Return should use v0");
        }
        _ => panic!("Expected Return with VReg"),
    }
}
