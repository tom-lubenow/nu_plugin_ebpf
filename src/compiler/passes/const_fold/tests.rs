use super::*;

fn make_constant_add_function() -> MirFunction {
    // v0 = 2
    // v1 = 3
    // v2 = v0 + v1  <- should fold to v2 = 5
    // return v2
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(2),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::Const(3),
    });
    func.block_mut(bb0).instructions.push(MirInst::BinOp {
        dst: v2,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::VReg(v1),
    });
    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v2)),
    };

    func
}

fn make_constant_branch_function() -> MirFunction {
    // v0 = 1
    // if v0 goto bb1 else bb2  <- should fold to: goto bb1
    // bb1: return 1
    // bb2: return 0 (unreachable)
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).terminator = MirInst::Branch {
        cond: v0,
        if_true: bb1,
        if_false: bb2,
    };

    func.block_mut(bb1).terminator = MirInst::Return {
        val: Some(MirValue::Const(1)),
    };
    func.block_mut(bb2).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    func
}

fn make_phi_constant_function() -> MirFunction {
    // bb0: c = helper(); branch c -> bb1, bb2
    // bb1: v1 = 5; jump bb3
    // bb2: v2 = 5; jump bb3
    // bb3: v3 = phi(v1:bb1, v2:bb2); v4 = v3 + 1; return v4
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    let bb3 = func.alloc_block();
    func.entry = bb0;

    let cond = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();
    let v3 = func.alloc_vreg();
    let v4 = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::CallHelper {
        dst: cond,
        helper: 14,
        args: vec![],
    });
    func.block_mut(bb0).terminator = MirInst::Branch {
        cond,
        if_true: bb1,
        if_false: bb2,
    };

    func.block_mut(bb1).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::Const(5),
    });
    func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

    func.block_mut(bb2).instructions.push(MirInst::Copy {
        dst: v2,
        src: MirValue::Const(5),
    });
    func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

    func.block_mut(bb3).instructions.push(MirInst::Phi {
        dst: v3,
        args: vec![(bb1, v1), (bb2, v2)],
    });
    func.block_mut(bb3).instructions.push(MirInst::BinOp {
        dst: v4,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v3),
        rhs: MirValue::Const(1),
    });
    func.block_mut(bb3).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v4)),
    };

    func
}

#[test]
fn test_fold_constant_add() {
    let mut func = make_constant_add_function();
    let cfg = CFG::build(&func);
    let cf = ConstantFolding;

    let changed = cf.run(&mut func, &cfg);

    assert!(changed);

    // The third instruction should now be: v2 = 5
    let block = func.block(func.entry);
    match &block.instructions[2] {
        MirInst::Copy {
            dst: _,
            src: MirValue::Const(5),
        } => {}
        other => panic!("Expected Copy with const 5, got {:?}", other),
    }
}

#[test]
fn test_fold_constant_branch() {
    let mut func = make_constant_branch_function();
    let cfg = CFG::build(&func);
    let cf = ConstantFolding;

    let changed = cf.run(&mut func, &cfg);

    assert!(changed);

    // The entry terminator should now be: Jump { target: bb1 }
    let block = func.block(func.entry);
    match &block.terminator {
        MirInst::Jump { target } => {
            assert_eq!(*target, BlockId(1)); // bb1
        }
        other => panic!("Expected Jump, got {:?}", other),
    }

    // bb2 should be removed as unreachable.
    assert_eq!(func.blocks.len(), 2);
    assert!(!func.has_block(BlockId(2)));
}

#[test]
fn test_phi_driven_constant_propagation() {
    let mut func = make_phi_constant_function();
    let cfg = CFG::build(&func);
    let cf = ConstantFolding;

    let changed = cf.run(&mut func, &cfg);
    assert!(changed);

    let bb3 = func.block(BlockId(3));
    match &bb3.instructions[0] {
        MirInst::Copy {
            src: MirValue::Const(5),
            ..
        } => {}
        other => panic!("Expected phi to fold to const copy, got {:?}", other),
    }

    match &bb3.instructions[1] {
        MirInst::Copy {
            src: MirValue::Const(6),
            ..
        } => {}
        other => panic!("Expected add to fold to const copy, got {:?}", other),
    }

    match &bb3.terminator {
        MirInst::Return {
            val: Some(MirValue::Const(6)),
        } => {}
        other => panic!("Expected return const 6, got {:?}", other),
    }
}

#[test]
fn test_all_binops() {
    let cf = ConstantFolding;

    // Test various operations
    assert_eq!(cf.eval_binop(BinOpKind::Add, 5, 3), Some(8));
    assert_eq!(cf.eval_binop(BinOpKind::Sub, 5, 3), Some(2));
    assert_eq!(cf.eval_binop(BinOpKind::Mul, 5, 3), Some(15));
    assert_eq!(cf.eval_binop(BinOpKind::Div, 6, 2), Some(3));
    assert_eq!(cf.eval_binop(BinOpKind::Div, 5, 0), None); // Division by zero
    assert_eq!(cf.eval_binop(BinOpKind::Mod, 7, 3), Some(1));
    assert_eq!(cf.eval_binop(BinOpKind::And, 0b1010, 0b1100), Some(0b1000));
    assert_eq!(cf.eval_binop(BinOpKind::Or, 0b1010, 0b1100), Some(0b1110));
    assert_eq!(cf.eval_binop(BinOpKind::Xor, 0b1010, 0b1100), Some(0b0110));
    assert_eq!(cf.eval_binop(BinOpKind::Eq, 5, 5), Some(1));
    assert_eq!(cf.eval_binop(BinOpKind::Eq, 5, 3), Some(0));
    assert_eq!(cf.eval_binop(BinOpKind::Lt, 3, 5), Some(1));
    assert_eq!(cf.eval_binop(BinOpKind::Lt, 5, 3), Some(0));
}

#[test]
fn test_unary_ops() {
    let cf = ConstantFolding;

    assert_eq!(cf.eval_unaryop(UnaryOpKind::Not, 0), Some(1));
    assert_eq!(cf.eval_unaryop(UnaryOpKind::Not, 1), Some(0));
    assert_eq!(cf.eval_unaryop(UnaryOpKind::Not, 42), Some(0));
    assert_eq!(cf.eval_unaryop(UnaryOpKind::Neg, 5), Some(-5));
    assert_eq!(cf.eval_unaryop(UnaryOpKind::BitNot, 0), Some(-1));
}
