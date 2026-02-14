use super::*;

#[test]
fn test_pass_manager_creation() {
    let pm = PassManager::new();
    assert!(pm.passes.is_empty());
}

#[test]
fn test_default_passes() {
    let pm = default_passes();
    assert!(!pm.passes.is_empty());
}

#[test]
fn test_run_passes() {
    let pm = default_passes();
    let mut func = make_simple_function();

    // Should run without error
    let _changes = pm.run(&mut func);

    // Function should still be valid
    assert!(!func.blocks.is_empty());
    assert!(func.block(func.entry).terminator.is_terminator());
}

#[test]
fn test_pass_manager_rebuilds_cfg_between_passes() {
    // bb0: branch v0 -> bb1, bb2
    // bb1: jump bb3 (empty forwarding block)
    // bb2: jump bb3 (empty forwarding block)
    // bb3: return 0
    //
    // BranchOptimization threads bb1/bb2 to bb3 and rewrites bb0 to Jump bb3.
    // DCE should then remove now-unreachable bb1/bb2 in the same iteration.
    // This requires CFG rebuild between passes (not just between iterations).
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    let bb3 = func.alloc_block();
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
    func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };
    func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };
    func.block_mut(bb3).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    // Single iteration: if CFG were stale across passes, DCE would miss bb1/bb2.
    let mut pm = PassManager::new().with_max_iterations(1);
    pm.add_pass(BranchOptimization);
    pm.add_pass(DeadCodeElimination);
    let _changes = pm.run(&mut func);

    assert!(matches!(
        func.block(bb0).terminator,
        MirInst::Jump { target } if target == bb3
    ));
    assert_eq!(
        func.blocks.len(),
        2,
        "DCE should remove bb1/bb2 using fresh CFG in the same iteration"
    );
    assert!(!func.has_block(bb1));
    assert!(!func.has_block(bb2));
}

#[test]
fn test_optimize_with_ssa_simple() {
    let mut func = make_simple_function();

    // Should run without error
    let _changes = optimize_with_ssa(&mut func);

    // Function should still be valid
    assert!(!func.blocks.is_empty());
    assert!(func.block(func.entry).terminator.is_terminator());

    // Should have no phi functions after SSA destruction
    for block in &func.blocks {
        for inst in &block.instructions {
            assert!(
                !matches!(inst, MirInst::Phi { .. }),
                "Phi should be eliminated after SSA destruction"
            );
        }
    }
}

#[test]
fn test_optimize_with_ssa_diamond() {
    use crate::compiler::mir::BinOpKind;

    // Create diamond CFG that will need a phi
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    let bb3 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    // bb0: v0 = 1; branch v0 -> bb1, bb2
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).terminator = MirInst::Branch {
        cond: v0,
        if_true: bb1,
        if_false: bb2,
    };

    // bb1: v1 = v0 + 1; jump bb3
    func.block_mut(bb1).instructions.push(MirInst::BinOp {
        dst: v1,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::Const(1),
    });
    func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

    // bb2: v1 = v0 - 1; jump bb3
    func.block_mut(bb2).instructions.push(MirInst::BinOp {
        dst: v1,
        op: BinOpKind::Sub,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::Const(1),
    });
    func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

    // bb3: return v1
    func.block_mut(bb3).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v1)),
    };

    // Run SSA optimization pipeline
    let changes = optimize_with_ssa(&mut func);
    assert!(
        changes > 0,
        "Should have made changes (SSA construction + destruction)"
    );

    // Should have no phi functions after SSA destruction
    for block in &func.blocks {
        for inst in &block.instructions {
            assert!(
                !matches!(inst, MirInst::Phi { .. }),
                "Phi should be eliminated after SSA destruction"
            );
        }
    }

    // Function should still be valid
    assert!(!func.blocks.is_empty());
}
