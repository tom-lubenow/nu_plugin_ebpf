use super::*;
use crate::compiler::mir::{BinOpKind, MirValue};

fn make_diamond_function() -> MirFunction {
    // bb0: v0 = 1; branch v0 -> bb1, bb2
    // bb1: v1 = v0 + 1; jump bb3
    // bb2: v1 = v0 - 1; jump bb3  <- v1 defined in both paths
    // bb3: return v1              <- needs phi for v1

    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    let bb3 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    // bb0
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).terminator = MirInst::Branch {
        cond: v0,
        if_true: bb1,
        if_false: bb2,
    };

    // bb1
    func.block_mut(bb1).instructions.push(MirInst::BinOp {
        dst: v1,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::Const(1),
    });
    func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

    // bb2
    func.block_mut(bb2).instructions.push(MirInst::BinOp {
        dst: v1,
        op: BinOpKind::Sub,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::Const(1),
    });
    func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

    // bb3
    func.block_mut(bb3).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v1)),
    };

    func
}

fn make_loop_function() -> MirFunction {
    // bb0: v0 = 0; jump bb1
    // bb1: v0 = v0 + 1; branch v0 -> bb1, bb2  <- loop, v0 defined inside
    // bb2: return v0

    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();

    // bb0
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(0),
    });
    func.block_mut(bb0).terminator = MirInst::Jump { target: bb1 };

    // bb1 - loop body
    func.block_mut(bb1).instructions.push(MirInst::BinOp {
        dst: v0,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::Const(1),
    });
    func.block_mut(bb1).terminator = MirInst::Branch {
        cond: v0,
        if_true: bb1,
        if_false: bb2,
    };

    // bb2
    func.block_mut(bb2).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v0)),
    };

    func
}

#[test]
fn test_phi_insertion_diamond() {
    let mut func = make_diamond_function();
    let cfg = CFG::build(&func);

    let pass = SsaConstruction;
    let changed = pass.run(&mut func, &cfg);

    assert!(changed);

    // bb3 should have a phi for v1
    let bb3 = func.block(BlockId(3));
    let has_phi = bb3
        .instructions
        .iter()
        .any(|inst| matches!(inst, MirInst::Phi { .. }));
    assert!(has_phi, "bb3 should have a phi function");
}

#[test]
fn test_phi_insertion_loop() {
    let mut func = make_loop_function();
    let cfg = CFG::build(&func);

    let pass = SsaConstruction;
    let changed = pass.run(&mut func, &cfg);

    assert!(changed);

    // bb1 should have a phi for v0 (loop header)
    let bb1 = func.block(BlockId(1));
    let has_phi = bb1
        .instructions
        .iter()
        .any(|inst| matches!(inst, MirInst::Phi { .. }));
    assert!(has_phi, "bb1 (loop header) should have a phi function");
}

#[test]
fn test_ssa_unique_definitions() {
    let mut func = make_diamond_function();
    let cfg = CFG::build(&func);

    let pass = SsaConstruction;
    pass.run(&mut func, &cfg);

    // After SSA, each vreg should be defined at most once
    let mut def_counts: HashMap<VReg, usize> = HashMap::new();

    for block in &func.blocks {
        for inst in &block.instructions {
            if let Some(vreg) = inst.def() {
                *def_counts.entry(vreg).or_insert(0) += 1;
            }
        }
    }

    for (vreg, count) in &def_counts {
        assert_eq!(
            *count, 1,
            "VReg {:?} should be defined exactly once, but was defined {} times",
            vreg, count
        );
    }
}

#[test]
fn test_phi_args_from_predecessors() {
    let mut func = make_diamond_function();
    let cfg = CFG::build(&func);

    let pass = SsaConstruction;
    pass.run(&mut func, &cfg);

    // Find the phi in bb3
    let bb3 = func.block(BlockId(3));
    let phi = bb3
        .instructions
        .iter()
        .find(|inst| matches!(inst, MirInst::Phi { .. }));

    if let Some(MirInst::Phi { args, .. }) = phi {
        // Should have 2 arguments (from bb1 and bb2)
        assert_eq!(args.len(), 2, "Phi should have 2 arguments");

        // Check that args come from the correct predecessors
        let pred_blocks: HashSet<_> = args.iter().map(|(block, _)| *block).collect();
        assert!(pred_blocks.contains(&BlockId(1)));
        assert!(pred_blocks.contains(&BlockId(2)));
    } else {
        panic!("Expected phi in bb3");
    }
}
