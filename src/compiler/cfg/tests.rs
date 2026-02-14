use super::*;
use crate::compiler::mir::{MirInst, MirValue};

fn make_test_function() -> MirFunction {
    // Create a simple function:
    // bb0: v0 = 1; if v0 goto bb1 else bb2
    // bb1: v1 = v0 + 1; goto bb3
    // bb2: v1 = v0 - 1; goto bb3
    // bb3: return v1

    let mut func = MirFunction::new();

    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    let bb3 = func.alloc_block();

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
        op: super::super::mir::BinOpKind::Add,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::Const(1),
    });
    func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

    // bb2
    func.block_mut(bb2).instructions.push(MirInst::BinOp {
        dst: v1,
        op: super::super::mir::BinOpKind::Sub,
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

#[test]
fn test_cfg_construction() {
    let func = make_test_function();
    let cfg = CFG::build(&func);

    // Check successors
    assert_eq!(cfg.successors.get(&BlockId(0)).unwrap().len(), 2);
    assert_eq!(cfg.successors.get(&BlockId(1)).unwrap(), &vec![BlockId(3)]);
    assert_eq!(cfg.successors.get(&BlockId(2)).unwrap(), &vec![BlockId(3)]);
    assert!(cfg.successors.get(&BlockId(3)).unwrap().is_empty());

    // Check predecessors
    assert!(cfg.predecessors.get(&BlockId(0)).unwrap().is_empty());
    assert_eq!(cfg.predecessors.get(&BlockId(3)).unwrap().len(), 2);
}

#[test]
fn test_dominators() {
    let func = make_test_function();
    let cfg = CFG::build(&func);

    // bb0 dominates everything
    assert!(cfg.dominates(BlockId(0), BlockId(0)));
    assert!(cfg.dominates(BlockId(0), BlockId(1)));
    assert!(cfg.dominates(BlockId(0), BlockId(2)));
    assert!(cfg.dominates(BlockId(0), BlockId(3)));

    // bb1 and bb2 don't dominate bb3 (both paths lead to bb3)
    assert!(!cfg.dominates(BlockId(1), BlockId(3)));
    assert!(!cfg.dominates(BlockId(2), BlockId(3)));
}

#[test]
fn test_dominance_frontiers() {
    let func = make_test_function();
    let cfg = CFG::build(&func);

    // In a diamond CFG (bb0 branches to bb1/bb2, both jump to bb3):
    // - DF(bb0) = {} (entry dominates everything)
    // - DF(bb1) = {bb3} (bb1 dominates itself, but at bb3 control can come from bb2)
    // - DF(bb2) = {bb3} (bb2 dominates itself, but at bb3 control can come from bb1)
    // - DF(bb3) = {} (bb3 has no successors)

    assert!(cfg.dominance_frontier(BlockId(0)).is_empty());
    assert!(cfg.dominance_frontier(BlockId(1)).contains(&BlockId(3)));
    assert!(cfg.dominance_frontier(BlockId(2)).contains(&BlockId(3)));
    assert!(cfg.dominance_frontier(BlockId(3)).is_empty());
}

#[test]
fn test_liveness_analysis() {
    let func = make_test_function();
    let cfg = CFG::build(&func);
    let liveness = LivenessInfo::compute(&func, &cfg);

    // v0 should be live in bb1 and bb2 (used there)
    assert!(
        liveness
            .live_in
            .get(&BlockId(1))
            .unwrap()
            .contains(&VReg(0))
    );
    assert!(
        liveness
            .live_in
            .get(&BlockId(2))
            .unwrap()
            .contains(&VReg(0))
    );

    // v1 should be live in bb3 (used in return)
    assert!(
        liveness
            .live_in
            .get(&BlockId(3))
            .unwrap()
            .contains(&VReg(1))
    );
}

#[test]
fn test_live_intervals() {
    let func = make_test_function();
    let cfg = CFG::build(&func);
    let liveness = LivenessInfo::compute(&func, &cfg);
    let intervals = compute_live_intervals(&func, &cfg, &liveness);

    // Should have intervals for v0 and v1
    assert_eq!(intervals.len(), 2);

    // v0 should start before v1
    let v0_interval = intervals.iter().find(|i| i.vreg.0 == 0).unwrap();
    let v1_interval = intervals.iter().find(|i| i.vreg.0 == 1).unwrap();
    assert!(v0_interval.start <= v1_interval.start);
}
