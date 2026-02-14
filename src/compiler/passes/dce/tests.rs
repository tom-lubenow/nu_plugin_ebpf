use super::*;
use crate::compiler::mir::{BinOpKind, MirInst, MirValue};

fn make_function_with_dead_code() -> MirFunction {
    // v0 = 1
    // v1 = 2  <- dead (never used)
    // v2 = v0 + 1
    // return v2
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::Const(2), // Dead!
    });
    func.block_mut(bb0).instructions.push(MirInst::BinOp {
        dst: v2,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::Const(1),
    });
    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v2)),
    };

    func
}

fn make_function_with_unreachable() -> MirFunction {
    // bb0: return 0
    // bb1: v0 = 1; return v0  <- unreachable
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    func.entry = bb0;

    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let v0 = func.alloc_vreg();
    func.block_mut(bb1).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(1),
    });
    func.block_mut(bb1).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v0)),
    };

    func
}

#[test]
fn test_remove_dead_instruction() {
    let mut func = make_function_with_dead_code();
    let cfg = CFG::build(&func);
    let dce = DeadCodeElimination;

    assert_eq!(func.block(func.entry).instructions.len(), 3);

    let changed = dce.run(&mut func, &cfg);

    assert!(changed);
    // Should have removed the dead v1 = 2 instruction
    assert_eq!(func.block(func.entry).instructions.len(), 2);
}

#[test]
fn test_remove_unreachable_block() {
    let mut func = make_function_with_unreachable();
    let cfg = CFG::build(&func);
    let dce = DeadCodeElimination;

    assert_eq!(func.blocks.len(), 2);

    let changed = dce.run(&mut func, &cfg);

    assert!(changed);
    // Should have removed bb1
    assert_eq!(func.blocks.len(), 1);
}

#[test]
fn test_no_changes_needed() {
    // v0 = 1
    // return v0  <- v0 is used, nothing to remove
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v0)),
    };

    let cfg = CFG::build(&func);
    let dce = DeadCodeElimination;

    let changed = dce.run(&mut func, &cfg);

    assert!(!changed);
    assert_eq!(func.block(func.entry).instructions.len(), 1);
}
