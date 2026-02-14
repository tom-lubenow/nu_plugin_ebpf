
use super::*;
use crate::compiler::mir::MirValue;

#[test]
fn test_same_target_branch() {
    // bb0: branch v0 -> bb1, bb1  (should become: jump bb1)
    // bb1: return 0
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).terminator = MirInst::Branch {
        cond: v0,
        if_true: bb1,
        if_false: bb1, // Same target!
    };

    func.block_mut(bb1).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let cfg = CFG::build(&func);
    let pass = BranchOptimization;
    let changed = pass.run(&mut func, &cfg);

    assert!(changed);

    // Should now be a simple jump
    match &func.block(bb0).terminator {
        MirInst::Jump { target } => {
            assert_eq!(*target, bb1);
        }
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_jump_threading() {
    // bb0: jump bb1
    // bb1: jump bb2  (empty block)
    // bb2: return 0
    //
    // Should become: bb0: jump bb2
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    func.entry = bb0;

    func.block_mut(bb0).terminator = MirInst::Jump { target: bb1 };
    func.block_mut(bb1).terminator = MirInst::Jump { target: bb2 }; // Empty block, just jump
    func.block_mut(bb2).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let cfg = CFG::build(&func);
    let pass = BranchOptimization;
    let changed = pass.run(&mut func, &cfg);

    assert!(changed);

    // bb0 should now jump directly to bb2
    match &func.block(bb0).terminator {
        MirInst::Jump { target } => {
            assert_eq!(*target, bb2, "Should thread through bb1 to bb2");
        }
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_branch_threading() {
    // bb0: v0 = 1; branch v0 -> bb1, bb2
    // bb1: jump bb3  (empty)
    // bb2: return 1
    // bb3: return 0
    //
    // Should thread bb1 -> bb3 in the branch
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

    func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 }; // Empty, just jump
    func.block_mut(bb2).terminator = MirInst::Return {
        val: Some(MirValue::Const(1)),
    };
    func.block_mut(bb3).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let cfg = CFG::build(&func);
    let pass = BranchOptimization;
    let changed = pass.run(&mut func, &cfg);

    assert!(changed);

    // Branch should now go directly to bb3 for if_true
    match &func.block(bb0).terminator {
        MirInst::Branch {
            if_true, if_false, ..
        } => {
            assert_eq!(*if_true, bb3, "if_true should be threaded to bb3");
            assert_eq!(*if_false, bb2, "if_false should remain bb2");
        }
        other => panic!("Expected Branch, got {:?}", other),
    }
}

#[test]
fn test_chain_threading() {
    // bb0: jump bb1
    // bb1: jump bb2  (empty)
    // bb2: jump bb3  (empty)
    // bb3: return 0
    //
    // Should thread all the way to bb3
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    let bb3 = func.alloc_block();
    func.entry = bb0;

    func.block_mut(bb0).terminator = MirInst::Jump { target: bb1 };
    func.block_mut(bb1).terminator = MirInst::Jump { target: bb2 };
    func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };
    func.block_mut(bb3).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let cfg = CFG::build(&func);
    let pass = BranchOptimization;
    let changed = pass.run(&mut func, &cfg);

    assert!(changed);

    // bb0 should jump directly to bb3
    match &func.block(bb0).terminator {
        MirInst::Jump { target } => {
            assert_eq!(*target, bb3, "Should thread through entire chain to bb3");
        }
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_no_threading_with_instructions() {
    // bb0: jump bb1
    // bb1: v0 = 1; jump bb2  (has instructions, should NOT thread)
    // bb2: return v0
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();

    func.block_mut(bb0).terminator = MirInst::Jump { target: bb1 };
    func.block_mut(bb1).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(1),
    });
    func.block_mut(bb1).terminator = MirInst::Jump { target: bb2 };
    func.block_mut(bb2).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v0)),
    };

    let cfg = CFG::build(&func);
    let pass = BranchOptimization;
    let changed = pass.run(&mut func, &cfg);

    // Should NOT change - bb1 has instructions
    assert!(!changed);

    match &func.block(bb0).terminator {
        MirInst::Jump { target } => {
            assert_eq!(
                *target, bb1,
                "Should NOT thread past bb1 (has instructions)"
            );
        }
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_no_change_needed() {
    // bb0: jump bb1
    // bb1: return 0  (not a jump, can't thread)
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    func.entry = bb0;

    func.block_mut(bb0).terminator = MirInst::Jump { target: bb1 };
    func.block_mut(bb1).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let cfg = CFG::build(&func);
    let pass = BranchOptimization;
    let changed = pass.run(&mut func, &cfg);

    assert!(!changed, "No threading possible");
}
