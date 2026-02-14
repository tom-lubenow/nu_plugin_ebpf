
use super::*;
use crate::compiler::mir::BinOpKind;

fn make_ssa_function() -> MirFunction {
    // This represents a diamond CFG after SSA construction:
    // bb0: v0_1 = 1; branch v0_1 -> bb1, bb2
    // bb1: v1_1 = v0_1 + 1; jump bb3
    // bb2: v1_2 = v0_1 - 1; jump bb3
    // bb3: v1_3 = phi(v1_1:bb1, v1_2:bb2); return v1_3

    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    let bb3 = func.alloc_block();
    func.entry = bb0;

    let v0_1 = func.alloc_vreg(); // v0_1
    let v1_1 = func.alloc_vreg(); // v1_1
    let v1_2 = func.alloc_vreg(); // v1_2
    let v1_3 = func.alloc_vreg(); // v1_3 (phi result)

    // bb0
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0_1,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).terminator = MirInst::Branch {
        cond: v0_1,
        if_true: bb1,
        if_false: bb2,
    };

    // bb1
    func.block_mut(bb1).instructions.push(MirInst::BinOp {
        dst: v1_1,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v0_1),
        rhs: MirValue::Const(1),
    });
    func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

    // bb2
    func.block_mut(bb2).instructions.push(MirInst::BinOp {
        dst: v1_2,
        op: BinOpKind::Sub,
        lhs: MirValue::VReg(v0_1),
        rhs: MirValue::Const(1),
    });
    func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

    // bb3 with phi
    func.block_mut(bb3).instructions.push(MirInst::Phi {
        dst: v1_3,
        args: vec![(bb1, v1_1), (bb2, v1_2)],
    });
    func.block_mut(bb3).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v1_3)),
    };

    func
}

#[test]
fn test_phi_elimination() {
    let mut func = make_ssa_function();
    let cfg = CFG::build(&func);

    // Verify we have a phi before
    let bb3 = func.block(BlockId(3));
    assert!(
        bb3.instructions
            .iter()
            .any(|i| matches!(i, MirInst::Phi { .. })),
        "Should have phi before destruction"
    );

    let pass = SsaDestruction;
    let changed = pass.run(&mut func, &cfg);

    assert!(changed);

    // Verify phi is gone
    let bb3 = func.block(BlockId(3));
    assert!(
        !bb3.instructions
            .iter()
            .any(|i| matches!(i, MirInst::Phi { .. })),
        "Should not have phi after destruction"
    );
}

#[test]
fn test_copies_inserted() {
    let mut func = make_ssa_function();
    let cfg = CFG::build(&func);

    let pass = SsaDestruction;
    pass.run(&mut func, &cfg);

    // bb1 should have a copy to v1_3 (the phi dst)
    let bb1 = func.block(BlockId(1));
    let has_copy = bb1
        .instructions
        .iter()
        .any(|i| matches!(i, MirInst::Copy { .. }));
    assert!(has_copy, "bb1 should have a copy instruction");

    // bb2 should also have a copy
    let bb2 = func.block(BlockId(2));
    let has_copy = bb2
        .instructions
        .iter()
        .any(|i| matches!(i, MirInst::Copy { .. }));
    assert!(has_copy, "bb2 should have a copy instruction");
}

#[test]
fn test_parallel_copy_multi_phi_join_ordering() {
    // bb0: cond=1; branch bb1, bb2
    // bb1: b=10; c=20; jump bb3
    // bb2: b2=30; c2=40; jump bb3
    // bb3:
    //   b = phi(c:bb1, b2:bb2)
    //   a = phi(b:bb1, c2:bb2)
    //   return a
    //
    // On edge bb1->bb3 this requires parallel copies:
    //   b <- c
    //   a <- b
    // Correct lowering must emit a <- b before b <- c.
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    let bb3 = func.alloc_block();
    func.entry = bb0;

    let cond = func.alloc_vreg();
    let a = func.alloc_vreg();
    let b = func.alloc_vreg();
    let c = func.alloc_vreg();
    let b2 = func.alloc_vreg();
    let c2 = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: cond,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).terminator = MirInst::Branch {
        cond,
        if_true: bb1,
        if_false: bb2,
    };

    func.block_mut(bb1).instructions.push(MirInst::Copy {
        dst: b,
        src: MirValue::Const(10),
    });
    func.block_mut(bb1).instructions.push(MirInst::Copy {
        dst: c,
        src: MirValue::Const(20),
    });
    func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

    func.block_mut(bb2).instructions.push(MirInst::Copy {
        dst: b2,
        src: MirValue::Const(30),
    });
    func.block_mut(bb2).instructions.push(MirInst::Copy {
        dst: c2,
        src: MirValue::Const(40),
    });
    func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

    func.block_mut(bb3).instructions.push(MirInst::Phi {
        dst: b,
        args: vec![(bb1, c), (bb2, b2)],
    });
    func.block_mut(bb3).instructions.push(MirInst::Phi {
        dst: a,
        args: vec![(bb1, b), (bb2, c2)],
    });
    func.block_mut(bb3).terminator = MirInst::Return {
        val: Some(MirValue::VReg(a)),
    };

    let cfg = CFG::build(&func);
    let pass = SsaDestruction;
    pass.run(&mut func, &cfg);

    let bb1 = func.block(bb1);
    let tail_copies: Vec<_> = bb1
        .instructions
        .iter()
        .filter_map(|inst| match inst {
            MirInst::Copy {
                dst,
                src: MirValue::VReg(src),
            } => Some((*dst, *src)),
            _ => None,
        })
        .collect();

    let inserted = &tail_copies[tail_copies.len() - 2..];
    assert_eq!(
        inserted[0],
        (a, b),
        "must preserve old b before rewriting b"
    );
    assert_eq!(inserted[1], (b, c));
}

#[test]
fn test_parallel_copy_loop_header_swap_cycle() {
    // bb0: x0=1; y0=2; cond=1; jump bb1
    // bb1:
    //   x = phi(x0:bb0, y:bb2)
    //   y = phi(y0:bb0, x:bb2)
    //   branch cond -> bb2, bb3
    // bb2: jump bb1
    // bb3: return x
    //
    // Backedge bb2->bb1 requires a swap:
    //   x <- y
    //   y <- x
    // Correct lowering needs a temporary.
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    let bb3 = func.alloc_block();
    func.entry = bb0;

    let x0 = func.alloc_vreg();
    let y0 = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let x = func.alloc_vreg();
    let y = func.alloc_vreg();
    let pre_temp_vreg_count = func.vreg_count;

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: x0,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: y0,
        src: MirValue::Const(2),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: cond,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).terminator = MirInst::Jump { target: bb1 };

    func.block_mut(bb1).instructions.push(MirInst::Phi {
        dst: x,
        args: vec![(bb0, x0), (bb2, y)],
    });
    func.block_mut(bb1).instructions.push(MirInst::Phi {
        dst: y,
        args: vec![(bb0, y0), (bb2, x)],
    });
    func.block_mut(bb1).terminator = MirInst::Branch {
        cond,
        if_true: bb2,
        if_false: bb3,
    };

    func.block_mut(bb2).terminator = MirInst::Jump { target: bb1 };
    func.block_mut(bb3).terminator = MirInst::Return {
        val: Some(MirValue::VReg(x)),
    };

    let cfg = CFG::build(&func);
    let pass = SsaDestruction;
    pass.run(&mut func, &cfg);

    assert_eq!(
        func.vreg_count,
        pre_temp_vreg_count + 1,
        "swap cycle should allocate one temporary"
    );

    let bb2 = func.block(bb2);
    let copies: Vec<_> = bb2
        .instructions
        .iter()
        .filter_map(|inst| match inst {
            MirInst::Copy {
                dst,
                src: MirValue::VReg(src),
            } => Some((*dst, *src)),
            _ => None,
        })
        .collect();

    assert_eq!(copies.len(), 3, "swap cycle should lower to 3 copies");
    let temp = copies[0].0;
    assert_ne!(temp, x);
    assert_ne!(temp, y);
    assert_eq!(copies[0], (temp, y));
    assert_eq!(copies[1], (y, x));
    assert_eq!(copies[2], (x, temp));
}

#[test]
fn test_critical_edge_is_split_for_phi_copies() {
    // bb0: cond=1; branch bb1, bb2
    // bb1: v1=11; branch cond -> bb3, bb4
    // bb2: v2=22; jump bb3
    // bb3: p = phi(v1:bb1, v2:bb2); return p
    // bb4: return cond
    //
    // Edge bb1->bb3 is critical and must be split so phi copy for `p`
    // does not execute on bb1->bb4.
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    let bb3 = func.alloc_block();
    let bb4 = func.alloc_block();
    func.entry = bb0;

    let cond = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();
    let p = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: cond,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).terminator = MirInst::Branch {
        cond,
        if_true: bb1,
        if_false: bb2,
    };

    func.block_mut(bb1).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::Const(11),
    });
    func.block_mut(bb1).terminator = MirInst::Branch {
        cond,
        if_true: bb3,
        if_false: bb4,
    };

    func.block_mut(bb2).instructions.push(MirInst::Copy {
        dst: v2,
        src: MirValue::Const(22),
    });
    func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

    func.block_mut(bb3).instructions.push(MirInst::Phi {
        dst: p,
        args: vec![(bb1, v1), (bb2, v2)],
    });
    func.block_mut(bb3).terminator = MirInst::Return {
        val: Some(MirValue::VReg(p)),
    };
    func.block_mut(bb4).terminator = MirInst::Return {
        val: Some(MirValue::VReg(cond)),
    };

    let old_block_count = func.blocks.len();
    let cfg = CFG::build(&func);
    let pass = SsaDestruction;
    pass.run(&mut func, &cfg);

    assert_eq!(
        func.blocks.len(),
        old_block_count + 1,
        "critical edge should be split with a new block"
    );

    let bb1_block = func.block(bb1);
    let split_id = match bb1_block.terminator {
        MirInst::Branch {
            if_true, if_false, ..
        } => {
            assert_eq!(if_false, bb4);
            assert_ne!(if_true, bb3);
            if_true
        }
        _ => panic!("expected bb1 to end in a branch"),
    };

    assert!(
        !bb1_block.instructions.iter().any(|inst| {
            matches!(
                inst,
                MirInst::Copy {
                    dst,
                    src: MirValue::VReg(src)
                } if *dst == p && *src == v1
            )
        }),
        "bb1 should not contain bb1->bb3 phi copy directly"
    );

    let split = func.block(split_id);
    assert!(
        split.instructions.iter().any(|inst| {
            matches!(
                inst,
                MirInst::Copy {
                    dst,
                    src: MirValue::VReg(src)
                } if *dst == p && *src == v1
            )
        }),
        "split block must contain the edge-local phi copy"
    );
    assert!(
        matches!(split.terminator, MirInst::Jump { target } if target == bb3),
        "split block should jump to phi block"
    );
}

#[test]
fn test_no_phis_no_change() {
    // Function without phis
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
    let pass = SsaDestruction;
    let changed = pass.run(&mut func, &cfg);

    assert!(!changed, "Should not change function without phis");
}
