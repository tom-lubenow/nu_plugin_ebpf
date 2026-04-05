use super::*;
use crate::compiler::mir::{AddressSpace, BinOpKind, MirType, MirValue, StackSlotKind};

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

#[test]
fn test_construct_ssa_with_type_hints_preserves_per_definition_types() {
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    let slot0 = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let slot1 = func.alloc_stack_slot(4, 4, StackSlotKind::Local);
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::StackSlot(slot0),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::VReg(v0),
    });
    func.block_mut(bb0).instructions.push(MirInst::LoadSlot {
        dst: v0,
        slot: slot1,
        offset: 0,
        ty: MirType::U32,
    });
    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v0)),
    };

    let cfg = CFG::build(&func);
    let original_hints = HashMap::from([(v0, MirType::U32), (v1, MirType::U32)]);
    let stack_slot_hints = HashMap::from([(slot0, MirType::U64), (slot1, MirType::U32)]);
    let (changed, ssa_hints) = construct_ssa_with_type_hints(
        &mut func,
        &cfg,
        None,
        &original_hints,
        &stack_slot_hints,
        &HashMap::new(),
    );

    assert!(changed);

    let first_copy_dst = match &func.block(bb0).instructions[0] {
        MirInst::Copy { dst, .. } => *dst,
        inst => panic!("expected first copy, got {inst:?}"),
    };
    let copied_use_dst = match &func.block(bb0).instructions[1] {
        MirInst::Copy { dst, .. } => *dst,
        inst => panic!("expected second copy, got {inst:?}"),
    };
    let load_slot_dst = match &func.block(bb0).instructions[2] {
        MirInst::LoadSlot { dst, .. } => *dst,
        inst => panic!("expected load slot, got {inst:?}"),
    };

    let expected_ptr = MirType::Ptr {
        pointee: Box::new(MirType::U64),
        address_space: AddressSpace::Stack,
    };
    assert_eq!(ssa_hints.get(&first_copy_dst), Some(&expected_ptr));
    assert_eq!(ssa_hints.get(&copied_use_dst), Some(&expected_ptr));
    assert_eq!(ssa_hints.get(&load_slot_dst), Some(&MirType::U32));
}

#[test]
fn test_construct_ssa_with_type_hints_recovers_phi_types_from_args() {
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    let bb1 = func.alloc_block();
    let bb2 = func.alloc_block();
    let bb3 = func.alloc_block();
    func.entry = bb0;

    let cond = func.alloc_vreg();
    let merged = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: cond,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).terminator = MirInst::Branch {
        cond,
        if_true: bb1,
        if_false: bb2,
    };
    func.block_mut(bb1).instructions.push(MirInst::LoadSlot {
        dst: merged,
        slot: StackSlotId(0),
        offset: 0,
        ty: MirType::U32,
    });
    func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };
    func.block_mut(bb2).instructions.push(MirInst::LoadSlot {
        dst: merged,
        slot: StackSlotId(1),
        offset: 0,
        ty: MirType::U32,
    });
    func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };
    func.block_mut(bb3).terminator = MirInst::Return {
        val: Some(MirValue::VReg(merged)),
    };
    func.stack_slots.push(crate::compiler::mir::StackSlot {
        id: StackSlotId(0),
        size: 4,
        align: 4,
        kind: StackSlotKind::Local,
        offset: None,
    });
    func.stack_slots.push(crate::compiler::mir::StackSlot {
        id: StackSlotId(1),
        size: 4,
        align: 4,
        kind: StackSlotKind::Local,
        offset: None,
    });

    let cfg = CFG::build(&func);
    let original_hints = HashMap::from([(merged, MirType::U64)]);
    let stack_slot_hints = HashMap::from([
        (StackSlotId(0), MirType::U32),
        (StackSlotId(1), MirType::U32),
    ]);
    let (changed, ssa_hints) = construct_ssa_with_type_hints(
        &mut func,
        &cfg,
        None,
        &original_hints,
        &stack_slot_hints,
        &HashMap::new(),
    );

    assert!(changed);

    let phi_dst = match func
        .block(bb3)
        .instructions
        .iter()
        .find(|inst| matches!(inst, MirInst::Phi { .. }))
    {
        Some(MirInst::Phi { dst, .. }) => *dst,
        other => panic!("expected phi in bb3, got {other:?}"),
    };
    assert_eq!(ssa_hints.get(&phi_dst), Some(&MirType::U32));
}
