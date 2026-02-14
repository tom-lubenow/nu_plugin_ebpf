
use super::*;
use crate::compiler::mir::{BinOpKind, MirInst, MirValue, StackSlotKind, StringAppendType};

fn make_simple_function() -> MirFunction {
    // v0 = 1
    // v1 = 2
    // v2 = v0 + v1
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
        src: MirValue::Const(2),
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

fn make_coalesce_function() -> MirFunction {
    // v0 = 1
    // v1 = v0  <-- this move should be coalesced
    // return v1
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
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
    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v1)),
    };

    func
}

fn make_pressure_function() -> MirFunction {
    // v0 = 1
    // v1 = 2
    // v2 = 3
    // v3 = 4
    // v4 = v0 + v1
    // v5 = v2 + v3
    // v6 = v4 + v5
    // return v6
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();
    let v3 = func.alloc_vreg();
    let v4 = func.alloc_vreg();
    let v5 = func.alloc_vreg();
    let v6 = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::Const(2),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v2,
        src: MirValue::Const(3),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v3,
        src: MirValue::Const(4),
    });
    func.block_mut(bb0).instructions.push(MirInst::BinOp {
        dst: v4,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::VReg(v1),
    });
    func.block_mut(bb0).instructions.push(MirInst::BinOp {
        dst: v5,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v2),
        rhs: MirValue::VReg(v3),
    });
    func.block_mut(bb0).instructions.push(MirInst::BinOp {
        dst: v6,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v4),
        rhs: MirValue::VReg(v5),
    });
    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v6)),
    };

    func
}

#[test]
fn test_simple_allocation() {
    let func = make_simple_function();
    let available = vec![EbpfReg::R6, EbpfReg::R7, EbpfReg::R8];

    let result = allocate_registers(&func, available);

    // All vregs should be colored, no spills
    assert_eq!(result.coloring.len(), 3);
    assert!(result.spills.is_empty());
}

#[test]
fn test_coalescing() {
    let func = make_coalesce_function();
    let available = vec![EbpfReg::R6, EbpfReg::R7, EbpfReg::R8];

    let result = allocate_registers(&func, available);

    // Should coalesce v0 and v1 to the same register
    assert!(
        result.coalesced_moves > 0,
        "Should have coalesced at least one move"
    );

    // v0 and v1 should have the same color
    let v0_color = result.coloring.get(&VReg(0));
    let v1_color = result.coloring.get(&VReg(1));
    assert_eq!(v0_color, v1_color, "Coalesced nodes should have same color");
}

#[test]
fn test_register_pressure() {
    let func = make_pressure_function();
    // Only 3 registers for 7 virtual registers
    let available = vec![EbpfReg::R6, EbpfReg::R7, EbpfReg::R8];

    let result = allocate_registers(&func, available);

    // With good allocation, we might need some spills
    let total = result.coloring.len() + result.spills.len();
    assert!(total > 0, "Should have some allocations");

    // Verify no two simultaneously live vregs share the same register
    // (This would require checking against live intervals)
}

#[test]
fn test_register_pressure_allocation_stable() {
    let func = make_pressure_function();
    let available = vec![EbpfReg::R6, EbpfReg::R7, EbpfReg::R8];

    let mut baseline: Option<(Vec<(u32, EbpfReg)>, Vec<u32>, usize)> = None;

    for _ in 0..8 {
        let result = allocate_registers(&func, available.clone());
        let mut coloring: Vec<(u32, EbpfReg)> = result
            .coloring
            .iter()
            .map(|(vreg, reg)| (vreg.0, *reg))
            .collect();
        coloring.sort_by_key(|(vreg, _)| *vreg);

        let mut spills: Vec<u32> = result.spills.keys().map(|vreg| vreg.0).collect();
        spills.sort_unstable();

        let signature = (coloring, spills, result.coalesced_moves);
        if let Some(expected) = &baseline {
            assert_eq!(
                &signature, expected,
                "register allocation result should be stable across runs"
            );
        } else {
            baseline = Some(signature);
        }
    }
}

#[test]
fn test_empty_function() {
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;
    func.block_mut(bb0).terminator = MirInst::Return { val: None };

    let result = allocate_registers(&func, vec![EbpfReg::R6, EbpfReg::R7, EbpfReg::R8]);

    assert!(result.coloring.is_empty());
    assert!(result.spills.is_empty());
}

#[test]
fn test_interference_detection() {
    // v0 = 1
    // v1 = 2
    // v2 = v0 + v1  <-- v0 and v1 are both live here, so they interfere
    // return v2
    let func = make_simple_function();
    let cfg = AnalysisCfg::build(&func);
    let liveness = BlockLiveness::compute(&func, &cfg);
    let mut allocator = GraphColoringAllocator::new(vec![EbpfReg::R6, EbpfReg::R7]);
    allocator.build(&func, &cfg, &liveness);

    // v0 and v1 should interfere (both live at the BinOp)
    assert!(
        allocator.graph.interferes(VReg(0), VReg(1)),
        "v0 and v1 should interfere"
    );
}

fn make_list_function() -> MirFunction {
    use crate::compiler::mir::StackSlotKind;
    // v0 = ListNew (list pointer)
    // v1 = 1
    // ListPush(v0, v1)
    // v2 = 2
    // ListPush(v0, v2)
    // EmitEvent(v0)
    // return
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    let v0 = func.alloc_vreg(); // list ptr
    let v1 = func.alloc_vreg(); // item 1
    let v2 = func.alloc_vreg(); // item 2

    // Allocate stack slot for list buffer
    let slot = func.alloc_stack_slot(32, 8, StackSlotKind::ListBuffer);

    func.block_mut(bb0).instructions.push(MirInst::ListNew {
        dst: v0,
        buffer: slot,
        max_len: 3,
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0)
        .instructions
        .push(MirInst::ListPush { list: v0, item: v1 });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v2,
        src: MirValue::Const(2),
    });
    func.block_mut(bb0)
        .instructions
        .push(MirInst::ListPush { list: v0, item: v2 });
    func.block_mut(bb0)
        .instructions
        .push(MirInst::EmitEvent { data: v0, size: 24 });
    func.block_mut(bb0).terminator = MirInst::Return { val: None };

    func
}

fn make_string_append_int_function() -> MirFunction {
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    let slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let len = func.alloc_vreg();
    let val = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: len,
        src: MirValue::Const(0),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: val,
        src: MirValue::Const(42),
    });
    func.block_mut(bb0)
        .instructions
        .push(MirInst::StringAppend {
            dst_buffer: slot,
            dst_len: len,
            val: MirValue::VReg(val),
            val_type: StringAppendType::Integer,
        });
    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(val)),
    };

    func
}

fn make_helper_call_clobber_function() -> MirFunction {
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    let v_keep = func.alloc_vreg();
    let v_ret = func.alloc_vreg();
    let v_out = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v_keep,
        src: MirValue::Const(7),
    });
    func.block_mut(bb0).instructions.push(MirInst::CallHelper {
        dst: v_ret,
        helper: 14, // bpf_get_current_pid_tgid
        args: vec![],
    });
    func.block_mut(bb0).instructions.push(MirInst::BinOp {
        dst: v_out,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v_keep),
        rhs: MirValue::VReg(v_ret),
    });
    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v_out)),
    };

    func
}

fn make_subfn_call_clobber_function() -> MirFunction {
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    let v_keep = func.alloc_vreg();
    let v_arg = func.alloc_vreg();
    let v_ret = func.alloc_vreg();
    let v_out = func.alloc_vreg();

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v_keep,
        src: MirValue::Const(11),
    });
    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: v_arg,
        src: MirValue::Const(1),
    });
    func.block_mut(bb0).instructions.push(MirInst::CallSubfn {
        dst: v_ret,
        subfn: crate::compiler::mir::SubfunctionId(0),
        args: vec![v_arg],
    });
    func.block_mut(bb0).instructions.push(MirInst::BinOp {
        dst: v_out,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v_keep),
        rhs: MirValue::VReg(v_ret),
    });
    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v_out)),
    };

    func
}

#[test]
fn test_list_register_allocation() {
    let func = make_list_function();
    let available = vec![EbpfReg::R6, EbpfReg::R7, EbpfReg::R8];

    let result = allocate_registers(&func, available);

    // All vregs should be colored (no spills needed for this simple case)
    assert_eq!(result.coloring.len(), 3, "Should color all 3 vregs");
    assert!(result.spills.is_empty(), "Should have no spills");

    // v0 (list ptr) must have a register since it's used across multiple instructions
    assert!(
        result.coloring.contains_key(&VReg(0)),
        "List pointer vreg v0 must be colored"
    );

    // Print the coloring for debugging
    eprintln!("List register allocation:");
    for (vreg, reg) in &result.coloring {
        eprintln!("  {} -> {:?}", vreg, reg);
    }
}

#[test]
fn test_list_push_clobber_constraints() {
    let func = make_list_function();
    let available = vec![
        EbpfReg::R1,
        EbpfReg::R2,
        EbpfReg::R3,
        EbpfReg::R4,
        EbpfReg::R5,
        EbpfReg::R6,
    ];

    let result = allocate_registers(&func, available);

    let v0_reg = result
        .coloring
        .get(&VReg(0))
        .copied()
        .expect("v0 should be colored");

    assert!(
        v0_reg != EbpfReg::R1 && v0_reg != EbpfReg::R2,
        "List pointer should avoid R1/R2 due to ListPush scratch usage, got {:?}",
        v0_reg
    );
}

#[test]
fn test_list_interference() {
    let func = make_list_function();
    let cfg = AnalysisCfg::build(&func);
    let liveness = BlockLiveness::compute(&func, &cfg);
    let mut allocator = GraphColoringAllocator::new(vec![EbpfReg::R6, EbpfReg::R7, EbpfReg::R8]);
    allocator.build(&func, &cfg, &liveness);

    // v0 should be in the graph (defined by ListNew)
    assert!(
        allocator.graph.nodes.contains(&VReg(0)),
        "v0 (list ptr from ListNew) should be in graph"
    );

    // v0 and v1 should interfere (v0 is live when v1 is used in ListPush)
    assert!(
        allocator.graph.interferes(VReg(0), VReg(1)),
        "v0 (list) and v1 (item) should interfere"
    );
}

#[test]
fn test_string_append_int_clobber_constraints() {
    let func = make_string_append_int_function();
    let available = vec![
        EbpfReg::R1,
        EbpfReg::R2,
        EbpfReg::R3,
        EbpfReg::R4,
        EbpfReg::R5,
        EbpfReg::R6,
        EbpfReg::R7,
        EbpfReg::R8,
    ];

    let result = allocate_registers(&func, available);
    let val_reg = result
        .coloring
        .get(&VReg(1))
        .copied()
        .expect("val vreg should be colored");

    assert!(
        !matches!(
            val_reg,
            EbpfReg::R1 | EbpfReg::R2 | EbpfReg::R3 | EbpfReg::R4 | EbpfReg::R5
        ),
        "StringAppend integer source should avoid R1-R5 scratch regs, got {:?}",
        val_reg
    );
}

#[test]
fn test_helper_call_clobber_constraints() {
    let func = make_helper_call_clobber_function();
    let available = vec![
        EbpfReg::R1,
        EbpfReg::R2,
        EbpfReg::R3,
        EbpfReg::R4,
        EbpfReg::R5,
        EbpfReg::R6,
    ];

    let result = allocate_registers(&func, available);
    let keep_reg = result
        .coloring
        .get(&VReg(0))
        .copied()
        .expect("value live across helper call should be colored");

    assert!(
        !matches!(
            keep_reg,
            EbpfReg::R1 | EbpfReg::R2 | EbpfReg::R3 | EbpfReg::R4 | EbpfReg::R5
        ),
        "value live across helper call should avoid R1-R5, got {:?}",
        keep_reg
    );
}

#[test]
fn test_subfn_call_clobber_constraints() {
    let func = make_subfn_call_clobber_function();
    let available = vec![
        EbpfReg::R1,
        EbpfReg::R2,
        EbpfReg::R3,
        EbpfReg::R4,
        EbpfReg::R5,
        EbpfReg::R6,
    ];

    let result = allocate_registers(&func, available);
    let keep_reg = result
        .coloring
        .get(&VReg(0))
        .copied()
        .expect("value live across subfn call should be colored");

    assert!(
        !matches!(
            keep_reg,
            EbpfReg::R1 | EbpfReg::R2 | EbpfReg::R3 | EbpfReg::R4 | EbpfReg::R5
        ),
        "value live across subfn call should avoid R1-R5, got {:?}",
        keep_reg
    );
}

#[test]
fn test_lir_loop_depths() {
    use crate::compiler::lir::{LirFunction, LirInst};

    let mut func = LirFunction::new();
    let entry = func.alloc_block();
    let header = func.alloc_block();
    let body = func.alloc_block();
    let exit = func.alloc_block();
    func.entry = entry;

    let counter = func.alloc_vreg();

    func.block_mut(entry).terminator = LirInst::Jump { target: header };
    func.block_mut(header).terminator = LirInst::LoopHeader {
        counter,
        limit: 10,
        body,
        exit,
    };
    func.block_mut(body).terminator = LirInst::LoopBack {
        counter,
        step: 1,
        header,
    };
    func.block_mut(exit).terminator = LirInst::Return { val: None };

    let depths = compute_loop_depths(&func);
    assert_eq!(depths.get(&entry).copied().unwrap_or(0), 0);
    assert_eq!(depths.get(&header).copied().unwrap_or(0), 1);
    assert_eq!(depths.get(&body).copied().unwrap_or(0), 1);
    assert_eq!(depths.get(&exit).copied().unwrap_or(0), 0);
}
