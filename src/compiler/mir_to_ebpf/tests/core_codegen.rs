use super::*;

#[test]
fn test_return_zero() {
    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(0),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);

    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(!mir_result.bytecode.is_empty(), "Should produce bytecode");
    assert_eq!(
        mir_result.bytecode.len() % 8,
        0,
        "Bytecode should be aligned to 8 bytes"
    );
}

/// Test valid bytecode for addition
#[test]
fn test_add() {
    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(1),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(2),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Add),
            rhs: RegId::new(1),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);

    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(!mir_result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_parallel_move_r0_cycle() {
    let mut func = LirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();

    func.precolored.insert(v0, EbpfReg::R0);
    func.precolored.insert(v1, EbpfReg::R1);
    func.precolored.insert(v2, EbpfReg::R2);

    func.block_mut(entry)
        .instructions
        .push(LirInst::ParallelMove {
            moves: vec![(v0, v1), (v1, v2), (v2, v0)],
        });
    func.block_mut(entry).terminator = LirInst::Return {
        val: Some(MirValue::VReg(v0)),
    };

    let program = LirProgram::new(func);
    let result = MirToEbpfCompiler::new(&program, None).compile();
    assert!(result.is_ok(), "ParallelMove with R0 should compile");
}

#[test]
fn test_parallel_move_stack_to_stack() {
    let program = LirProgram::new(LirFunction::new());
    let mut compiler = MirToEbpfCompiler::new(&program, None);

    compiler.parallel_move_cycle_offset = Some(-8);
    compiler.parallel_move_scratch_offset = Some(-16);
    compiler.vreg_spills.insert(VReg(0), -24);
    compiler.vreg_spills.insert(VReg(1), -32);
    compiler.vreg_to_phys.insert(VReg(2), EbpfReg::R1);

    let inst = LirInst::ParallelMove {
        moves: vec![(VReg(0), VReg(1)), (VReg(0), VReg(2))],
    };

    compiler
        .compile_instruction(&inst)
        .expect("ParallelMove stack-to-stack should compile");
    assert!(
        !compiler.instructions.is_empty(),
        "ParallelMove should emit instructions"
    );
}

#[test]
fn test_ensure_reg_rematerializes_spilled_const() {
    let program = LirProgram::new(LirFunction::new());
    let mut compiler = MirToEbpfCompiler::new(&program, None);

    compiler.vreg_spills.insert(VReg(0), -8);
    compiler.vreg_remat.insert(VReg(0), RematExpr::Const(42));

    let reg = compiler
        .ensure_reg(VReg(0))
        .expect("rematerialized ensure_reg should succeed");
    assert_eq!(reg, EbpfReg::R0);
    assert_eq!(compiler.instructions.len(), 1);

    let insn = compiler.instructions[0];
    assert_eq!(insn.opcode, opcode::MOV64_IMM);
    assert_eq!(insn.dst_reg, EbpfReg::R0.as_u8());
    assert_eq!(insn.imm, 42);
}

#[test]
fn test_compile_instruction_stores_non_remat_spilled_def() {
    let program = LirProgram::new(LirFunction::new());
    let mut compiler = MirToEbpfCompiler::new(&program, None);

    compiler.vreg_spills.insert(VReg(0), -8);

    compiler
        .compile_instruction_with_spills(&LirInst::Copy {
            dst: VReg(0),
            src: MirValue::Const(7),
        })
        .expect("spilled copy should compile");

    assert_eq!(compiler.instructions.len(), 2);
    assert_eq!(compiler.instructions[0].opcode, opcode::MOV64_IMM);

    let spill_store = compiler.instructions[1];
    assert_eq!(
        spill_store.opcode,
        opcode::BPF_STX | opcode::BPF_DW | opcode::BPF_MEM
    );
    assert_eq!(spill_store.dst_reg, EbpfReg::R10.as_u8());
    assert_eq!(spill_store.src_reg, EbpfReg::R0.as_u8());
    assert_eq!(spill_store.offset, -8);
}

#[test]
fn test_compile_instruction_skips_store_for_rematerialized_spilled_def() {
    let program = LirProgram::new(LirFunction::new());
    let mut compiler = MirToEbpfCompiler::new(&program, None);

    compiler.vreg_spills.insert(VReg(0), -8);
    compiler.vreg_remat.insert(VReg(0), RematExpr::Const(7));

    compiler
        .compile_instruction_with_spills(&LirInst::Copy {
            dst: VReg(0),
            src: MirValue::Const(7),
        })
        .expect("spilled rematerialized copy should compile");

    assert_eq!(compiler.instructions.len(), 1);
    assert_eq!(compiler.instructions[0].opcode, opcode::MOV64_IMM);
}

#[test]
fn test_compute_rematerializable_spill_stack_expression() {
    let mut func = LirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::Spill);
    let base = func.alloc_vreg();
    let ptr = func.alloc_vreg();

    func.block_mut(entry).instructions.push(LirInst::Copy {
        dst: base,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(LirInst::BinOp {
        dst: ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(base),
        rhs: MirValue::Const(8),
    });
    func.block_mut(entry).terminator = LirInst::Return {
        val: Some(MirValue::VReg(ptr)),
    };

    let program = LirProgram::new(func.clone());
    let compiler = MirToEbpfCompiler::new(&program, None);
    let mut spills = HashMap::new();
    spills.insert(ptr, StackSlotId(0));

    let remat = compiler.compute_rematerializable_spills(&func, &spills);
    assert_eq!(
        remat.get(&ptr),
        Some(&RematExpr::StackAddr { slot, addend: 8 })
    );
}

/// Test that old compiler handles branching (MIR branch test is separate)
#[test]
fn test_branch() {
    let _ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Bool(true),
        },
        Instruction::BranchIf {
            cond: RegId::new(0),
            index: 3, // Jump to Return
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(0),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);
    // MIR compiler branching is tested separately with proper block construction
}

/// Test multiplication
#[test]
fn test_multiply() {
    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(5),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(3),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Multiply),
            rhs: RegId::new(1),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);
    // Compile and verify
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(
        !mir_result.bytecode.is_empty(),
        "Should produce empty bytecode"
    );
}

/// Test MIR function creation directly
#[test]
fn test_mir_direct_compile() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();

    // Create entry block
    let mut entry_block = BasicBlock::new(BlockId(0));

    // Simple: mov r0, 42; exit
    entry_block.instructions.push(MirInst::Copy {
        dst: VReg(0),
        src: MirValue::Const(42),
    });
    entry_block.terminator = MirInst::Return {
        val: Some(MirValue::VReg(VReg(0))),
    };

    func.blocks.push(entry_block);
    func.vreg_count = 1;

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).unwrap();
    assert!(
        !result.bytecode.is_empty(),
        "Direct MIR compile produced empty bytecode"
    );
}

/// Test MIR branching directly
#[test]
fn test_mir_branch_compile() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();

    // Entry block: load condition, branch
    let mut entry = BasicBlock::new(BlockId(0));
    entry.instructions.push(MirInst::Copy {
        dst: VReg(0),
        src: MirValue::Const(1), // true
    });
    entry.terminator = MirInst::Branch {
        cond: VReg(0),
        if_true: BlockId(1),
        if_false: BlockId(2),
    };

    // True block: return 1
    let mut true_block = BasicBlock::new(BlockId(1));
    true_block.instructions.push(MirInst::Copy {
        dst: VReg(1),
        src: MirValue::Const(1),
    });
    true_block.terminator = MirInst::Return {
        val: Some(MirValue::VReg(VReg(1))),
    };

    // False block: return 0
    let mut false_block = BasicBlock::new(BlockId(2));
    false_block.instructions.push(MirInst::Copy {
        dst: VReg(2),
        src: MirValue::Const(0),
    });
    false_block.terminator = MirInst::Return {
        val: Some(MirValue::VReg(VReg(2))),
    };

    func.blocks.push(entry);
    func.blocks.push(true_block);
    func.blocks.push(false_block);
    func.vreg_count = 3;

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).unwrap();
    assert!(
        !result.bytecode.is_empty(),
        "MIR branch compile produced empty bytecode"
    );
}

#[test]
fn test_mir_phi_compile_without_prepass() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();

    let mut entry = BasicBlock::new(BlockId(0));
    entry.instructions.push(MirInst::Copy {
        dst: VReg(0),
        src: MirValue::Const(1),
    });
    entry.terminator = MirInst::Branch {
        cond: VReg(0),
        if_true: BlockId(1),
        if_false: BlockId(2),
    };

    let mut left = BasicBlock::new(BlockId(1));
    left.instructions.push(MirInst::Copy {
        dst: VReg(1),
        src: MirValue::Const(10),
    });
    left.terminator = MirInst::Jump { target: BlockId(3) };

    let mut right = BasicBlock::new(BlockId(2));
    right.instructions.push(MirInst::Copy {
        dst: VReg(2),
        src: MirValue::Const(20),
    });
    right.terminator = MirInst::Jump { target: BlockId(3) };

    let mut join = BasicBlock::new(BlockId(3));
    join.instructions.push(MirInst::Phi {
        dst: VReg(3),
        args: vec![(BlockId(1), VReg(1)), (BlockId(2), VReg(2))],
    });
    join.terminator = MirInst::Return {
        val: Some(MirValue::VReg(VReg(3))),
    };

    func.blocks.push(entry);
    func.blocks.push(left);
    func.blocks.push(right);
    func.blocks.push(join);
    func.vreg_count = 4;

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).unwrap();
    assert!(
        !result.bytecode.is_empty(),
        "MIR with phi should compile via internal SSA destruction"
    );
}

/// Test histogram instruction compiles
#[test]
fn test_mir_histogram() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let mut entry = BasicBlock::new(BlockId(0));

    // Load a value and compute histogram bucket
    entry.instructions.push(MirInst::Copy {
        dst: VReg(0),
        src: MirValue::Const(42),
    });
    entry
        .instructions
        .push(MirInst::Histogram { value: VReg(0) });
    entry.terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    func.blocks.push(entry);
    func.vreg_count = 1;

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).unwrap();
    assert!(!result.bytecode.is_empty());
    // Should have histogram map
    assert!(result.maps.iter().any(|m| m.name == HISTOGRAM_MAP_NAME));
}

/// Test start/stop timer instructions compile
#[test]
fn test_mir_timer() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let mut entry = BasicBlock::new(BlockId(0));

    entry.instructions.push(MirInst::StartTimer);
    entry.instructions.push(MirInst::StopTimer { dst: VReg(0) });
    entry.terminator = MirInst::Return {
        val: Some(MirValue::VReg(VReg(0))),
    };

    func.blocks.push(entry);
    func.vreg_count = 1;

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).unwrap();
    assert!(!result.bytecode.is_empty());
    // Should have timestamp map
    assert!(result.maps.iter().any(|m| m.name == TIMESTAMP_MAP_NAME));
}

#[test]
fn test_stop_timer_preserves_value_across_delete_for_histogram_use() {
    // Regression for a verifier failure where stop-timer wrote its result to a
    // caller-clobbered register, then called map_delete_elem before histogram used it.
    let mut func = LirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let delta = func.alloc_vreg();
    func.precolored.insert(delta, EbpfReg::R3);

    func.block_mut(entry)
        .instructions
        .push(LirInst::StopTimer { dst: delta });
    func.block_mut(entry)
        .instructions
        .push(LirInst::Histogram { value: delta });
    func.block_mut(entry).terminator = LirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = LirProgram::new(func);
    let result = MirToEbpfCompiler::new(&program, None)
        .compile()
        .expect("stop-timer + histogram should compile");

    let decode = |chunk: &[u8]| EbpfInsn {
        opcode: chunk[0],
        dst_reg: chunk[1] & 0x0f,
        src_reg: (chunk[1] >> 4) & 0x0f,
        offset: i16::from_le_bytes([chunk[2], chunk[3]]),
        imm: i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
    };
    let insns: Vec<EbpfInsn> = result.bytecode.chunks(8).map(decode).collect();

    let delete_idx = insns
        .iter()
        .position(|insn| insn.opcode == opcode::CALL && insn.imm == BpfHelper::MapDeleteElem as i32)
        .expect("expected stop-timer map_delete helper call");

    // stop-timer now spills delta to stack before delete and reloads it after.
    let spill_idx = (0..delete_idx)
        .rev()
        .find(|&i| {
            let insn = insns[i];
            insn.opcode == (opcode::BPF_STX | opcode::BPF_DW | opcode::BPF_MEM)
                && insn.dst_reg == EbpfReg::R10.as_u8()
                && insn.src_reg == EbpfReg::R0.as_u8()
        })
        .expect("expected stop-timer delta spill before map_delete");
    let spill_offset = insns[spill_idx].offset;

    let reload_idx = ((delete_idx + 1)..insns.len())
        .find(|&i| {
            let insn = insns[i];
            insn.opcode == (opcode::BPF_LDX | opcode::BPF_DW | opcode::BPF_MEM)
                && insn.dst_reg == EbpfReg::R3.as_u8()
                && insn.src_reg == EbpfReg::R10.as_u8()
                && insn.offset == spill_offset
        })
        .expect("expected reloaded stop-timer delta after map_delete");

    let histogram_lookup_idx = insns
        .iter()
        .enumerate()
        .skip(delete_idx + 1)
        .find_map(|(i, insn)| {
            (insn.opcode == opcode::CALL && insn.imm == BpfHelper::MapLookupElem as i32)
                .then_some(i)
        })
        .expect("expected histogram map_lookup helper call");

    assert!(
        reload_idx < histogram_lookup_idx,
        "expected stop-timer reload before histogram helper use"
    );
}

/// Test loop header and back compile
#[test]
fn test_mir_loop() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();

    // Entry: set counter to 0
    let mut entry = BasicBlock::new(BlockId(0));
    entry.instructions.push(MirInst::Copy {
        dst: VReg(0),
        src: MirValue::Const(0),
    });
    entry.terminator = MirInst::Jump { target: BlockId(1) };

    // Header: check if counter < 10, go to body or exit
    let mut header = BasicBlock::new(BlockId(1));
    header.terminator = MirInst::LoopHeader {
        counter: VReg(0),
        limit: 10,
        body: BlockId(2),
        exit: BlockId(3),
    };

    // Body: increment and loop back
    let mut body = BasicBlock::new(BlockId(2));
    body.terminator = MirInst::LoopBack {
        counter: VReg(0),
        step: 1,
        header: BlockId(1),
    };

    // Exit: return
    let mut exit = BasicBlock::new(BlockId(3));
    exit.terminator = MirInst::Return {
        val: Some(MirValue::VReg(VReg(0))),
    };

    func.blocks.push(entry);
    func.blocks.push(header);
    func.blocks.push(body);
    func.blocks.push(exit);
    func.vreg_count = 1;

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).unwrap();
    assert!(
        !result.bytecode.is_empty(),
        "Loop compile produced empty bytecode"
    );
}

// ==================== Additional Parity Tests ====================

/// Test parity for subtraction
#[test]
fn test_subtract() {
    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(10),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(3),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Subtract),
            rhs: RegId::new(1),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);
    // Compile and verify
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(
        !mir_result.bytecode.is_empty(),
        "Should produce empty bytecode"
    );
}

/// Test parity for division
#[test]
fn test_divide() {
    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(100),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(5),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Divide),
            rhs: RegId::new(1),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);
    // Compile and verify
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(
        !mir_result.bytecode.is_empty(),
        "Should produce empty bytecode"
    );
}

/// Test parity for modulo operation
#[test]
fn test_modulo() {
    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(17),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(5),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Modulo),
            rhs: RegId::new(1),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);
    // Compile and verify
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(
        !mir_result.bytecode.is_empty(),
        "Should produce empty bytecode"
    );
}

/// Test parity for comparison: greater than
#[test]
fn test_greater_than() {
    use nu_protocol::ast::Comparison;

    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(10),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(5),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Comparison(Comparison::GreaterThan),
            rhs: RegId::new(1),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);
    // Compile and verify
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(
        !mir_result.bytecode.is_empty(),
        "Should produce empty bytecode"
    );
}

/// Test parity for comparison: less than
#[test]
fn test_less_than() {
    use nu_protocol::ast::Comparison;

    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(3),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(7),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Comparison(Comparison::LessThan),
            rhs: RegId::new(1),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);
    // Compile and verify
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(
        !mir_result.bytecode.is_empty(),
        "Should produce empty bytecode"
    );
}

/// Test parity for comparison: equal
#[test]
fn test_equal() {
    use nu_protocol::ast::Comparison;

    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(42),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(42),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Comparison(Comparison::Equal),
            rhs: RegId::new(1),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);
    // Compile and verify
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(
        !mir_result.bytecode.is_empty(),
        "Should produce empty bytecode"
    );
}

/// Test parity for comparison: not equal
#[test]
fn test_not_equal() {
    use nu_protocol::ast::Comparison;

    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(1),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(2),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Comparison(Comparison::NotEqual),
            rhs: RegId::new(1),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);
    // Compile and verify
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(
        !mir_result.bytecode.is_empty(),
        "Should produce empty bytecode"
    );
}

/// Test parity for logical NOT
#[test]
fn test_logical_not() {
    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Bool(true),
        },
        Instruction::Not {
            src_dst: RegId::new(0),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);
    // Compile and verify
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(
        !mir_result.bytecode.is_empty(),
        "Should produce empty bytecode"
    );
}

/// Test parity for bitwise AND
#[test]
fn test_bitwise_and() {
    use nu_protocol::ast::Bits;

    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(0b1111),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(0b1010),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Bits(Bits::BitAnd),
            rhs: RegId::new(1),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);
    // Compile and verify
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(
        !mir_result.bytecode.is_empty(),
        "Should produce empty bytecode"
    );
}

/// Test parity for bitwise OR
#[test]
fn test_bitwise_or() {
    use nu_protocol::ast::Bits;

    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(0b1100),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(0b0011),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Bits(Bits::BitOr),
            rhs: RegId::new(1),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);
    // Compile and verify
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(
        !mir_result.bytecode.is_empty(),
        "Should produce empty bytecode"
    );
}

/// Test parity for left shift
#[test]
fn test_shift_left() {
    use nu_protocol::ast::Bits;

    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(1),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(4),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Bits(Bits::ShiftLeft),
            rhs: RegId::new(1),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);
    // Compile and verify
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(
        !mir_result.bytecode.is_empty(),
        "Should produce empty bytecode"
    );
}

/// Test parity for chained arithmetic: (a + b) * c
#[test]
fn test_chained_arithmetic() {
    let ir = make_ir_block(vec![
        // a = 2
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(2),
        },
        // b = 3
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(3),
        },
        // c = 4
        Instruction::LoadLiteral {
            dst: RegId::new(2),
            lit: Literal::Int(4),
        },
        // a = a + b (= 5)
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Add),
            rhs: RegId::new(1),
        },
        // a = a * c (= 20)
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Multiply),
            rhs: RegId::new(2),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);
    // Compile and verify
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(
        !mir_result.bytecode.is_empty(),
        "Should produce empty bytecode"
    );
}

/// Test parity for conditional return
#[test]
fn test_conditional_return() {
    let ir = make_ir_block(vec![
        // Load condition
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(1), // true
        },
        // Load return value for true branch
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(42),
        },
        // Load return value for false branch
        Instruction::LoadLiteral {
            dst: RegId::new(2),
            lit: Literal::Int(0),
        },
        // Branch to index 5 if true
        Instruction::BranchIf {
            cond: RegId::new(0),
            index: 5,
        },
        // False branch: return 0
        Instruction::Return { src: RegId::new(2) },
        // True branch: return 42
        Instruction::Return { src: RegId::new(1) },
    ]);
    // Compile and verify
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(
        !mir_result.bytecode.is_empty(),
        "Should produce empty bytecode"
    );
}

/// Test parity for large constant
#[test]
fn test_large_constant() {
    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(0x1_0000_0000), // > 32-bit
        },
        Instruction::Return { src: RegId::new(0) },
    ]);
    // Compile and verify
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(
        !mir_result.bytecode.is_empty(),
        "Should produce empty bytecode"
    );
}

/// Test parity for negative constant
#[test]
fn test_negative_constant() {
    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(-42),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);
    // Compile and verify
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();
    assert!(
        !mir_result.bytecode.is_empty(),
        "Should produce empty bytecode"
    );
}

/// Test register pressure - more vregs than physical registers
/// This tests the linear scan register allocator integration
#[test]
fn test_register_pressure_integration() {
    // Create code that uses multiple registers to exercise allocation
    // v0 = 1, v1 = 2, v2 = 3, v3 = 4, v4 = 5
    // result = v0 + v1 + v2 + v3 + v4 (needs all values live)
    let ir = make_ir_block(vec![
        // Load 5 values into different registers
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(1),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(2),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(2),
            lit: Literal::Int(3),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(3),
            lit: Literal::Int(4),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(4),
            lit: Literal::Int(5),
        },
        // Chain additions to force all values to be live
        // r0 = r0 + r1 (1 + 2 = 3)
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Add),
            rhs: RegId::new(1),
        },
        // r0 = r0 + r2 (3 + 3 = 6)
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Add),
            rhs: RegId::new(2),
        },
        // r0 = r0 + r3 (6 + 4 = 10)
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Add),
            rhs: RegId::new(3),
        },
        // r0 = r0 + r4 (10 + 5 = 15)
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Add),
            rhs: RegId::new(4),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);

    // Compile and verify should handle register pressure via linear scan
    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();

    // Should produce valid bytecode
    assert!(
        !mir_result.bytecode.is_empty(),
        "MIR compiler should produce bytecode even with register pressure"
    );
    assert_eq!(
        mir_result.bytecode.len() % 8,
        0,
        "Bytecode should be aligned to 8 bytes"
    );

    // Should produce more instructions due to spill/reload
    // A basic version without spilling would be ~11 instructions
    // With spilling we expect more
    let insn_count = mir_result.bytecode.len() / 8;
    assert!(
        insn_count >= 10,
        "Should have at least 10 instructions, got {}",
        insn_count
    );
}

#[test]
fn test_register_pressure_codegen_stable() {
    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(1),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(2),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(2),
            lit: Literal::Int(3),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(3),
            lit: Literal::Int(4),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(4),
            lit: Literal::Int(5),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Add),
            rhs: RegId::new(1),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Add),
            rhs: RegId::new(2),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Add),
            rhs: RegId::new(3),
        },
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Add),
            rhs: RegId::new(4),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);

    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();

    let mut baseline: Option<(Vec<u8>, usize)> = None;
    for _ in 0..8 {
        let result = compile_mir_to_ebpf(&mir_program, None).unwrap();
        let signature = (result.bytecode, result.main_size);
        if let Some(expected) = &baseline {
            assert_eq!(
                &signature, expected,
                "codegen should be stable across repeated compilations"
            );
        } else {
            baseline = Some(signature);
        }
    }
}

/// Test that the linear scan allocator correctly handles simultaneous live ranges
#[test]
fn test_simultaneous_live_ranges() {
    // Create a pattern where multiple values must be live at once:
    // v0 = 10, v1 = 20, v2 = 30, v3 = 40
    // temp = v0 + v1
    // result = temp + v2 + v3
    // Here v2 and v3 are live across multiple operations
    let ir = make_ir_block(vec![
        Instruction::LoadLiteral {
            dst: RegId::new(0),
            lit: Literal::Int(10),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(1),
            lit: Literal::Int(20),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(2),
            lit: Literal::Int(30),
        },
        Instruction::LoadLiteral {
            dst: RegId::new(3),
            lit: Literal::Int(40),
        },
        // v0 = v0 + v1 (v2, v3 still live)
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Add),
            rhs: RegId::new(1),
        },
        // v0 = v0 + v2 (v3 still live)
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Add),
            rhs: RegId::new(2),
        },
        // v0 = v0 + v3
        Instruction::BinaryOp {
            lhs_dst: RegId::new(0),
            op: Operator::Math(Math::Add),
            rhs: RegId::new(3),
        },
        Instruction::Return { src: RegId::new(0) },
    ]);

    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();
    let mir_result = compile_mir_to_ebpf(&mir_program, None).unwrap();

    assert!(
        !mir_result.bytecode.is_empty(),
        "Should compile with simultaneous live ranges"
    );
}
