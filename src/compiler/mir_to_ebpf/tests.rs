
use super::*;
use crate::compiler::ir_to_mir::lower_ir_to_mir;
use crate::compiler::mir_to_lir::lower_mir_to_lir;
use nu_protocol::RegId;
use nu_protocol::ast::{Math, Operator};
use nu_protocol::ir::{Instruction, IrBlock, Literal};
use std::sync::Arc;

fn make_ir_block(instructions: Vec<Instruction>) -> IrBlock {
    IrBlock {
        instructions,
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec![],
        register_count: 10,
        file_count: 0,
    }
}

/// Test valid bytecode for return zero
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

#[test]
fn test_string_literal_lowering_populates_buffer() {
    use crate::compiler::mir::{MirInst, StringAppendType};
    use nu_protocol::ir::DataSlice;

    let mut data = Vec::new();
    data.extend_from_slice(b"hello");
    let ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::String(DataSlice { start: 0, len: 5 }),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from(data),
        ast: vec![],
        comments: vec![],
        register_count: 2,
        file_count: 0,
    };

    let mir_program =
        lower_ir_to_mir(&ir, None, &HashMap::new(), &HashMap::new(), &[], None).unwrap();

    let saw_literal_append = mir_program.main.blocks.iter().any(|block| {
        block.instructions.iter().any(|inst| match inst {
            MirInst::StringAppend {
                val_type: StringAppendType::Literal { bytes },
                ..
            } => bytes.starts_with(b"hello") && bytes.len() == 16 && bytes[5] == 0,
            _ => false,
        })
    });

    assert!(
        saw_literal_append,
        "Expected string literal to populate stack buffer via StringAppend"
    );
}

#[test]
fn test_emit_event_copies_buffer() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let v0 = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::EmitEvent { data: v0, size: 16 });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let lir = lower_mir_to_lir(&program);
    let mut compiler = MirToEbpfCompiler::new(&lir, None);
    compiler
        .prepare_function_state(
            &lir.main,
            compiler.available_regs.clone(),
            lir.main.precolored.clone(),
        )
        .unwrap();
    compiler.compile_function(&lir.main).unwrap();
    compiler.fixup_jumps().unwrap();

    // After graph coloring, VReg(0) should be assigned a register
    let data_reg = compiler
        .vreg_to_phys
        .get(&VReg(0))
        .copied()
        .expect("VReg(0) should be assigned a physical register by graph coloring");
    let saw_copy = compiler.instructions.iter().any(|insn| {
        insn.opcode == (opcode::BPF_LDX | opcode::BPF_DW | opcode::BPF_MEM)
            && insn.dst_reg == EbpfReg::R0.as_u8()
            && insn.src_reg == data_reg.as_u8()
    });

    assert!(saw_copy, "Expected buffer copy from pointer for emit");
}

#[test]
fn test_emit_record_schema_mismatch_errors() {
    use crate::compiler::CompileError;
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::Const(2),
    });

    func.block_mut(entry)
        .instructions
        .push(MirInst::EmitRecord {
            fields: vec![RecordFieldDef {
                name: "a".to_string(),
                value: v0,
                ty: MirType::I64,
            }],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::EmitRecord {
            fields: vec![RecordFieldDef {
                name: "b".to_string(),
                value: v1,
                ty: MirType::I64,
            }],
        });

    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None);
    match result {
        Err(CompileError::UnsupportedInstruction(msg)) => {
            assert!(
                msg.contains("schema mismatch"),
                "Unexpected error message: {msg}"
            );
        }
        Ok(_) => panic!("Expected schema mismatch error, got Ok"),
        Err(e) => panic!("Expected schema mismatch error, got: {e:?}"),
    }
}

#[test]
fn test_string_counter_map_emitted() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let v0 = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: STRING_COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Hash,
        },
        key: v0,
        val: v0,
        flags: 0,
    });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).unwrap();
    let map = result
        .maps
        .iter()
        .find(|m| m.name == STRING_COUNTER_MAP_NAME)
        .expect("Expected string counter map");
    assert_eq!(map.def.key_size, 16);
}

#[test]
fn test_counter_map_emits_per_cpu_kind() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: COUNTER_MAP_NAME.to_string(),
            kind: MapKind::PerCpuHash,
        },
        key,
        val: key,
        flags: 0,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    let result = compile_mir_to_ebpf(&program, None).expect("counter map should compile");

    let map = result
        .maps
        .iter()
        .find(|m| m.name == COUNTER_MAP_NAME)
        .expect("expected counters map");
    assert_eq!(
        map.def.map_type,
        crate::compiler::elf::BpfMapType::PerCpuHash as u32
    );
}

#[test]
fn test_counter_map_kind_conflict_rejected() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key0 = func.alloc_vreg();
    let key1 = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key0,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key1,
        src: MirValue::Const(2),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Hash,
        },
        key: key0,
        val: key0,
        flags: 0,
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: COUNTER_MAP_NAME.to_string(),
            kind: MapKind::PerCpuHash,
        },
        key: key1,
        val: key1,
        flags: 0,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    match compile_mir_to_ebpf(&program, None) {
        Ok(_) => panic!("expected kind conflict"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("conflicting kinds"),
                "unexpected error message: {msg}"
            );
        }
    }
}

#[test]
fn test_counter_map_rejects_non_hash_kind() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(9),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Array,
        },
        key,
        val: key,
        flags: 0,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    match compile_mir_to_ebpf(&program, None) {
        Ok(_) => panic!("expected kind rejection"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("Hash/PerCpuHash"),
                "unexpected error message: {msg}"
            );
        }
    }
}

#[test]
fn test_map_lookup_compiles_and_emits_generic_map() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst,
        map: MapRef {
            name: "custom_lookup".to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).expect("map lookup should compile");
    let map = result
        .maps
        .iter()
        .find(|m| m.name == "custom_lookup")
        .expect("expected generic map definition");
    assert_eq!(map.def.key_size, 8);
    assert_eq!(map.def.value_size, 8);
    assert!(
        result
            .relocations
            .iter()
            .any(|r| r.map_name == "custom_lookup")
    );

    let has_lookup_helper = result.bytecode.chunks(8).any(|chunk| {
        chunk[0] == opcode::CALL
            && i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]])
                == BpfHelper::MapLookupElem as i32
    });
    assert!(
        has_lookup_helper,
        "expected bpf_map_lookup_elem helper call"
    );
}

#[test]
fn test_map_update_compiles_and_emits_generic_map() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let val = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(42),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: val,
        src: MirValue::Const(99),
    });
    func.block_mut(entry).instructions.push(MirInst::MapUpdate {
        map: MapRef {
            name: "custom_update".to_string(),
            kind: MapKind::Hash,
        },
        key,
        val,
        flags: 1,
    });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).expect("map update should compile");
    let map = result
        .maps
        .iter()
        .find(|m| m.name == "custom_update")
        .expect("expected generic map definition");
    assert_eq!(map.def.key_size, 8);
    assert_eq!(map.def.value_size, 8);
    assert!(
        result
            .relocations
            .iter()
            .any(|r| r.map_name == "custom_update")
    );

    let has_update_helper = result.bytecode.chunks(8).any(|chunk| {
        chunk[0] == opcode::CALL
            && i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]])
                == BpfHelper::MapUpdateElem as i32
    });
    assert!(
        has_update_helper,
        "expected bpf_map_update_elem helper call"
    );
}

#[test]
fn test_map_delete_compiles_and_emits_generic_map() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(11),
    });
    func.block_mut(entry).instructions.push(MirInst::MapDelete {
        map: MapRef {
            name: "custom_delete".to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).expect("map delete should compile");
    let map = result
        .maps
        .iter()
        .find(|m| m.name == "custom_delete")
        .expect("expected generic map definition");
    assert_eq!(map.def.key_size, 8);
    assert_eq!(map.def.value_size, 8);
    assert!(
        result
            .relocations
            .iter()
            .any(|r| r.map_name == "custom_delete")
    );

    let has_delete_helper = result.bytecode.chunks(8).any(|chunk| {
        chunk[0] == opcode::CALL
            && i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]])
                == BpfHelper::MapDeleteElem as i32
    });
    assert!(
        has_delete_helper,
        "expected bpf_map_delete_elem helper call"
    );
}

#[test]
fn test_map_delete_rejects_array_maps() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapDelete {
        map: MapRef {
            name: "array_delete".to_string(),
            kind: MapKind::Array,
        },
        key,
    });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    match compile_mir_to_ebpf(&program, None) {
        Ok(_) => panic!("expected array map delete rejection, got Ok"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("array map kind") || msg.contains("Array"),
                "unexpected error: {msg}"
            );
        }
    }
}

#[test]
fn test_tail_call_compiles_and_emits_prog_array_map() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let idx = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: idx,
        src: MirValue::Const(3),
    });
    func.block_mut(entry).terminator = MirInst::TailCall {
        prog_map: MapRef {
            name: "tail_targets".to_string(),
            kind: MapKind::ProgArray,
        },
        index: MirValue::VReg(idx),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).expect("tail call should compile");
    let map = result
        .maps
        .iter()
        .find(|m| m.name == "tail_targets")
        .expect("expected prog array map");
    assert_eq!(
        map.def.map_type,
        crate::compiler::elf::BpfMapType::ProgArray as u32
    );
    assert!(
        result
            .relocations
            .iter()
            .any(|r| r.map_name == "tail_targets")
    );

    let has_tail_call_helper = result.bytecode.chunks(8).any(|chunk| {
        chunk[0] == opcode::CALL
            && i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]])
                == BpfHelper::TailCall as i32
    });
    assert!(has_tail_call_helper, "expected bpf_tail_call helper call");
}

#[test]
fn test_tail_call_rejects_non_prog_array_map() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.block_mut(entry).terminator = MirInst::TailCall {
        prog_map: MapRef {
            name: "bad_tail_map".to_string(),
            kind: MapKind::Hash,
        },
        index: MirValue::Const(0),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    match compile_mir_to_ebpf(&program, None) {
        Ok(_) => panic!("expected non-prog-array map error, got Ok"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("ProgArray") || msg.contains("prog array"),
                "unexpected error: {msg}"
            );
        }
    }
}

#[test]
fn test_helper_call_rejects_more_than_five_args() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let mut args = Vec::new();
    for n in 0..6 {
        let v = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: v,
            src: MirValue::Const(n),
        });
        args.push(MirValue::VReg(v));
    }
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 9999, // Unknown helper still follows generic 5-arg limit
            args,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    match compile_mir_to_ebpf(&program, None) {
        Ok(_) => panic!("expected argument-limit error, got Ok"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("at most 5 arguments"),
                "unexpected error: {msg}"
            );
        }
    }
}

#[test]
fn test_kfunc_call_with_explicit_btf_id_compiles() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let cgid = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let level = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cgid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ptr,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![cgid],
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: level,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };
    func.block_mut(call).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_cgroup_ancestor".to_string(),
        btf_id: Some(321),
        args: vec![ptr, level],
    });
    func.block_mut(call).terminator = MirInst::Jump { target: release };
    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_cgroup_release".to_string(),
            btf_id: None,
            args: vec![ptr],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None).expect("kfunc call should compile");
    let has_kfunc_call = result.bytecode.chunks(8).any(|chunk| {
        chunk[0] == opcode::CALL
            && ((chunk[1] >> 4) & 0x0f) == 2
            && i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]) == 321
    });
    assert!(has_kfunc_call, "expected BPF_PSEUDO_KFUNC_CALL bytecode");
}

#[test]
fn test_kfunc_task_release_compiles_with_copied_cond_and_join() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond0 = func.alloc_vreg();
    let cond1 = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let then_val = func.alloc_vreg();
    let else_val = func.alloc_vreg();
    let result = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond0,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cond1,
        src: MirValue::VReg(cond0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cond1,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).instructions.push(MirInst::Copy {
        dst: then_val,
        src: MirValue::Const(0),
    });
    func.block_mut(release).terminator = MirInst::Jump { target: join };

    func.block_mut(done).instructions.push(MirInst::Copy {
        dst: else_val,
        src: MirValue::Const(0),
    });
    func.block_mut(done).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::Phi {
        dst: result,
        args: vec![(release, then_val), (done, else_val)],
    });
    func.block_mut(join).terminator = MirInst::Return {
        val: Some(MirValue::VReg(result)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    compile_mir_to_ebpf(&program, None)
        .expect("expected copied null-check guard to preserve kfunc release semantics");
}

#[test]
fn test_kfunc_task_release_compiles_with_negated_cond() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let negated = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::UnaryOp {
        dst: negated,
        op: UnaryOpKind::Not,
        src: MirValue::VReg(cond),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: negated,
        if_true: done,
        if_false: release,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    compile_mir_to_ebpf(&program, None)
        .expect("expected negated null-check guard to preserve kfunc release semantics");
}

#[test]
fn test_kfunc_call_rejects_unknown_signature() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let arg = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: arg,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "definitely_not_a_known_kfunc".to_string(),
        btf_id: Some(1),
        args: vec![arg],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    match compile_mir_to_ebpf(&program, None) {
        Ok(_) => panic!("expected unknown-kfunc error, got Ok"),
        Err(err) => {
            let msg = err.to_string();
            assert!(msg.contains("unknown kfunc"), "unexpected error: {msg}");
        }
    }
}

#[test]
fn test_subfunction_call_rejects_more_than_five_args() {
    use crate::compiler::mir::*;

    let mut subfn = MirFunction::with_name("too_many_args");
    subfn.param_count = 6;
    let sub_entry = subfn.alloc_block();
    subfn.entry = sub_entry;
    subfn.block_mut(sub_entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let mut main = MirFunction::new();
    let entry = main.alloc_block();
    main.entry = entry;

    let mut args = Vec::new();
    for n in 0..6 {
        let v = main.alloc_vreg();
        main.block_mut(entry).instructions.push(MirInst::Copy {
            dst: v,
            src: MirValue::Const(10 + n),
        });
        args.push(v);
    }
    let dst = main.alloc_vreg();
    main.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst,
        subfn: SubfunctionId(0),
        args,
    });
    main.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(dst)),
    };

    let program = MirProgram {
        main,
        subfunctions: vec![subfn],
    };

    match compile_mir_to_ebpf(&program, None) {
        Ok(_) => panic!("expected argument-limit error, got Ok"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("at most 5 arguments"),
                "unexpected error: {msg}"
            );
        }
    }
}

// ==================== BPF-to-BPF Function Call Tests ====================

/// Test BPF-to-BPF function call compiles correctly
#[test]
fn test_bpf_to_bpf_call_simple() {
    use crate::compiler::mir::*;

    // Create a subfunction that adds 1 to its argument and returns it
    let mut subfn = MirFunction::with_name("add_one");
    subfn.param_count = 1;
    let entry = subfn.alloc_block();
    subfn.entry = entry;

    // Subfunction: R1 = arg, return R1 + 1
    // VReg(0) represents the first argument (passed in R1)
    let v0 = VReg(0);
    let v1 = subfn.alloc_vreg(); // Result

    subfn.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: v1,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::Const(1),
    });
    subfn.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v1)),
    };

    // Create main function that calls the subfunction
    let mut main_func = MirFunction::new();
    let main_entry = main_func.alloc_block();
    main_func.entry = main_entry;

    let arg = main_func.alloc_vreg();
    let result = main_func.alloc_vreg();

    // Load argument value
    main_func
        .block_mut(main_entry)
        .instructions
        .push(MirInst::Copy {
            dst: arg,
            src: MirValue::Const(41),
        });

    // Call subfunction with arg
    main_func
        .block_mut(main_entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: result,
            subfn: SubfunctionId(0),
            args: vec![arg],
        });

    // Return result
    main_func.block_mut(main_entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(result)),
    };

    let program = MirProgram {
        main: main_func,
        subfunctions: vec![subfn],
    };

    let result = compile_mir_to_ebpf(&program, None).unwrap();
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");

    // The bytecode should contain a call instruction
    // BPF call instruction has opcode 0x85 (for local calls with src_reg=1)
    let has_call = result.bytecode.chunks(8).any(|chunk| {
        chunk[0] == 0x85 && chunk[1] & 0xf0 == 0x10 // opcode CALL with src_reg=1
    });
    assert!(has_call, "Should contain a BPF-to-BPF call instruction");
}

/// Test BPF-to-BPF call with multiple arguments
#[test]
fn test_bpf_to_bpf_call_multi_args() {
    use crate::compiler::mir::*;

    // Create a subfunction that adds two arguments
    let mut subfn = MirFunction::with_name("add_two");
    subfn.param_count = 2;
    let entry = subfn.alloc_block();
    subfn.entry = entry;

    // VReg(0) = arg0, VReg(1) = arg1
    let arg0 = VReg(0);
    let arg1 = VReg(1);
    let result = subfn.alloc_vreg();

    subfn.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: result,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(arg0),
        rhs: MirValue::VReg(arg1),
    });
    subfn.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(result)),
    };

    // Create main function
    let mut main_func = MirFunction::new();
    let main_entry = main_func.alloc_block();
    main_func.entry = main_entry;

    let a = main_func.alloc_vreg();
    let b = main_func.alloc_vreg();
    let result = main_func.alloc_vreg();

    main_func
        .block_mut(main_entry)
        .instructions
        .push(MirInst::Copy {
            dst: a,
            src: MirValue::Const(10),
        });
    main_func
        .block_mut(main_entry)
        .instructions
        .push(MirInst::Copy {
            dst: b,
            src: MirValue::Const(32),
        });

    main_func
        .block_mut(main_entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: result,
            subfn: SubfunctionId(0),
            args: vec![a, b],
        });

    main_func.block_mut(main_entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(result)),
    };

    let program = MirProgram {
        main: main_func,
        subfunctions: vec![subfn],
    };

    let result = compile_mir_to_ebpf(&program, None).unwrap();
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

/// Test multiple BPF-to-BPF calls to the same function
#[test]
fn test_bpf_to_bpf_multiple_calls() {
    use crate::compiler::mir::*;

    // Create a subfunction
    let mut subfn = MirFunction::with_name("double");
    subfn.param_count = 1;
    let entry = subfn.alloc_block();
    subfn.entry = entry;

    let arg = VReg(0);
    let result = subfn.alloc_vreg();

    subfn.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: result,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(arg),
        rhs: MirValue::Const(2),
    });
    subfn.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(result)),
    };

    // Main function calls the subfunction twice
    let mut main_func = MirFunction::new();
    let main_entry = main_func.alloc_block();
    main_func.entry = main_entry;

    let v0 = main_func.alloc_vreg();
    let v1 = main_func.alloc_vreg();
    let v2 = main_func.alloc_vreg();

    main_func
        .block_mut(main_entry)
        .instructions
        .push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(5),
        });

    // First call: double(5)
    main_func
        .block_mut(main_entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: v1,
            subfn: SubfunctionId(0),
            args: vec![v0],
        });

    // Second call: double(result of first call)
    main_func
        .block_mut(main_entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: v2,
            subfn: SubfunctionId(0),
            args: vec![v1],
        });

    main_func.block_mut(main_entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v2)),
    };

    let program = MirProgram {
        main: main_func,
        subfunctions: vec![subfn],
    };

    let result = compile_mir_to_ebpf(&program, None).unwrap();
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");

    // Count call instructions
    let call_count = result
        .bytecode
        .chunks(8)
        .filter(|chunk| chunk[0] == 0x85 && chunk[1] & 0xf0 == 0x10)
        .count();
    assert_eq!(call_count, 2, "Should have 2 BPF-to-BPF call instructions");
}

/// Test that call instruction offsets are correct
#[test]
fn test_bpf_to_bpf_call_offset_verification() {
    use crate::compiler::mir::*;

    // Create a simple subfunction: return arg + 100
    let mut subfn = MirFunction::with_name("add_hundred");
    subfn.param_count = 1;
    let entry = subfn.alloc_block();
    subfn.entry = entry;

    let arg = VReg(0);
    let result_vreg = subfn.alloc_vreg();

    subfn.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: result_vreg,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(arg),
        rhs: MirValue::Const(100),
    });
    subfn.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(result_vreg)),
    };

    // Create main function that calls the subfunction
    let mut main_func = MirFunction::new();
    let main_entry = main_func.alloc_block();
    main_func.entry = main_entry;

    let input = main_func.alloc_vreg();
    let output = main_func.alloc_vreg();

    main_func
        .block_mut(main_entry)
        .instructions
        .push(MirInst::Copy {
            dst: input,
            src: MirValue::Const(42),
        });

    main_func
        .block_mut(main_entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: output,
            subfn: SubfunctionId(0),
            args: vec![input],
        });

    main_func.block_mut(main_entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(output)),
    };

    let program = MirProgram {
        main: main_func,
        subfunctions: vec![subfn],
    };

    let result = compile_mir_to_ebpf(&program, None).unwrap();

    // Find the call instruction and verify its offset
    let mut call_idx = None;
    let mut call_offset: Option<i32> = None;

    for (i, chunk) in result.bytecode.chunks(8).enumerate() {
        if chunk[0] == 0x85 && chunk[1] & 0xf0 == 0x10 {
            // This is a BPF-to-BPF call
            call_idx = Some(i);
            // imm is at bytes 4-7 (little endian)
            call_offset = Some(i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]));
            break;
        }
    }

    assert!(call_idx.is_some(), "Should find a call instruction");
    let call_idx = call_idx.unwrap();
    let call_offset = call_offset.unwrap();

    // The subfunction should start after the main function's code
    // The call offset is relative: target = call_idx + 1 + offset
    let target_idx = (call_idx as i32 + 1 + call_offset) as usize;
    let total_instructions = result.bytecode.len() / 8;

    assert!(
        target_idx < total_instructions,
        "Call target {} should be within bytecode (total: {})",
        target_idx,
        total_instructions
    );

    // Verify the subfunction exists at the target location
    // It should have some instructions (not all zeros)
    let subfunction_start = target_idx * 8;
    let subfn_first_insn = &result.bytecode[subfunction_start..subfunction_start + 8];
    assert!(
        subfn_first_insn.iter().any(|&b| b != 0),
        "Subfunction should have non-zero instructions"
    );

    println!(
        "Call at instruction {}, offset {}, targets instruction {}",
        call_idx, call_offset, target_idx
    );
    println!("Total instructions: {}", total_instructions);
}

/// Test bytecode disassembly for debugging
#[test]
fn test_bpf_to_bpf_bytecode_structure() {
    use crate::compiler::mir::*;

    // Simple subfunction that returns its argument * 2
    let mut subfn = MirFunction::with_name("double");
    subfn.param_count = 1;
    let entry = subfn.alloc_block();
    subfn.entry = entry;

    let arg = VReg(0);
    let result_vreg = subfn.alloc_vreg();

    subfn.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: result_vreg,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(arg),
        rhs: MirValue::Const(2),
    });
    subfn.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(result_vreg)),
    };

    // Main function
    let mut main_func = MirFunction::new();
    let main_entry = main_func.alloc_block();
    main_func.entry = main_entry;

    let v0 = main_func.alloc_vreg();
    let v1 = main_func.alloc_vreg();

    main_func
        .block_mut(main_entry)
        .instructions
        .push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(21),
        });

    main_func
        .block_mut(main_entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: v1,
            subfn: SubfunctionId(0),
            args: vec![v0],
        });

    main_func.block_mut(main_entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(v1)),
    };

    let program = MirProgram {
        main: main_func,
        subfunctions: vec![subfn],
    };

    let result = compile_mir_to_ebpf(&program, None).unwrap();

    // Disassemble and print
    println!("\n=== BPF-to-BPF Call Bytecode ===");
    for (i, chunk) in result.bytecode.chunks(8).enumerate() {
        let opcode = chunk[0];
        let regs = chunk[1];
        let dst = regs & 0x0f;
        let src = (regs >> 4) & 0x0f;
        let offset = i16::from_le_bytes([chunk[2], chunk[3]]);
        let imm = i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);

        let desc = match opcode {
            0x85 if src == 1 => format!("call local +{}", imm),
            0x85 => format!("call helper #{}", imm),
            0xb7 => format!("mov r{}, {}", dst, imm),
            0xbf => format!("mov r{}, r{}", dst, src),
            0x0f => format!("add r{}, r{}", dst, src),
            0x07 => format!("add r{}, {}", dst, imm),
            0x2f => format!("mul r{}, r{}", dst, src),
            0x27 => format!("mul r{}, {}", dst, imm),
            0x95 => "exit".to_string(),
            _ => format!(
                "op={:#04x} dst=r{} src=r{} off={} imm={}",
                opcode, dst, src, offset, imm
            ),
        };

        println!(
            "{:4}: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}  ; {}",
            i, chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7], desc
        );
    }
    println!("=================================\n");

    // Verify structure
    let total = result.bytecode.len() / 8;
    assert!(total >= 4, "Should have at least 4 instructions");

    // Find exit instructions (opcode 0x95)
    let exit_count = result.bytecode.chunks(8).filter(|c| c[0] == 0x95).count();
    assert!(
        exit_count >= 2,
        "Should have at least 2 exit instructions (main + subfunction)"
    );
}

#[test]
fn test_string_append_literal() {
    // Test appending a literal string
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    // Allocate stack slot for string buffer
    let slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);

    // Allocate vreg for length tracking
    let len_vreg = func.alloc_vreg();

    // Initialize length to 0
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: len_vreg,
        src: MirValue::Const(0),
    });

    // Append "hello" literal
    func.block_mut(entry)
        .instructions
        .push(MirInst::StringAppend {
            dst_buffer: slot,
            dst_len: len_vreg,
            val: MirValue::Const(0), // Not used for literals
            val_type: StringAppendType::Literal {
                bytes: b"hello".to_vec(),
            },
        });

    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let lir = lower_mir_to_lir(&program);
    let compiler = MirToEbpfCompiler::new(&lir, None);
    let result = compiler.compile();

    assert!(result.is_ok(), "StringAppend literal should compile");
    let result = result.unwrap();
    assert!(!result.bytecode.is_empty(), "Should generate bytecode");
}

#[test]
fn test_int_to_string() {
    // Test integer to string conversion
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    // Allocate stack slot for string buffer
    let slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);

    // Allocate vregs
    let val_vreg = func.alloc_vreg();
    let len_vreg = func.alloc_vreg();

    // Load value 12345
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: val_vreg,
        src: MirValue::Const(12345),
    });

    // Convert to string
    func.block_mut(entry)
        .instructions
        .push(MirInst::IntToString {
            dst_buffer: slot,
            dst_len: len_vreg,
            val: val_vreg,
        });

    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let lir = lower_mir_to_lir(&program);
    let compiler = MirToEbpfCompiler::new(&lir, None);
    let result = compiler.compile();

    assert!(result.is_ok(), "IntToString should compile");
    let result = result.unwrap();
    assert!(!result.bytecode.is_empty(), "Should generate bytecode");
}

#[test]
fn test_string_append_slot() {
    // Test appending from another string slot
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    // Allocate source and dest stack slots
    let src_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let dst_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);

    // Allocate vregs
    let len_vreg = func.alloc_vreg();
    let src_vreg = func.alloc_vreg();

    // Initialize length to 0
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: len_vreg,
        src: MirValue::Const(0),
    });

    // Create src vreg pointing to slot
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: src_vreg,
        src: MirValue::StackSlot(src_slot),
    });

    // Append from source slot
    func.block_mut(entry)
        .instructions
        .push(MirInst::StringAppend {
            dst_buffer: dst_slot,
            dst_len: len_vreg,
            val: MirValue::VReg(src_vreg),
            val_type: StringAppendType::StringSlot {
                slot: src_slot,
                max_len: 32,
            },
        });

    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let lir = lower_mir_to_lir(&program);
    let compiler = MirToEbpfCompiler::new(&lir, None);
    let result = compiler.compile();

    assert!(result.is_ok(), "StringAppend slot should compile");
    let result = result.unwrap();
    assert!(!result.bytecode.is_empty(), "Should generate bytecode");
}

#[test]
fn test_string_append_integer() {
    // Test appending an integer to a string (integer interpolation)
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    // Allocate stack slot for string buffer
    let slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);

    // Allocate vregs
    let len_vreg = func.alloc_vreg();
    let int_vreg = func.alloc_vreg();

    // Initialize length to 0
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: len_vreg,
        src: MirValue::Const(0),
    });

    // Load integer value 12345
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: int_vreg,
        src: MirValue::Const(12345),
    });

    // Append integer to string
    func.block_mut(entry)
        .instructions
        .push(MirInst::StringAppend {
            dst_buffer: slot,
            dst_len: len_vreg,
            val: MirValue::VReg(int_vreg),
            val_type: StringAppendType::Integer,
        });

    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let lir = lower_mir_to_lir(&program);
    let compiler = MirToEbpfCompiler::new(&lir, None);
    let result = compiler.compile();

    assert!(result.is_ok(), "StringAppend integer should compile");
    let result = result.unwrap();
    assert!(!result.bytecode.is_empty(), "Should generate bytecode");
}

#[test]
fn test_string_append_integer_zero() {
    // Test appending zero to a string (edge case)
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    // Allocate stack slot for string buffer
    let slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);

    // Allocate vregs
    let len_vreg = func.alloc_vreg();
    let int_vreg = func.alloc_vreg();

    // Initialize length to 0
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: len_vreg,
        src: MirValue::Const(0),
    });

    // Load integer value 0
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: int_vreg,
        src: MirValue::Const(0),
    });

    // Append integer to string
    func.block_mut(entry)
        .instructions
        .push(MirInst::StringAppend {
            dst_buffer: slot,
            dst_len: len_vreg,
            val: MirValue::VReg(int_vreg),
            val_type: StringAppendType::Integer,
        });

    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let lir = lower_mir_to_lir(&program);
    let compiler = MirToEbpfCompiler::new(&lir, None);
    let result = compiler.compile();

    assert!(result.is_ok(), "StringAppend integer zero should compile");
    let result = result.unwrap();
    assert!(!result.bytecode.is_empty(), "Should generate bytecode");
}

/// Test list literal compilation with ListNew, ListPush, and EmitEvent
/// This tests the fix for the R0 initialization bug and proper register allocation
#[test]
fn test_list_literal_compilation() {
    use crate::compiler::cfg::CFG;
    use crate::compiler::mir::*;
    use crate::compiler::passes::{ListLowering, MirPass};

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    // Allocate stack slot for list buffer (length + 3 elements)
    let slot = func.alloc_stack_slot(32, 8, StackSlotKind::ListBuffer);

    // Allocate vregs
    let list_ptr = func.alloc_vreg();
    let item1 = func.alloc_vreg();
    let item2 = func.alloc_vreg();
    let item3 = func.alloc_vreg();

    // ListNew: initialize list buffer
    func.block_mut(entry).instructions.push(MirInst::ListNew {
        dst: list_ptr,
        buffer: slot,
        max_len: 3,
    });

    // Push elements
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: item1,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::ListPush {
        list: list_ptr,
        item: item1,
    });

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: item2,
        src: MirValue::Const(2),
    });
    func.block_mut(entry).instructions.push(MirInst::ListPush {
        list: list_ptr,
        item: item2,
    });

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: item3,
        src: MirValue::Const(3),
    });
    func.block_mut(entry).instructions.push(MirInst::ListPush {
        list: list_ptr,
        item: item3,
    });

    // Emit the list
    func.block_mut(entry).instructions.push(MirInst::EmitEvent {
        data: list_ptr,
        size: 32,
    });

    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let cfg = CFG::build(&func);
    let pass = ListLowering;
    assert!(pass.run(&mut func, &cfg));

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    // Compile and verify
    let lir = lower_mir_to_lir(&program);
    let mut compiler = MirToEbpfCompiler::new(&lir, None);
    compiler
        .prepare_function_state(
            &lir.main,
            compiler.available_regs.clone(),
            lir.main.precolored.clone(),
        )
        .unwrap();

    // Verify list_ptr (VReg 0) got a physical register
    assert!(
        compiler.vreg_to_phys.contains_key(&VReg(0)),
        "list_ptr vreg should be assigned a physical register"
    );

    compiler.compile_function(&lir.main).unwrap();
    compiler.fixup_jumps().unwrap();

    // Verify bytecode was generated
    assert!(
        !compiler.instructions.is_empty(),
        "Should generate bytecode for list literal"
    );

    // The first instructions should set up the list pointer (mov + add for R10 + offset)
    // Then initialize length to 0 (mov R0, 0; stxdw)
    let has_list_init = compiler.instructions.iter().any(|insn| {
        // Look for mov immediate 0 (R0 = 0 for length initialization)
        insn.opcode == (opcode::BPF_ALU64 | opcode::BPF_MOV | opcode::BPF_K) && insn.imm == 0
    });
    assert!(has_list_init, "Should have length initialization to 0");
}
