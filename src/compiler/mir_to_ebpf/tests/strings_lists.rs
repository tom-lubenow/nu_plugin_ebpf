use super::*;

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
fn test_string_append_literal_exact_nul() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let len_vreg = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: len_vreg,
        src: MirValue::Const(0),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::StringAppend {
            dst_buffer: slot,
            dst_len: len_vreg,
            val: MirValue::Const(0),
            val_type: StringAppendType::LiteralExact {
                bytes: vec![0; 16],
                len: 1,
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

    assert!(
        result.is_ok(),
        "StringAppend exact NUL literal should compile"
    );
    assert!(
        !result.unwrap().bytecode.is_empty(),
        "Should generate bytecode"
    );
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
fn test_int_to_string_zero_compare_initializes_r0_and_preserves_r0_value() {
    let program = LirProgram::new(LirFunction::new());
    let mut compiler = MirToEbpfCompiler::new(&program, None);
    let slot = StackSlotId(0);
    let val = VReg(0);
    let len = VReg(1);

    compiler.slot_offsets.insert(slot, -32);
    compiler.vreg_to_phys.insert(val, EbpfReg::R0);
    compiler.vreg_to_phys.insert(len, EbpfReg::R2);

    compiler
        .compile_int_to_string(slot, len, val)
        .expect("IntToString should lower with val in R0");

    let jne_reg = opcode::BPF_JMP | opcode::BPF_JNE | opcode::BPF_X;
    let jne_idx = compiler
        .instructions
        .iter()
        .position(|insn| {
            insn.opcode == jne_reg
                && insn.dst_reg == EbpfReg::R3.as_u8()
                && insn.src_reg == EbpfReg::R0.as_u8()
                && insn.offset == 6
        })
        .expect("expected zero-special-case compare against initialized R0");

    assert!(
        compiler.instructions[..jne_idx].iter().any(|insn| {
            insn.opcode == opcode::MOV64_REG
                && insn.dst_reg == EbpfReg::R3.as_u8()
                && insn.src_reg == EbpfReg::R0.as_u8()
        }),
        "value in R0 should be copied before R0 is initialized for comparison"
    );

    let zero_init = compiler.instructions[jne_idx - 1];
    assert_eq!(zero_init.opcode, opcode::MOV64_IMM);
    assert_eq!(zero_init.dst_reg, EbpfReg::R0.as_u8());
    assert_eq!(zero_init.imm, 0);

    let zero_done_jmp_idx =
        jne_idx + usize::try_from(compiler.instructions[jne_idx].offset).unwrap();
    let zero_done_jmp = compiler.instructions[zero_done_jmp_idx];
    assert_eq!(zero_done_jmp.opcode, opcode::BPF_JMP | opcode::BPF_JA);

    let non_zero_idx =
        jne_idx + 1 + usize::try_from(compiler.instructions[jne_idx].offset).unwrap();
    let non_zero_setup = compiler.instructions[non_zero_idx];
    assert_eq!(non_zero_setup.opcode, opcode::MOV64_REG);
    assert_eq!(non_zero_setup.dst_reg, EbpfReg::R3.as_u8());
    assert_eq!(non_zero_setup.src_reg, EbpfReg::R3.as_u8());

    let zero_done_idx = zero_done_jmp_idx + 1 + usize::try_from(zero_done_jmp.offset).unwrap();
    assert_eq!(
        zero_done_idx,
        compiler.instructions.len(),
        "zero path should jump past non-zero digit extraction"
    );

    assert!(
        compiler.instructions[non_zero_idx..].iter().any(|insn| {
            insn.opcode == (opcode::BPF_JMP | opcode::BPF_JEQ | opcode::BPF_K)
                && insn.dst_reg == EbpfReg::R3.as_u8()
                && insn.imm == 0
                && insn.offset == 9
        }),
        "digit extraction should skip the full unrolled iteration once R3 reaches zero"
    );
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
fn test_strcmp_compiles() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let lhs = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let rhs = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::StrCmp {
        dst,
        lhs,
        lhs_offset: 0,
        rhs,
        rhs_offset: 0,
        len: 8,
    });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(dst)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None);
    if let Err(err) = result {
        panic!("StrCmp should compile: {err:?}");
    }
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

    let emit_data = func
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .find_map(|inst| match inst {
            MirInst::EmitEvent { data, .. } => Some(*data),
            _ => None,
        })
        .expect("list lowering should preserve emit event");

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    // Compile and verify
    let lir = lower_mir_to_lir(&program);
    let mut program_types = ProgramVregTypes::default();
    program_types.main.insert(
        emit_data,
        MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 32,
            }),
            address_space: AddressSpace::Stack,
        },
    );
    let mut compiler = MirToEbpfCompiler::new_with_types(&lir, None, program_types.clone());
    compiler.current_types = program_types.main.clone();
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
