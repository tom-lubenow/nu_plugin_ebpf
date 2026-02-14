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
