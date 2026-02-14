use super::*;

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
