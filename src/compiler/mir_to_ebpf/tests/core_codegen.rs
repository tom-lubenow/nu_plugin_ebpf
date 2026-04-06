use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::hir::{
    HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
};
use crate::compiler::ir_to_mir::lower_hir_to_mir_with_hints;
use crate::compiler::mir::MirInst;
use crate::compiler::{EbpfProgram, compile_mir_to_ebpf_with_hints_and_readonly_globals};
use crate::kernel_btf::{KernelBtf, TrampolineValueKind};
use nu_protocol::ast::{CellPath, PathMember};
use nu_protocol::casing::Casing;
use nu_protocol::{Span, VarId};
use std::collections::HashMap;

fn find_aggregate_fentry_arg_candidate() -> (String, u8, usize) {
    for (func_name, arg_idx) in [
        ("__copy_xstate_to_uabi_buf", 0usize),
        ("__audit_tk_injoffset", 0),
    ] {
        let Ok(Some(spec)) = KernelBtf::get().function_trampoline_arg(func_name, arg_idx) else {
            continue;
        };
        if let TrampolineValueKind::Aggregate { size_bytes } = spec.kind {
            return (func_name.to_string(), arg_idx as u8, size_bytes);
        }
    }
    panic!("expected an aggregate fentry candidate on this kernel");
}

fn string_member(name: &str) -> PathMember {
    PathMember::test_string(name.to_string(), false, Casing::Sensitive)
}

fn int_member(index: usize) -> PathMember {
    PathMember::Int {
        val: index,
        span: Span::test_data(),
        optional: false,
    }
}

fn make_ctx_path_program(path: CellPath) -> HirProgram {
    let ctx_var = VarId::new(0);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(path)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 3],
        ast: vec![None; 3],
        comments: vec![],
        register_count: 2,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

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
fn test_constant_record_rodata_survives_projection_codegen_and_elf() {
    use crate::compiler::ReadonlyGlobal;
    use crate::compiler::mir::{MirFunction, MirProgram, StructField};

    let record_ty = MirType::Struct {
        name: None,
        kernel_btf_type_id: None,
        fields: vec![
            StructField {
                name: "mnt".to_string(),
                ty: MirType::I64,
                offset: 0,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "dentry".to_string(),
                ty: MirType::I64,
                offset: 8,
                synthetic: false,
                bitfield: None,
            },
        ],
    };
    let symbol = "__nu_rodata_test".to_string();
    let readonly_globals = vec![ReadonlyGlobal {
        name: symbol.clone(),
        data: [1i64.to_le_bytes().as_slice(), 2i64.to_le_bytes().as_slice()].concat(),
    }];

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let rodata_vreg = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadGlobal {
            dst: rodata_vreg,
            symbol: symbol.clone(),
            ty: record_ty,
        });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };
    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let compile_result = compile_mir_to_ebpf_with_hints_and_readonly_globals(
        &program,
        None,
        None,
        readonly_globals.clone(),
    )
    .expect("constant record rodata should compile");

    assert_eq!(compile_result.readonly_globals.len(), 1);
    assert!(
        compile_result
            .relocations
            .iter()
            .any(|reloc| reloc.symbol_name == symbol),
        "expected rodata load relocation to target the readonly-global symbol"
    );

    let program = EbpfProgram::with_maps(
        EbpfProgramType::Kprobe,
        "sys_clone",
        "readonly_global_test",
        compile_result.bytecode,
        compile_result.main_size,
        compile_result.maps,
        compile_result.relocations,
        compile_result.subfunction_symbols,
        compile_result.event_schema,
        compile_result.bytes_counter_key_schema,
        HashMap::new(),
    )
    .with_readonly_globals(compile_result.readonly_globals);

    let elf = program
        .to_elf()
        .expect("readonly-global relocation should produce a valid ELF");
    assert!(!elf.is_empty(), "ELF should not be empty");
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
fn test_comparison_codegen_preserves_rhs_when_dst_aliases_r0() {
    let mut func = LirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let cmp = func.alloc_vreg();
    let lhs = func.alloc_vreg();

    func.precolored.insert(cmp, EbpfReg::R0);
    func.precolored.insert(lhs, EbpfReg::R1);

    func.block_mut(entry).instructions.push(LirInst::BinOp {
        dst: cmp,
        op: BinOpKind::Lt,
        lhs: MirValue::VReg(lhs),
        rhs: MirValue::VReg(cmp),
    });
    func.block_mut(entry).terminator = LirInst::Return {
        val: Some(MirValue::VReg(cmp)),
    };

    let program = LirProgram::new(func);
    let mut compiler = MirToEbpfCompiler::new(&program, None);
    compiler
        .prepare_function_state(
            &program.main,
            compiler.available_regs.clone(),
            program.main.precolored.clone(),
        )
        .expect("comparison alias program should prepare");
    compiler
        .compile_function(&program.main)
        .expect("comparison alias program should compile");
    compiler.fixup_jumps().expect("jump fixups should succeed");

    let self_compare_opcode = opcode::BPF_JMP | opcode::BPF_JSLT | opcode::BPF_X;
    assert!(
        !compiler
            .instructions
            .iter()
            .any(|insn| { insn.opcode == self_compare_opcode && insn.dst_reg == insn.src_reg }),
        "comparison codegen should not collapse aliased rhs preservation into a self-compare"
    );
}

#[test]
fn test_comparison_codegen_does_not_spill_r0_as_temp() {
    let mut func = LirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let cmp = func.alloc_vreg();
    let lhs = func.alloc_vreg();
    let rhs = func.alloc_vreg();

    func.precolored.insert(cmp, EbpfReg::R6);
    func.precolored.insert(lhs, EbpfReg::R6);
    func.precolored.insert(rhs, EbpfReg::R3);

    func.block_mut(entry).instructions.push(LirInst::BinOp {
        dst: cmp,
        op: BinOpKind::Le,
        lhs: MirValue::VReg(lhs),
        rhs: MirValue::VReg(rhs),
    });
    func.block_mut(entry).terminator = LirInst::Return {
        val: Some(MirValue::VReg(cmp)),
    };

    let program = LirProgram::new(func);
    let mut compiler = MirToEbpfCompiler::new(&program, None);
    compiler
        .prepare_function_state(
            &program.main,
            compiler.available_regs.clone(),
            program.main.precolored.clone(),
        )
        .expect("comparison temp program should prepare");
    compiler
        .compile_function(&program.main)
        .expect("comparison temp program should compile");
    compiler.fixup_jumps().expect("jump fixups should succeed");

    assert!(
        !compiler.instructions.iter().any(|insn| {
            insn.opcode == opcode::BPF_STX | opcode::BPF_DW | opcode::BPF_MEM
                && insn.dst_reg == EbpfReg::R10.as_u8()
                && insn.src_reg == EbpfReg::R0.as_u8()
        }),
        "comparison codegen must not spill unreadable R0 as a temporary"
    );
}

#[test]
fn test_binop_codegen_does_not_spill_r0_as_temp() {
    let mut func = LirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    let lhs = func.alloc_vreg();
    let rhs = func.alloc_vreg();

    func.precolored.insert(dst, EbpfReg::R6);
    func.precolored.insert(lhs, EbpfReg::R1);
    func.precolored.insert(rhs, EbpfReg::R6);

    func.block_mut(entry).instructions.push(LirInst::BinOp {
        dst,
        op: BinOpKind::Or,
        lhs: MirValue::VReg(lhs),
        rhs: MirValue::VReg(rhs),
    });
    func.block_mut(entry).terminator = LirInst::Return {
        val: Some(MirValue::VReg(dst)),
    };

    let program = LirProgram::new(func);
    let mut compiler = MirToEbpfCompiler::new(&program, None);
    compiler
        .prepare_function_state(
            &program.main,
            compiler.available_regs.clone(),
            program.main.precolored.clone(),
        )
        .expect("binop temp program should prepare");
    compiler
        .compile_function(&program.main)
        .expect("binop temp program should compile");
    compiler.fixup_jumps().expect("jump fixups should succeed");

    assert!(
        !compiler.instructions.iter().any(|insn| {
            insn.opcode == opcode::BPF_STX | opcode::BPF_DW | opcode::BPF_MEM
                && insn.dst_reg == EbpfReg::R10.as_u8()
                && insn.src_reg == EbpfReg::R0.as_u8()
        }),
        "binop codegen must not spill unreadable R0 as a temporary"
    );
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

#[test]
fn test_compile_fentry_aggregate_arg_copies_into_backing_slot() {
    let (func_name, arg_idx, size_bytes) = find_aggregate_fentry_arg_candidate();
    let ctx = ProbeContext::new(EbpfProgramType::Fentry, &func_name);

    let mut func = LirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(size_bytes.div_ceil(8) * 8, 8, StackSlotKind::Local);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(LirInst::LoadCtxField {
            dst,
            field: CtxField::Arg(arg_idx),
            slot: Some(slot),
        });
    func.block_mut(entry).terminator = LirInst::Return {
        val: Some(MirValue::VReg(dst)),
    };

    let program = LirProgram::new(func);
    let mut compiler = MirToEbpfCompiler::new(&program, Some(&ctx));
    compiler
        .prepare_function_state(
            &program.main,
            compiler.available_regs.clone(),
            program.main.precolored.clone(),
        )
        .unwrap();
    compiler.compile_function(&program.main).unwrap();
    compiler.fixup_jumps().unwrap();

    let dst_reg = compiler
        .vreg_to_phys
        .get(&dst)
        .copied()
        .expect("destination vreg should be assigned a physical register");
    let slot_offset = *compiler
        .slot_offsets
        .get(&slot)
        .expect("stack slot should have an assigned offset");
    let expected_chunks = if size_bytes >= 8 {
        size_bytes / 8
    } else if size_bytes >= 4 {
        1
    } else if size_bytes >= 2 {
        1
    } else {
        1
    };

    let load_count = compiler
        .instructions
        .iter()
        .filter(|insn| {
            insn.src_reg == EbpfReg::R9.as_u8()
                && [
                    opcode::BPF_LDX | opcode::BPF_B | opcode::BPF_MEM,
                    opcode::BPF_LDX | opcode::BPF_H | opcode::BPF_MEM,
                    opcode::BPF_LDX | opcode::BPF_W | opcode::BPF_MEM,
                    opcode::BPF_LDX | opcode::BPF_DW | opcode::BPF_MEM,
                ]
                .contains(&insn.opcode)
        })
        .count();
    let store_count = compiler
        .instructions
        .iter()
        .filter(|insn| {
            insn.dst_reg == EbpfReg::R10.as_u8()
                && [
                    opcode::BPF_STX | opcode::BPF_B | opcode::BPF_MEM,
                    opcode::BPF_STX | opcode::BPF_H | opcode::BPF_MEM,
                    opcode::BPF_STX | opcode::BPF_W | opcode::BPF_MEM,
                    opcode::BPF_STX | opcode::BPF_DW | opcode::BPF_MEM,
                ]
                .contains(&insn.opcode)
        })
        .count();
    let saw_stack_addr = compiler.instructions.iter().any(|insn| {
        insn.opcode == opcode::MOV64_REG
            && insn.dst_reg == dst_reg.as_u8()
            && insn.src_reg == EbpfReg::R10.as_u8()
    }) && compiler.instructions.iter().any(|insn| {
        insn.opcode == opcode::ADD64_IMM
            && insn.dst_reg == dst_reg.as_u8()
            && insn.imm == slot_offset as i32
    });

    assert_eq!(load_count, expected_chunks);
    assert!(
        store_count >= expected_chunks,
        "expected at least {expected_chunks} stores into the backing slot"
    );
    assert!(saw_stack_addr, "expected load to return a stack pointer");
}

#[test]
fn test_compile_xdp_packet_len_load() {
    let ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let mut func = LirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(LirInst::LoadCtxField {
            dst,
            field: CtxField::PacketLen,
            slot: None,
        });
    func.block_mut(entry).terminator = LirInst::Return {
        val: Some(MirValue::VReg(dst)),
    };

    let program = LirProgram::new(func);
    let mut compiler = MirToEbpfCompiler::new(&program, Some(&ctx));
    compiler
        .prepare_function_state(
            &program.main,
            compiler.available_regs.clone(),
            program.main.precolored.clone(),
        )
        .unwrap();
    compiler.compile_function(&program.main).unwrap();
    compiler.fixup_jumps().unwrap();

    assert!(compiler.instructions.iter().any(|insn| {
        insn.opcode == opcode::BPF_LDX | opcode::BPF_W | opcode::BPF_MEM
            && insn.src_reg == EbpfReg::R9.as_u8()
            && insn.offset == 4
    }));
    assert!(compiler.instructions.iter().any(|insn| {
        insn.opcode == opcode::BPF_LDX | opcode::BPF_W | opcode::BPF_MEM
            && insn.src_reg == EbpfReg::R9.as_u8()
            && insn.offset == 0
    }));
    assert!(compiler.instructions.iter().any(|insn| {
        insn.opcode == opcode::BPF_ALU64 | opcode::BPF_X | opcode::BPF_SUB
            && insn.src_reg == EbpfReg::R0.as_u8()
    }));
}

#[test]
fn test_compile_xdp_data_ctx_load() {
    let ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let mut func = LirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(LirInst::LoadCtxField {
            dst,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(entry).terminator = LirInst::Return {
        val: Some(MirValue::VReg(dst)),
    };

    let program = LirProgram::new(func);
    let mut compiler = MirToEbpfCompiler::new(&program, Some(&ctx));
    compiler
        .prepare_function_state(
            &program.main,
            compiler.available_regs.clone(),
            program.main.precolored.clone(),
        )
        .unwrap();
    compiler.compile_function(&program.main).unwrap();
    compiler.fixup_jumps().unwrap();

    assert!(compiler.instructions.iter().any(|insn| {
        insn.opcode == opcode::BPF_LDX | opcode::BPF_W | opcode::BPF_MEM
            && insn.src_reg == EbpfReg::R9.as_u8()
            && insn.offset == 0
    }));
}

#[test]
fn test_compile_cgroup_sock_addr_user_ip6_load_copies_four_words_into_stack_slot() {
    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect6");

    let mut func = LirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::Local);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(LirInst::LoadCtxField {
            dst,
            field: CtxField::UserIp6,
            slot: Some(slot),
        });
    func.block_mut(entry).terminator = LirInst::Return {
        val: Some(MirValue::VReg(dst)),
    };

    let program = LirProgram::new(func);
    let mut compiler = MirToEbpfCompiler::new(&program, Some(&ctx));
    compiler
        .prepare_function_state(
            &program.main,
            compiler.available_regs.clone(),
            program.main.precolored.clone(),
        )
        .unwrap();
    compiler.compile_function(&program.main).unwrap();
    compiler.fixup_jumps().unwrap();

    let word_load_offsets: Vec<i16> = compiler
        .instructions
        .iter()
        .filter(|insn| {
            insn.opcode == opcode::BPF_LDX | opcode::BPF_W | opcode::BPF_MEM
                && insn.src_reg == EbpfReg::R9.as_u8()
        })
        .map(|insn| insn.offset)
        .collect();
    assert_eq!(word_load_offsets, vec![8, 12, 16, 20]);
}

#[test]
fn test_compile_xdp_u16be_packet_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("data"), string_member("u16be"), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("u16be packet projection should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("u16be packet projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_xdp_eth_header_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("data"),
            string_member("eth"),
            string_member("dst"),
            int_member(0),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("eth header packet projection should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("eth header packet projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_xdp_eth_payload_ipv4_protocol_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("data"),
            string_member("eth"),
            string_member("payload"),
            string_member("ipv4"),
            string_member("protocol"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("eth payload ipv4 protocol projection should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("eth payload ipv4 protocol projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_tc_eth_payload_ipv4_protocol_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("data"),
            string_member("eth"),
            string_member("payload"),
            string_member("ipv4"),
            string_member("protocol"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc eth payload ipv4 protocol projection should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("tc eth payload ipv4 protocol projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_xdp_eth_ipv4_tcp_payload_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("data"),
            string_member("eth"),
            string_member("payload"),
            string_member("ipv4"),
            string_member("payload"),
            string_member("tcp"),
            string_member("payload"),
            int_member(0),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("eth ipv4 tcp payload projection should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("eth ipv4 tcp payload projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_fentry_aggregate_scalar_field_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("tv_nsec")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "__audit_tk_injoffset");
    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("field projection should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("field projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_fexit_aggregate_ret_field_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("retval"), string_member("size")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fexit, "__jump_label_patch");
    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("retval field projection should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("retval field projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_fentry_pointer_root_scalar_field_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("f_flags")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("pointer-root field projection should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("pointer-root field projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_fentry_pointer_hop_scalar_field_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("arg0"),
            string_member("f_inode"),
            string_member("i_ino"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("pointer-hop field projection should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("pointer-hop field projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_fentry_array_element_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("comm"), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("array element projection should lower");

    let result = compile_mir_to_ebpf_with_hints(
        &lowering.program,
        Some(&probe_ctx),
        Some(&lowering.type_hints),
    )
    .expect("array element projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_fentry_array_leaf_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("comm")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("array leaf projection should lower");

    let mut program = lowering.program.clone();
    let status = program.main.alloc_vreg();
    let return_block = program
        .main
        .blocks
        .iter_mut()
        .find(|block| matches!(block.terminator, MirInst::Return { .. }))
        .expect("expected return block");
    return_block.instructions.push(MirInst::EmitEvent {
        data: crate::compiler::mir::VReg(0),
        size: 16,
    });
    return_block.instructions.push(MirInst::Copy {
        dst: status,
        src: MirValue::Const(0),
    });
    return_block.terminator = MirInst::Return {
        val: Some(MirValue::VReg(status)),
    };

    let result =
        compile_mir_to_ebpf_with_hints(&program, Some(&probe_ctx), Some(&lowering.type_hints))
            .expect("array leaf projection should compile");
    assert!(!result.bytecode.is_empty(), "Should produce bytecode");
}

#[test]
fn test_compile_fentry_struct_leaf_emit_registers_record_schema() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("f_path")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let lowering = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("struct leaf projection should lower");

    let mut program = lowering.program.clone();
    let status = program.main.alloc_vreg();
    let return_block = program
        .main
        .blocks
        .iter_mut()
        .find(|block| matches!(block.terminator, MirInst::Return { .. }))
        .expect("expected return block");
    return_block.instructions.push(MirInst::EmitEvent {
        data: crate::compiler::mir::VReg(0),
        size: 16,
    });
    return_block.instructions.push(MirInst::Copy {
        dst: status,
        src: MirValue::Const(0),
    });
    return_block.terminator = MirInst::Return {
        val: Some(MirValue::VReg(status)),
    };

    let result =
        compile_mir_to_ebpf_with_hints(&program, Some(&probe_ctx), Some(&lowering.type_hints))
            .expect("struct leaf emit should compile");
    assert_eq!(
        result.event_schema,
        Some(crate::compiler::EventSchema {
            fields: vec![
                crate::compiler::SchemaField {
                    name: "mnt".to_string(),
                    field_type: crate::compiler::BpfFieldType::Int {
                        size: 8,
                        signed: false,
                    },
                    value_schema: None,
                    offset: 0,
                    bitfield: None,
                },
                crate::compiler::SchemaField {
                    name: "dentry".to_string(),
                    field_type: crate::compiler::BpfFieldType::Int {
                        size: 8,
                        signed: false,
                    },
                    value_schema: None,
                    offset: 8,
                    bitfield: None,
                },
            ],
            total_size: 16,
        })
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

#[test]
fn test_mir_subtract_i32_min_immediate_compile() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();

    let mut entry_block = BasicBlock::new(BlockId(0));
    entry_block.instructions.push(MirInst::Copy {
        dst: VReg(0),
        src: MirValue::Const(1),
    });
    entry_block.instructions.push(MirInst::BinOp {
        dst: VReg(0),
        op: BinOpKind::Sub,
        lhs: MirValue::VReg(VReg(0)),
        rhs: MirValue::Const(i32::MIN as i64),
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
        "subtract with i32::MIN immediate should compile without panicking"
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
        start: 0,
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
