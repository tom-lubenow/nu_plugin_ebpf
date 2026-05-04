use super::helpers::*;
use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::compile_mir_to_ebpf_with_hints;
use crate::compiler::hir::{
    AnnotatedMutGlobal, HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt,
    HirTerminator,
};
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::{AddressSpace, BYTES_COUNTER_MAP_NAME, COUNTER_MAP_NAME};
use crate::compiler::passes::optimize_with_ssa_hints;
use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector, TypeInfo};
use nu_protocol::ast::{CellPath, RangeInclusion};
use nu_protocol::{DeclId, Record, RegId, Span, Type, Value, VarId};
use std::collections::HashMap;

fn find_tracepoint_pointer_field_candidate() -> Option<(String, String)> {
    for (target, field_name) in [
        ("syscalls/sys_enter_openat", "filename"),
        ("syscalls/sys_enter_openat2", "filename"),
        ("syscalls/sys_enter_execve", "filename"),
    ] {
        let (category, name) = target.split_once('/')?;
        let Ok(ctx) = KernelBtf::get().get_tracepoint_context(category, name) else {
            continue;
        };
        let Some(field) = ctx.get_field(field_name) else {
            continue;
        };
        if field.type_info.is_ptr() {
            return Some((target.to_string(), field_name.to_string()));
        }
    }
    None
}

fn make_nested_metadata_record_call_program(decl_id: DeclId) -> HirProgram {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("msg".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("hi".into()),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(0),
                    key: RegId::new(1),
                    val: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(0),
                    key: RegId::new(3),
                    val: RegId::new(4),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::String("inner".into()),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(5),
                    key: RegId::new(6),
                    val: RegId::new(0),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::String("cpu".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(8),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(5),
                    key: RegId::new(7),
                    val: RegId::new(8),
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(5),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(5) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 9,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_no_arg_call_program(decl_id: DeclId) -> HirProgram {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::Call {
                decl_id,
                src_dst: RegId::new(0),
                args: HirCallArgs::default(),
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 1,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_random_int_range_call_program(decl_id: DeclId, start: i64, end: i64) -> HirProgram {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(start),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(end),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Range {
                        start: RegId::new(0),
                        step: RegId::new(1),
                        end: RegId::new(2),
                        inclusion: RangeInclusion::Inclusive,
                    },
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(3)],
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(4) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

#[test]
fn test_mir_function_creation() {
    let mut func = MirFunction::new();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    assert_eq!(v0.0, 0);
    assert_eq!(v1.0, 1);
    assert_eq!(func.vreg_count, 2);
}

#[test]
fn test_lower_random_int_calls_prandom_helper() {
    let decl_id = DeclId::new(42);
    let hir = make_no_arg_call_program(decl_id);
    let mut decl_names = HashMap::new();
    decl_names.insert(decl_id, "random int".to_string());

    let result = lower_hir_to_mir(&hir, None, &decl_names).expect("random int should lower to MIR");

    let helper = result
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::CallHelper { helper, args, .. } => Some((*helper, args.clone())),
            _ => None,
        })
        .expect("expected helper call");

    assert_eq!(helper.0, BpfHelper::GetPrandomU32 as u32);
    assert!(helper.1.is_empty(), "random int should pass no helper args");
}

#[test]
fn test_lower_random_int_bounded_range_scales_prandom_result() {
    let decl_id = DeclId::new(42);
    let hir = make_random_int_range_call_program(decl_id, 10, 20);
    let mut decl_names = HashMap::new();
    decl_names.insert(decl_id, "random int".to_string());

    let result = lower_hir_to_mir(&hir, None, &decl_names)
        .expect("random int bounded range should lower to MIR");
    let instructions: Vec<_> = result
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect();

    assert!(instructions.iter().any(|inst| {
        matches!(
            inst,
            MirInst::CallHelper {
                helper,
                args,
                ..
            } if *helper == BpfHelper::GetPrandomU32 as u32 && args.is_empty()
        )
    }));
    assert!(instructions.iter().any(|inst| {
        matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Mod,
                rhs: MirValue::Const(11),
                ..
            }
        )
    }));
    assert!(instructions.iter().any(|inst| {
        matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Add,
                rhs: MirValue::Const(10),
                ..
            }
        )
    }));
}

#[test]
fn test_unsupported_runtime_operator_message_mentions_compile_time_constant_escape_hatch() {
    use nu_protocol::ast::{Math, Operator};

    let hir_program = HirProgram::new(
        HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::Int(2),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::Int(3),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Math(Math::Pow),
                        rhs: RegId::new(1),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            }],
            entry: HirBlockId(0),
            spans: Vec::new(),
            ast: Vec::new(),
            comments: Vec::new(),
            register_count: 2,
            file_count: 0,
        },
        HashMap::new(),
        vec![],
        None,
    );

    let err = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("runtime-only pow lowering should be rejected");

    let message = err.to_string();
    assert!(
        message.contains("Operator ** is not supported in eBPF runtime lowering"),
        "unexpected error message: {message}"
    );
    assert!(
        message.contains("compile-time constant"),
        "unexpected error message: {message}"
    );
}

#[test]
fn test_basic_block_creation() {
    let mut func = MirFunction::new();
    let b0 = func.alloc_block();
    let b1 = func.alloc_block();

    assert_eq!(b0.0, 0);
    assert_eq!(b1.0, 1);
    assert_eq!(func.blocks.len(), 2);
}

#[test]
fn test_list_instructions_creation() {
    // Test that list MIR instructions can be created correctly
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    // Allocate virtual registers
    let list_ptr = func.alloc_vreg();
    let item1 = func.alloc_vreg();
    let item2 = func.alloc_vreg();
    let len = func.alloc_vreg();
    let result = func.alloc_vreg();

    // Allocate stack slot for list buffer
    let slot = func.alloc_stack_slot(72, 8, StackSlotKind::ListBuffer); // 8 + 8*8 = 72 bytes

    // Create list instructions
    func.block_mut(bb0).instructions.push(MirInst::ListNew {
        dst: list_ptr,
        buffer: slot,
        max_len: 8,
    });

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: item1,
        src: MirValue::Const(42),
    });

    func.block_mut(bb0).instructions.push(MirInst::ListPush {
        list: list_ptr,
        item: item1,
    });

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: item2,
        src: MirValue::Const(100),
    });

    func.block_mut(bb0).instructions.push(MirInst::ListPush {
        list: list_ptr,
        item: item2,
    });

    func.block_mut(bb0).instructions.push(MirInst::ListLen {
        dst: len,
        list: list_ptr,
    });

    func.block_mut(bb0).instructions.push(MirInst::ListGet {
        dst: result,
        list: list_ptr,
        idx: MirValue::Const(0),
    });

    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(result)),
    };

    // Verify instructions were created
    assert_eq!(func.block(bb0).instructions.len(), 7);

    // Verify list instructions have correct structure
    match &func.block(bb0).instructions[0] {
        MirInst::ListNew {
            dst,
            buffer,
            max_len,
        } => {
            assert_eq!(*dst, list_ptr);
            assert_eq!(*buffer, slot);
            assert_eq!(*max_len, 8);
        }
        _ => panic!("Expected ListNew instruction"),
    }

    match &func.block(bb0).instructions[2] {
        MirInst::ListPush { list, item } => {
            assert_eq!(*list, list_ptr);
            assert_eq!(*item, item1);
        }
        _ => panic!("Expected ListPush instruction"),
    }

    match &func.block(bb0).instructions[5] {
        MirInst::ListLen { dst, list } => {
            assert_eq!(*dst, len);
            assert_eq!(*list, list_ptr);
        }
        _ => panic!("Expected ListLen instruction"),
    }

    match &func.block(bb0).instructions[6] {
        MirInst::ListGet { dst, list, idx } => {
            assert_eq!(*dst, result);
            assert_eq!(*list, list_ptr);
            match idx {
                MirValue::Const(0) => {}
                _ => panic!("Expected constant index 0"),
            }
        }
        _ => panic!("Expected ListGet instruction"),
    }
}

#[test]
fn test_list_def_and_uses() {
    // Test that list instructions correctly report definitions and uses
    let mut func = MirFunction::new();
    let list_ptr = func.alloc_vreg();
    let item = func.alloc_vreg();
    let len = func.alloc_vreg();
    let result = func.alloc_vreg();
    let slot = func.alloc_stack_slot(72, 8, StackSlotKind::ListBuffer);

    // ListNew defines dst
    let inst = MirInst::ListNew {
        dst: list_ptr,
        buffer: slot,
        max_len: 8,
    };
    assert_eq!(inst.def(), Some(list_ptr));
    assert!(inst.uses().is_empty());

    // ListPush uses both list and item, defines nothing
    let inst = MirInst::ListPush {
        list: list_ptr,
        item,
    };
    assert_eq!(inst.def(), None);
    let uses = inst.uses();
    assert_eq!(uses.len(), 2);
    assert!(uses.contains(&list_ptr));
    assert!(uses.contains(&item));

    // ListLen defines dst, uses list
    let inst = MirInst::ListLen {
        dst: len,
        list: list_ptr,
    };
    assert_eq!(inst.def(), Some(len));
    let uses = inst.uses();
    assert_eq!(uses.len(), 1);
    assert!(uses.contains(&list_ptr));

    // ListGet defines dst, uses list (and maybe idx if VReg)
    let inst = MirInst::ListGet {
        dst: result,
        list: list_ptr,
        idx: MirValue::Const(0),
    };
    assert_eq!(inst.def(), Some(result));
    let uses = inst.uses();
    assert_eq!(uses.len(), 1);
    assert!(uses.contains(&list_ptr));

    // ListGet with VReg index
    let idx_vreg = func.alloc_vreg();
    let inst = MirInst::ListGet {
        dst: result,
        list: list_ptr,
        idx: MirValue::VReg(idx_vreg),
    };
    let uses = inst.uses();
    assert_eq!(uses.len(), 2);
    assert!(uses.contains(&list_ptr));
    assert!(uses.contains(&idx_vreg));
}

#[test]
fn test_lower_default_step_range_iterate_emits_loop_header_start() {
    let hir = make_range_iterate_program(0, HirLiteral::Nothing, 1);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("default-step iterate should lower");

    let loop_header = result
        .program
        .main
        .blocks
        .iter()
        .find_map(|block| match &block.terminator {
            MirInst::LoopHeader {
                start,
                step,
                limit,
                body,
                exit,
                ..
            } => Some((*start, *step, *limit, *body, *exit)),
            _ => None,
        })
        .expect("expected loop header");
    assert_eq!(loop_header.0, 0);
    assert_eq!(loop_header.1, 1);
    assert_eq!(loop_header.2, 2);
    assert_eq!(
        result.program.main.block(loop_header.3).instructions.len(),
        1
    );
    let exit_block = result.program.main.block(loop_header.4);
    let exit_initializes_result = exit_block.instructions.iter().any(|inst| {
        matches!(
            inst,
            MirInst::Copy {
                src: MirValue::Const(0),
                ..
            }
        )
    }) || matches!(
        exit_block.terminator,
        MirInst::Return {
            val: Some(MirValue::Const(0))
        }
    );
    assert!(
        exit_initializes_result,
        "expected exit edge to initialize the loop result register"
    );
}

#[test]
fn test_lower_descending_range_iterate_emits_signed_loop_header() {
    let hir = make_range_iterate_program(3, HirLiteral::Int(-1), 0);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("descending iterate should lower");

    let loop_header = result
        .program
        .main
        .blocks
        .iter()
        .find_map(|block| match &block.terminator {
            MirInst::LoopHeader {
                start,
                step,
                limit,
                body,
                exit,
                ..
            } => Some((*start, *step, *limit, *body, *exit)),
            _ => None,
        })
        .expect("expected descending loop header");
    assert_eq!(loop_header.0, 3);
    assert_eq!(loop_header.1, -1);
    assert_eq!(loop_header.2, -1);
    assert_eq!(
        result.program.main.block(loop_header.3).instructions.len(),
        1
    );
    let exit_block = result.program.main.block(loop_header.4);
    let exit_initializes_result = exit_block.instructions.iter().any(|inst| {
        matches!(
            inst,
            MirInst::Copy {
                src: MirValue::Const(0),
                ..
            }
        )
    }) || matches!(
        exit_block.terminator,
        MirInst::Return {
            val: Some(MirValue::Const(0))
        }
    );
    assert!(
        exit_initializes_result,
        "expected exit edge to initialize the descending loop result register"
    );
}

#[test]
fn test_lower_bounded_list_iterate_uses_runtime_length_guard() {
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::List { capacity: 4 },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::Int(10),
                    },
                    HirStmt::ListPush {
                        src_dst: RegId::new(0),
                        item: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(20),
                    },
                    HirStmt::ListPush {
                        src_dst: RegId::new(0),
                        item: RegId::new(2),
                    },
                ],
                terminator: HirTerminator::Iterate {
                    dst: RegId::new(3),
                    stream: RegId::new(0),
                    body: HirBlockId(1),
                    end: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![],
                terminator: HirTerminator::Jump {
                    target: HirBlockId(0),
                },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![],
                terminator: HirTerminator::Return { src: RegId::new(3) },
            },
        ],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };

    let result = lower_hir_to_mir_with_hints(
        &HirProgram::new(func, HashMap::new(), vec![], None),
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bounded list iterate should lower");

    let (counter, start, step, limit, guard_block, exit_block) = result
        .program
        .main
        .blocks
        .iter()
        .find_map(|block| match &block.terminator {
            MirInst::LoopHeader {
                counter,
                start,
                step,
                limit,
                body,
                exit,
            } => Some((*counter, *start, *step, *limit, *body, *exit)),
            _ => None,
        })
        .expect("expected bounded list iterate loop header");
    assert_eq!(start, 0);
    assert_eq!(step, 1);
    assert_eq!(limit, 4);

    let guard = result.program.main.block(guard_block);
    assert!(
        guard
            .instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListLen { .. }))
    );
    assert!(guard.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::BinOp {
            op: BinOpKind::Lt,
            lhs: MirValue::VReg(lhs),
            rhs: MirValue::VReg(_),
            ..
        } if *lhs == counter
    )));

    let (body_block, branch_exit) = match guard.terminator {
        MirInst::Branch {
            if_true, if_false, ..
        } => (if_true, if_false),
        ref other => panic!("expected guard branch terminator, got {other:?}"),
    };
    assert_eq!(branch_exit, exit_block);

    let body = result.program.main.block(body_block);
    assert!(body.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::ListGet {
            idx: MirValue::VReg(idx),
            ..
        } if *idx == counter
    )));

    let exit = result.program.main.block(exit_block);
    let exit_initializes_result = exit.instructions.iter().any(|inst| {
        matches!(
            inst,
            MirInst::Copy {
                src: MirValue::Const(0),
                ..
            }
        )
    }) || matches!(
        exit.terminator,
        MirInst::Return {
            val: Some(MirValue::Const(0))
        }
    );
    assert!(
        exit_initializes_result,
        "expected exit edge to initialize the list-iterate result register"
    );
}

#[test]
fn test_loop_break_edge_does_not_disable_sibling_continue_backedge() {
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::Nothing,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(3),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::Range {
                            start: RegId::new(0),
                            step: RegId::new(1),
                            end: RegId::new(2),
                            inclusion: RangeInclusion::Inclusive,
                        },
                    },
                ],
                terminator: HirTerminator::Iterate {
                    dst: RegId::new(4),
                    stream: RegId::new(3),
                    body: HirBlockId(1),
                    end: HirBlockId(4),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Bool(true),
                }],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(5),
                    if_true: HirBlockId(2),
                    if_false: HirBlockId(3),
                },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![],
                terminator: HirTerminator::Jump {
                    target: HirBlockId(4),
                },
            },
            HirBlock {
                id: HirBlockId(3),
                stmts: vec![],
                terminator: HirTerminator::Jump {
                    target: HirBlockId(0),
                },
            },
            HirBlock {
                id: HirBlockId(4),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Int(9),
                }],
                terminator: HirTerminator::Return { src: RegId::new(6) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 7],
        ast: vec![None; 7],
        comments: Vec::new(),
        register_count: 7,
        file_count: 0,
    };

    let result = lower_hir_to_mir_with_hints(
        &HirProgram::new(func, HashMap::new(), vec![], None),
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("loop with break and continue edges should lower");

    let header_block = result
        .program
        .main
        .blocks
        .iter()
        .find_map(|block| {
            matches!(block.terminator, MirInst::LoopHeader { .. }).then_some(block.id)
        })
        .expect("expected loop header block");

    assert!(
        result.program.main.blocks.iter().any(|block| {
            matches!(
                block.terminator,
                MirInst::LoopBack { header, .. } if header == header_block
            )
        }),
        "continue edge should lower to LoopBack even when a sibling block breaks"
    );
}

#[test]
fn test_loop_branch_to_header_lowers_through_loopback_trampoline() {
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::Nothing,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(3),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::Range {
                            start: RegId::new(0),
                            step: RegId::new(1),
                            end: RegId::new(2),
                            inclusion: RangeInclusion::Inclusive,
                        },
                    },
                ],
                terminator: HirTerminator::Iterate {
                    dst: RegId::new(4),
                    stream: RegId::new(3),
                    body: HirBlockId(1),
                    end: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Bool(true),
                }],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(5),
                    if_true: HirBlockId(0),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 6],
        ast: vec![None; 6],
        comments: Vec::new(),
        register_count: 6,
        file_count: 0,
    };

    let result = lower_hir_to_mir_with_hints(
        &HirProgram::new(func, HashMap::new(), vec![], None),
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("loop branch to header should lower");

    let header_block = result
        .program
        .main
        .blocks
        .iter()
        .find_map(|block| {
            matches!(block.terminator, MirInst::LoopHeader { .. }).then_some(block.id)
        })
        .expect("expected loop header block");

    let loopback_block = result
        .program
        .main
        .blocks
        .iter()
        .find_map(|block| {
            matches!(
                block.terminator,
                MirInst::LoopBack { header, .. } if header == header_block
            )
            .then_some(block.id)
        })
        .expect("expected conditional header edge to use a LoopBack trampoline");

    assert!(
        result.program.main.blocks.iter().any(|block| matches!(
            block.terminator,
            MirInst::Branch { if_true, if_false, .. }
                if if_true == loopback_block || if_false == loopback_block
        )),
        "expected a branch edge to target the LoopBack trampoline"
    );
}

#[test]
fn test_lower_fentry_aggregate_scalar_field_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("tv_nsec")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "__audit_tk_injoffset");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("aggregate field projection should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Arg(0),
            slot: Some(_),
            ..
        }
    )));
    let load = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::Load { offset, ty, .. } => Some((*offset, ty.clone())),
            _ => None,
        })
        .expect("expected projected field load");
    assert_eq!(load.0, 8);
    assert_eq!(load.1, MirType::I64);
}

#[test]
fn test_lower_fentry_aggregate_pointer_field_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("p")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "__copy_xstate_to_uabi_buf");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("aggregate pointer field projection should lower");

    let block = result.program.main.block(result.program.main.entry);
    let load = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::Load { offset, ty, .. } => Some((*offset, ty.clone())),
            _ => None,
        })
        .expect("expected projected pointer field load");
    assert_eq!(load.0, 0);
    assert!(matches!(
        load.1,
        MirType::Ptr {
            address_space: AddressSpace::Kernel,
            ..
        }
    ));
}

#[test]
fn test_lower_xdp_ifindex_alias_to_ingress_ifindex() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("ifindex")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp ifindex alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::IngressIfindex,
            ..
        }
    )));
}

#[test]
fn test_lower_sk_skb_ifindex_field_to_real_ifindex() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("ifindex")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_skb ifindex should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Ifindex,
            ..
        }
    )));
}

#[test]
fn test_lower_socket_filter_hash_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("hash")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("socket_filter ctx.hash should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SkbHash,
            ..
        }
    )));
}

#[test]
fn test_lower_sk_skb_queue_mapping_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("queue_mapping")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sk_skb ctx.queue_mapping should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::QueueMapping,
            ..
        }
    )));
}

#[test]
fn test_lower_socket_filter_napi_id_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("napi_id")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("socket_filter ctx.napi_id should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::NapiId,
            ..
        }
    )));
}

#[test]
fn test_lower_socket_filter_vlan_proto_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("vlan_proto")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("socket_filter ctx.vlan_proto should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::VlanProto,
            ..
        }
    )));
}

#[test]
fn test_lower_socket_filter_cb_index_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("cb"), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("socket_filter ctx.cb[0] should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::SkbCb,
            ..
        }
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::Load {
            ty: MirType::U32,
            ..
        }
    )));
}

#[test]
fn test_lower_kprobe_comm_index_field() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("comm"), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "do_sys_open");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("kprobe ctx.comm[0] should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Comm,
            ..
        }
    )));
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::Load {
            ty: MirType::U8,
            ..
        }
    )));
}

#[test]
fn test_lower_xdp_data_byte_projection_adds_guarded_packet_load() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("data"), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp data byte projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Data,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataEnd,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::Le,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_xdp_data_meta_byte_projection_adds_data_guarded_packet_load() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("data_meta"), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp data_meta byte projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataMeta,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Data,
                    ..
                }
            )))
    );
    assert!(
        !blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataEnd,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_tc_data_meta_byte_projection_adds_data_guarded_packet_load() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("data_meta"), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tc data_meta byte projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataMeta,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Data,
                    ..
                }
            )))
    );
    assert!(
        !blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataEnd,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_xdp_data_u16be_projection_adds_guarded_packet_load_and_byteswap() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("data"), string_member("u16be"), int_member(6)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp data u16be projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Data,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataEnd,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U16,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::Shl,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::Or,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_xdp_data_meta_runtime_get_adds_data_guard() {
    let hir = make_bound_ctx_runtime_get_program(
        CellPath {
            members: vec![string_member("data_meta")],
        },
        CellPath {
            members: vec![string_member("cpu")],
        },
        4,
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "get".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp data_meta numeric get should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataMeta,
                    ..
                }
            ))
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Data,
                    ..
                }
            ))
    );
    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataEnd,
                    ..
                }
            ))
    );
}

#[test]
fn test_lower_cgroup_sock_addr_user_ip6_load_uses_backing_slot_and_normalizes_words() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("user_ip6")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect6");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("cgroup_sock_addr user_ip6 should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::UserIp6,
            slot: Some(_),
            ..
        }
    )));
    let load_count = block
        .instructions
        .iter()
        .filter(|inst| {
            matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U32,
                    ..
                }
            )
        })
        .count();
    let store_count = block
        .instructions
        .iter()
        .filter(|inst| {
            matches!(
                inst,
                MirInst::Store {
                    ty: MirType::U32,
                    ..
                }
            )
        })
        .count();
    assert_eq!(load_count, 4);
    assert_eq!(store_count, 4);
}

#[test]
fn test_lower_xdp_eth_ethertype_projection_adds_guarded_packet_load_and_byteswap() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("data"),
            string_member("eth"),
            string_member("ethertype"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp eth ethertype projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Data,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::DataEnd,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U16,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::Shl,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_xdp_eth_payload_ipv4_protocol_projection_adds_vlan_and_ipv4_payload_steps() {
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp eth payload ipv4 protocol projection should lower");

    let blocks = &result.program.main.blocks;
    let eq_consts: Vec<i64> = blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter_map(|inst| match inst {
            MirInst::BinOp {
                op: BinOpKind::Eq,
                rhs: MirValue::Const(value),
                ..
            } => Some(*value),
            _ => None,
        })
        .collect();

    assert_eq!(
        eq_consts.iter().filter(|value| **value == 0x8100).count(),
        2
    );
    assert_eq!(
        eq_consts.iter().filter(|value| **value == 0x88a8).count(),
        2
    );
    assert_eq!(
        eq_consts.iter().filter(|value| **value == 0x9100).count(),
        2
    );
    assert!(
        blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .filter(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U16,
                    ..
                }
            ))
            .count()
            >= 2
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_xdp_eth_ipv4_tcp_payload_byte_projection_adds_dynamic_header_steps() {
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp eth/ipv4/tcp payload projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U16,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .filter(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::Shl,
                    ..
                }
            ))
            .count()
            >= 2
    );
}

#[test]
fn test_lower_xdp_eth_payload_ipv6_next_header_projection_adds_ipv6_view() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("data"),
            string_member("eth"),
            string_member("payload"),
            string_member("ipv6"),
            string_member("next_header"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp eth payload ipv6 next_header projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .filter(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U16,
                    ..
                }
            ))
            .count()
            >= 2
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_xdp_eth_ipv6_udp_payload_projection_adds_bounded_ipv6_extension_scan() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("data"),
            string_member("eth"),
            string_member("payload"),
            string_member("ipv6"),
            string_member("payload"),
            string_member("udp"),
            string_member("dst"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp eth ipv6 udp payload projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::Add,
                    rhs: MirValue::Const(40),
                    ..
                }
            ))
    );
    assert!(
        blocks
            .iter()
            .any(|block| matches!(block.terminator, MirInst::Branch { .. }))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U16,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_xdp_eth_ipv4_icmp_payload_projection_adds_fixed_icmp_payload_step() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("data"),
            string_member("eth"),
            string_member("payload"),
            string_member("ipv4"),
            string_member("payload"),
            string_member("icmp"),
            string_member("payload"),
            int_member(0),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp eth ipv4 icmp payload projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::Add,
                    rhs: MirValue::Const(8),
                    ..
                }
            ))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_xdp_eth_ipv4_tcp_seq_projection_reuses_dynamic_payload_steps() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("data"),
            string_member("eth"),
            string_member("ipv4"),
            string_member("tcp"),
            string_member("seq"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp eth ipv4 tcp seq projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| matches!(block.terminator, MirInst::Branch { .. }))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::And,
                    rhs: MirValue::Const(0x0f),
                    ..
                }
            ))
    );
}

#[test]
fn test_lower_xdp_eth_ipv6_udp_src_projection_reuses_bounded_ipv6_extension_scan() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("data"),
            string_member("eth"),
            string_member("ipv6"),
            string_member("udp"),
            string_member("src"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp eth ipv6 udp src projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::Add,
                    rhs: MirValue::Const(40),
                    ..
                }
            ))
    );
    assert!(
        blocks
            .iter()
            .any(|block| matches!(block.terminator, MirInst::Branch { .. }))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_xdp_eth_ipv6_icmpv6_code_projection_adds_icmpv6_view() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("data"),
            string_member("eth"),
            string_member("payload"),
            string_member("ipv6"),
            string_member("payload"),
            string_member("icmpv6"),
            string_member("code"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("xdp eth ipv6 icmpv6 code projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U8,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_fexit_aggregate_ret_field_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("retval"), string_member("size")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fexit, "__jump_label_patch");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("aggregate retval field projection should lower");

    let block = result.program.main.block(result.program.main.entry);
    let load = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::Load { offset, ty, .. } => Some((*offset, ty.clone())),
            _ => None,
        })
        .expect("expected projected retval field load");
    assert_eq!(load.0, 8);
    assert_eq!(load.1, MirType::I32);
}

#[test]
fn test_lower_fentry_pointer_root_scalar_field_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("f_flags")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("pointer-root field projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Arg(0),
                    slot: None,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::CallHelper {
                    helper,
                    ..
                } if *helper == BpfHelper::ProbeReadKernel as u32
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadSlot {
                    ty: MirType::U32,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_lsm_pointer_root_field_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("arg0"),
            string_member("f_path"),
            string_member("dentry"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Lsm, "file_open");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("lsm pointer-root field projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Arg(0),
                    slot: None,
                    ..
                }
            )))
    );
    assert!(
        !blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::CallHelper {
                    helper,
                    ..
                } if *helper == BpfHelper::ProbeReadKernel as u32
            ))),
        "terminal trusted BTF pointer field should not use probe_read"
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::Ptr {
                        address_space: AddressSpace::Kernel,
                        ..
                    },
                    ..
                }
            ))),
        "expected trusted BTF pointer field to lower as a direct load"
    );
}

#[test]
fn test_lower_fentry_pointer_hop_scalar_field_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("arg0"),
            string_member("f_inode"),
            string_member("i_ino"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("pointer-hop field projection should lower");

    let helper_reads = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
            )
        })
        .count();
    let direct_kernel_pointer_loads = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::Load {
                    ty: MirType::Ptr {
                        address_space: AddressSpace::Kernel,
                        ..
                    },
                    ..
                }
            )
        })
        .count();
    assert!(
        helper_reads == 1,
        "expected only the scalar leaf to use probe_read after direct trusted pointer hop"
    );
    assert!(
        direct_kernel_pointer_loads >= 1,
        "expected intermediate pointer hop to use a direct trusted BTF load"
    );
}

#[test]
fn test_lower_netfilter_state_pointer_hop_preserves_trusted_btf_provenance() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("state"),
            string_member("in"),
            string_member("ifindex"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Netfilter, "ipv4:pre_routing");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("netfilter trusted pointer-hop projection should lower");

    let helper_reads = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
            )
        })
        .count();
    let direct_kernel_pointer_loads = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::Load {
                    ty: MirType::Ptr {
                        address_space: AddressSpace::Kernel,
                        ..
                    },
                    ..
                }
            )
        })
        .count();

    assert_eq!(
        helper_reads, 1,
        "expected only the scalar net_device field leaf to use probe_read"
    );
    assert!(
        direct_kernel_pointer_loads >= 1,
        "expected netfilter trusted BTF pointer hop to use a direct load"
    );

    let compiled =
        compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
            .expect("netfilter trusted pointer-hop projection should compile");
    let program = compiled.into_program(
        EbpfProgramType::Netfilter,
        "ipv4:pre_routing",
        "main",
        HashMap::new(),
        HashMap::new(),
    );
    let helper_requirement = program
        .helper_compatibility_requirements()
        .into_iter()
        .find(|requirement| requirement.helper() == BpfHelper::ProbeReadKernel)
        .expect("netfilter scalar BTF projection should report probe_read_kernel compatibility");
    assert_eq!(helper_requirement.minimum_kernel(), "5.5");
    assert_eq!(program.helper_compatibility_minimum_kernel(), Some("5.5"));
}

#[test]
fn test_lower_fentry_array_element_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("comm"), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("array element projection should lower");

    let helper_reads = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
            )
        })
        .count();
    assert!(
        helper_reads >= 1,
        "expected a helper read for pointer-backed array element access"
    );
}

#[test]
fn test_compile_fixed_array_iterate_over_struct_elements() {
    let decl_names = HashMap::new();
    let closure_irs = HashMap::new();
    let captures: Vec<(VarId, Value)> = Vec::new();
    let user_functions = HashMap::new();
    let decl_signatures = HashMap::new();
    let mut lowering = HirToMirLowering::new(
        None,
        &decl_names,
        &closure_irs,
        &captures,
        None,
        None,
        None,
        None,
        None,
        None,
        &user_functions,
        &decl_signatures,
    );
    let header_block = lowering.func.alloc_block();
    lowering.func.entry = header_block;
    lowering.current_block = header_block;

    let element_ty = MirType::Struct {
        name: None,
        kernel_btf_type_id: None,
        fields: vec![
            StructField {
                name: "pid".to_string(),
                ty: MirType::I64,
                offset: 0,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "uid".to_string(),
                ty: MirType::U32,
                offset: 8,
                synthetic: false,
                bitfield: None,
            },
        ],
    };
    let array_ty = MirType::Array {
        elem: Box::new(element_ty.clone()),
        len: 2,
    };
    let array_slot =
        lowering
            .func
            .alloc_stack_slot(align_to_eight(array_ty.size()), 8, StackSlotKind::Local);
    lowering.record_stack_slot_type(array_slot, array_ty.clone());

    let stream_reg = RegId::new(0);
    let stream_vreg = lowering.get_vreg(stream_reg);
    lowering.emit(MirInst::Copy {
        dst: stream_vreg,
        src: MirValue::StackSlot(array_slot),
    });
    lowering.vreg_type_hints.insert(
        stream_vreg,
        MirType::Ptr {
            pointee: Box::new(array_ty),
            address_space: AddressSpace::Stack,
        },
    );

    let iter_reg = RegId::new(1);
    let path_reg = RegId::new(2);
    let body_block = lowering.func.alloc_block();
    let exit_block = lowering.func.alloc_block();

    assert!(
        lowering
            .lower_fixed_array_iterate(iter_reg, stream_reg, body_block, exit_block, true)
            .expect("fixed array iterate over struct elements should lower"),
        "expected fixed array iterate helper to accept a stack-backed array of structs"
    );

    lowering.current_block = body_block;
    lowering
        .lower_load_literal(
            path_reg,
            &HirLiteral::CellPath(Box::new(CellPath {
                members: vec![string_member("pid")],
            })),
        )
        .expect("field path literal should lower");
    lowering
        .lower_follow_cell_path(iter_reg, path_reg)
        .expect("loop body should be able to project a field from the iterated struct element");
    lowering.terminate(MirInst::Jump {
        target: header_block,
    });

    lowering.current_block = exit_block;
    lowering.terminate(MirInst::Return {
        val: Some(MirValue::Const(0)),
    });

    assert!(
        lowering
            .func
            .blocks
            .iter()
            .any(|block| matches!(block.terminator, MirInst::LoopHeader { .. })),
        "expected fixed array iterate lowering to emit a loop header"
    );
    assert!(
        lowering
            .func
            .blocks
            .iter()
            .find(|block| block.id == body_block)
            .into_iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::Load {
                    offset: 0,
                    ty: MirType::I64,
                    ..
                }
            )),
        "expected the loop body to load the projected struct field from the iterated element"
    );

    let (mut program, mut type_hints, _, _, _, _, _, _, _) = lowering.finish_with_hints();
    optimize_with_ssa_hints(
        &mut program.main,
        None,
        &mut type_hints.main,
        &type_hints.main_stack_slots,
        &type_hints.generic_map_value_types,
    );
    let result = compile_mir_to_ebpf_with_hints(&program, None, Some(&type_hints))
        .expect("fixed array iterate over struct elements should compile");
    assert!(!result.bytecode.is_empty(), "expected bytecode output");
}

#[test]
fn test_lower_fentry_array_leaf_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("comm")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("array leaf projection should lower");

    let helper_reads = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
            )
        })
        .count();
    assert!(
        helper_reads >= 1,
        "expected a helper read for pointer-backed array leaf access"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::Copy {
                    src: MirValue::StackSlot(_),
                    ..
                }
            )),
        "expected array leaf projection to produce a stack-backed pointer"
    );
}

#[test]
fn test_lower_fentry_array_leaf_emit_uses_full_byte_size() {
    let hir = make_ctx_path_call_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("comm")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "emit".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("array leaf emit should lower");

    let emit_size = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::EmitEvent { size, .. } => Some(*size),
            _ => None,
        })
        .expect("expected emit event");
    assert_eq!(emit_size, 16);
}

#[test]
fn test_lower_tracepoint_args_leaf_emit_uses_full_byte_size() {
    let hir = make_ctx_path_call_program(
        CellPath {
            members: vec![string_member("args")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tracepoint, "syscalls/sys_enter_openat");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "emit".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tracepoint args leaf emit should lower");

    let emit_size = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::EmitEvent { size, .. } => Some(*size),
            _ => None,
        })
        .expect("expected emit event");
    assert_eq!(emit_size, 48);
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::TracepointField(name),
                    slot: Some(_),
                    ..
                } if name == "args"
            )),
        "expected tracepoint aggregate field load to use a stack backing slot"
    );
}

#[test]
fn test_lower_tracepoint_args_index_projection_uses_stack_backed_numeric_get() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("args"), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tracepoint, "syscalls/sys_enter_openat");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tracepoint args index projection should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::TracepointField(name),
                    slot: Some(_),
                    ..
                } if name == "args"
            )),
        "expected tracepoint aggregate field root to materialize into a backing slot"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U64,
                    offset: 0,
                    ..
                }
            )),
        "expected indexed tracepoint arg projection to load the selected u64 element from stack"
    );
}

#[test]
fn test_lower_tracepoint_pointer_index_projection_uses_helper_read() {
    let Some((target, field_name)) = find_tracepoint_pointer_field_candidate() else {
        return;
    };
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member(&field_name), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tracepoint, &target);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("tracepoint pointer index projection should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::TracepointField(name),
                    slot: None,
                    ..
                } if name == &field_name
            )),
        "expected tracepoint pointer root to stay as a direct ctx field load"
    );
    let helper_reads = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
                        || *helper == BpfHelper::ProbeReadUser as u32
            )
        })
        .count();
    assert!(
        helper_reads >= 1,
        "expected pointer-root tracepoint projection to use probe-read helpers"
    );
}

#[test]
fn test_lower_fentry_array_leaf_count_uses_string_counter_map() {
    let hir = make_ctx_path_call_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("comm")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "count".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("array leaf count should lower");

    let map_name = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapUpdate { map, .. } => Some(map.name.as_str()),
            _ => None,
        })
        .expect("expected map update");
    assert_eq!(map_name, "str_counters");
}

#[test]
fn test_lower_generic_field_projection_after_array_leaf_binding() {
    let hir = make_chained_ctx_path_program(vec![
        CellPath {
            members: vec![string_member("arg0"), string_member("comm")],
        },
        CellPath {
            members: vec![int_member(0)],
        },
    ]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("generic array field projection should lower");

    let load = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .rev()
        .find_map(|inst| match inst {
            MirInst::Load { offset, ty, .. } => Some((*offset, ty.clone())),
            _ => None,
        })
        .expect("expected projected array element load");
    assert_eq!(load.0, 0);
    assert!(matches!(load.1, MirType::I8 | MirType::U8));
}

#[test]
fn test_lower_generic_field_projection_after_pointer_binding() {
    let hir = make_chained_ctx_path_program(vec![
        CellPath {
            members: vec![string_member("arg0"), string_member("f_inode")],
        },
        CellPath {
            members: vec![string_member("i_ino")],
        },
    ]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("generic pointer field projection should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper {
                    helper,
                    args,
                    ..
                } if *helper == BpfHelper::ProbeReadKernel as u32
                    && matches!(args.get(0), Some(MirValue::StackSlot(_)))
            ))
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadSlot {
                    ty: MirType::U64,
                    ..
                }
            ))
    );
}

#[test]
fn test_lower_generic_field_projection_after_deeper_pointer_binding() {
    let hir = make_chained_ctx_path_program(vec![
        CellPath {
            members: vec![string_member("arg0"), string_member("f_inode")],
        },
        CellPath {
            members: vec![string_member("i_sb"), string_member("s_flags")],
        },
    ]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("deeper generic pointer field projection should lower");

    let helper_reads = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
            )
        })
        .count();
    assert!(
        helper_reads == 1,
        "expected only the scalar leaf to use probe_read across a deeper trusted pointer path"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadSlot {
                    ty: MirType::U32 | MirType::U64 | MirType::I32 | MirType::I64,
                    ..
                }
            )),
        "expected final scalar load from helper scratch slot"
    );
}

#[test]
fn test_lower_fentry_multi_level_pointer_field_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("arg0"),
            string_member("fdt"),
            string_member("fd"),
            string_member("f_inode"),
            string_member("i_ino"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("multi-level pointer field projection should lower");

    let helper_reads = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
            )
        })
        .count();
    assert!(
        helper_reads == 1,
        "expected only the scalar leaf to use probe_read across trusted multi-level pointer hops"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadSlot {
                    ty: MirType::U64,
                    ..
                }
            )),
        "expected final inode-number load from the projected multi-level pointer field"
    );
}

#[test]
fn test_lower_fentry_multi_level_pointer_index_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("arg0"),
            string_member("fdt"),
            string_member("fd"),
            int_member(0),
            string_member("f_inode"),
            string_member("i_ino"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("multi-level pointer index projection should lower");

    let helper_reads = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
            )
        })
        .count();
    assert!(
        helper_reads == 1,
        "expected only the scalar leaf to use probe_read across trusted pointer indexing"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadSlot {
                    ty: MirType::U64,
                    ..
                }
            )),
        "expected final inode-number load from the indexed multi-level pointer field"
    );
}

#[test]
fn test_lower_generic_field_projection_after_multi_level_pointer_binding() {
    let hir = make_chained_ctx_path_program(vec![
        CellPath {
            members: vec![
                string_member("arg0"),
                string_member("fdt"),
                string_member("fd"),
            ],
        },
        CellPath {
            members: vec![string_member("f_inode"), string_member("i_ino")],
        },
    ]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("post-binding multi-level pointer field projection should lower");

    let helper_reads = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
            )
        })
        .count();
    assert!(
        helper_reads == 1,
        "expected only the scalar leaf to use probe_read across a bound trusted pointer path"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadSlot {
                    ty: MirType::U64,
                    ..
                }
            )),
        "expected final inode number load from helper scratch slot"
    );
}

#[test]
fn test_lower_generic_field_projection_after_binding_root_trampoline_arg() {
    let hir = make_bound_ctx_path_program(
        CellPath {
            members: vec![string_member("arg0")],
        },
        CellPath {
            members: vec![
                string_member("fdt"),
                string_member("fd"),
                string_member("f_inode"),
                string_member("i_ino"),
            ],
        },
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bound root trampoline arg projection should lower");

    let helper_reads = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
            )
        })
        .count();
    assert!(
        helper_reads == 1,
        "expected only the scalar leaf to use probe_read after binding a trusted trampoline arg"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadSlot {
                    ty: MirType::U64,
                    ..
                }
            )),
        "expected final inode number load from the bound trampoline arg"
    );
}

#[test]
fn test_lower_generic_pointer_index_projection_after_binding_root_trampoline_arg() {
    let hir = make_bound_ctx_path_program(
        CellPath {
            members: vec![
                string_member("arg0"),
                string_member("fdt"),
                string_member("fd"),
            ],
        },
        CellPath {
            members: vec![
                int_member(0),
                string_member("f_inode"),
                string_member("i_ino"),
            ],
        },
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bound root trampoline pointer indexing should lower");

    let helper_reads = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
            )
        })
        .count();
    assert!(
        helper_reads == 1,
        "expected only the scalar leaf to use probe_read across bound trusted pointer indexing"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadSlot {
                    ty: MirType::U64,
                    ..
                }
            )),
        "expected final inode number load from the indexed bound pointer"
    );
}

#[test]
fn test_lower_generic_numeric_get_after_binding_pointer_sequence() {
    let hir = make_bound_ctx_get_program(
        CellPath {
            members: vec![
                string_member("arg0"),
                string_member("fdt"),
                string_member("fd"),
            ],
        },
        CellPath {
            members: vec![string_member("f_inode"), string_member("i_ino")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "get".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bound numeric get projection should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
            )),
        "expected helper reads across numeric get and subsequent pointer hops"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadSlot {
                    ty: MirType::U64,
                    ..
                }
            )),
        "expected final inode-number load after numeric get"
    );
}

#[test]
fn test_lower_generic_numeric_get_after_binding_stack_backed_array() {
    let hir = make_bound_ctx_runtime_get_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("comm")],
        },
        CellPath {
            members: vec![string_member("pid")],
        },
        2,
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "get".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("stack-backed array numeric get should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::Add,
                    rhs: MirValue::VReg(_),
                    ..
                }
            )),
        "expected numeric get to add a bounded runtime index to the stack-backed array base"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::I8 | MirType::U8,
                    offset: 0,
                    ..
                }
            )),
        "expected stack-backed array numeric get to load the selected scalar element directly from stack"
    );
}

#[test]
fn test_lower_generic_field_projection_after_runtime_get_stack_backed_bitfield_struct() {
    let hir = make_bound_ctx_runtime_get_path_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("uclamp_req")],
        },
        CellPath {
            members: vec![string_member("pid")],
        },
        2,
        CellPath {
            members: vec![string_member("bucket_id")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "get".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("stack-backed aggregate bitfield projection after numeric get should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::Shr,
                    rhs: MirValue::Const(11),
                    ..
                }
            )),
        "expected bitfield projection to shift bucket_id into place"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::And,
                    rhs: MirValue::Const(7),
                    ..
                }
            )),
        "expected bitfield projection to mask the bucket_id width"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::Load {
                    ty: MirType::U32,
                    ..
                }
            )),
        "expected bitfield projection to load the 32-bit storage word before extraction"
    );
}

#[test]
fn test_lower_generic_field_projection_after_binding_root_trampoline_aggregate() {
    let hir = make_bound_ctx_path_program(
        CellPath {
            members: vec![string_member("arg0")],
        },
        CellPath {
            members: vec![string_member("tv_nsec")],
        },
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "__audit_tk_injoffset");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bound root trampoline aggregate projection should lower");

    let load = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::Load { offset, ty, .. } => Some((*offset, ty.clone())),
            _ => None,
        })
        .expect("expected aggregate field load after binding the root trampoline value");
    assert_eq!(load.0, 8);
    assert_eq!(load.1, MirType::I64);
}

#[test]
fn test_lower_fentry_struct_leaf_emit_uses_struct_size() {
    let projection = KernelBtf::get()
        .function_trampoline_arg_field(
            "security_file_open",
            0,
            &[TrampolineFieldSelector::Field("f_path".to_string())],
        )
        .expect("security_file_open f_path projection should resolve")
        .expect("security_file_open arg0.f_path should exist");
    let TypeInfo::Struct { size, .. } = projection.type_info else {
        panic!("expected security_file_open arg0.f_path to resolve to a struct");
    };

    let hir = make_ctx_path_call_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("f_path")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "emit".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("struct leaf emit should lower");

    let emit_size = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::EmitEvent { size, .. } => Some(*size),
            _ => None,
        })
        .expect("expected emit event");
    assert_eq!(emit_size, size);
}

#[test]
fn test_lower_fentry_struct_leaf_preserves_struct_fields() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("f_path")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("struct leaf access should lower");

    let hinted_ty = result
        .type_hints
        .main
        .values()
        .find_map(|ty| match ty {
            MirType::Ptr { pointee, .. } => match pointee.as_ref() {
                MirType::Struct { name, .. } if name.as_deref() == Some("path") => {
                    Some(pointee.as_ref().clone())
                }
                _ => None,
            },
            _ => None,
        })
        .expect("expected struct leaf type hint");

    let MirType::Struct { fields, .. } = hinted_ty else {
        panic!("expected trampoline struct hint");
    };
    assert!(
        fields
            .iter()
            .any(|field| field.name == "mnt" && !field.synthetic)
    );
    assert!(
        fields
            .iter()
            .any(|field| field.name == "dentry" && !field.synthetic)
    );
    assert!(!fields.iter().any(|field| field.name == "__opaque"));
}

#[test]
fn test_lower_runtime_get_bitfield_struct_preserves_overlapping_layout() {
    let hir = make_bound_ctx_runtime_get_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("uclamp_req")],
        },
        CellPath {
            members: vec![string_member("pid")],
        },
        2,
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "get".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bitfield struct runtime get should lower");

    let hinted_ty = result
        .type_hints
        .main
        .values()
        .find_map(|ty| match ty {
            MirType::Ptr { pointee, .. } => match pointee.as_ref() {
                MirType::Struct { name, .. } if name.as_deref() == Some("uclamp_se") => {
                    Some(pointee.as_ref().clone())
                }
                _ => None,
            },
            _ => None,
        })
        .expect("expected uclamp_se pointer hint");

    assert_eq!(hinted_ty.size(), 4);
    let MirType::Struct { fields, .. } = hinted_ty else {
        panic!("expected uclamp_se struct hint");
    };
    let names: Vec<_> = fields
        .iter()
        .filter(|field| !field.synthetic)
        .map(|field| field.name.as_str())
        .collect();
    assert_eq!(names, vec!["value", "bucket_id", "active", "user_defined"]);
    assert!(
        fields
            .iter()
            .filter(|field| !field.synthetic)
            .all(|field| field.offset == 0)
    );
    assert_eq!(
        fields[0].bitfield,
        Some(crate::compiler::mir::BitfieldInfo {
            bit_offset: 0,
            bit_size: 11,
        })
    );
    assert_eq!(
        fields[1].bitfield,
        Some(crate::compiler::mir::BitfieldInfo {
            bit_offset: 11,
            bit_size: 3,
        })
    );
}

#[test]
fn test_lower_fentry_struct_leaf_count_uses_bytes_counter_map() {
    let hir = make_ctx_path_call_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("f_path")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "count".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("struct leaf count should lower");

    let map_name = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapUpdate { map, .. } => Some(map.name.as_str()),
            _ => None,
        })
        .expect("expected map update");
    assert_eq!(map_name, "bytes_counters");
}

#[test]
fn test_lower_nested_metadata_record_emit_materializes_nested_field_storage() {
    let emit_decl = DeclId::new(42);
    let hir = make_nested_metadata_record_call_program(emit_decl);
    let decl_names = HashMap::from([(emit_decl, "emit".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("nested metadata-only record emit should lower");

    let inner_field = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::EmitRecord { fields } => {
                fields.iter().find(|field| field.name == "inner").cloned()
            }
            _ => None,
        })
        .expect("expected nested record field in emit");

    assert!(
        matches!(
            result.type_hints.main.get(&inner_field.value),
            Some(MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack,
            }) if matches!(
                pointee.as_ref(),
                MirType::Struct { fields, .. }
                    if fields.len() == 2
                        && fields[0].name == "msg"
                        && fields[1].name == "pid"
            )
        ),
        "expected nested emit field to use a stack-backed materialized record pointer"
    );

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("nested metadata-only record emit should compile");
}

#[test]
fn test_lower_nested_metadata_record_count_uses_bytes_counter_map() {
    let count_decl = DeclId::new(42);
    let hir = make_nested_metadata_record_call_program(count_decl);
    let decl_names = HashMap::from([(count_decl, "count".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("nested metadata-only record count should lower");

    let (map_name, key_vreg) = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapUpdate { map, key, .. } => Some((map.name.clone(), *key)),
            _ => None,
        })
        .expect("expected map update");
    assert_eq!(map_name, BYTES_COUNTER_MAP_NAME);
    assert_ne!(map_name, COUNTER_MAP_NAME);

    assert!(
        matches!(
            result.type_hints.main.get(&key_vreg),
            Some(MirType::Ptr {
                pointee,
                address_space: AddressSpace::Stack,
            }) if matches!(
                pointee.as_ref(),
                MirType::Struct { fields, .. }
                    if fields.len() == 2
                        && fields[0].name == "inner"
                        && fields[1].name == "cpu"
            )
        ),
        "expected count key to materialize the metadata-only record into a stack-backed aggregate"
    );

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("nested metadata-only record count should compile");
}

#[test]
fn test_lower_follow_cell_path_on_metadata_only_record_builder_preserves_string_semantics() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("msg".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("hi".into()),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(0),
                    key: RegId::new(1),
                    val: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(0),
                    key: RegId::new(3),
                    val: RegId::new(4),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("msg")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(5),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::String("!".into()),
                },
                HirStmt::StringAppend {
                    src_dst: RegId::new(0),
                    val: RegId::new(6),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 7,
        file_count: 0,
    };

    let result = lower_hir_to_mir_with_hints(
        &HirProgram::new(func, HashMap::new(), vec![], None),
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("metadata-only record builder field projection should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected projected metadata-only record string field to remain a stack-backed string value"
    );
}

#[test]
fn test_lower_record_spread_preserves_spread_field_string_semantics() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("msg".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("hi".into()),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(0),
                    key: RegId::new(1),
                    val: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Record { capacity: 1 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(3),
                    key: RegId::new(4),
                    val: RegId::new(5),
                },
                HirStmt::RecordSpread {
                    src_dst: RegId::new(3),
                    items: RegId::new(0),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("msg")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(6),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::String("!".into()),
                },
                HirStmt::StringAppend {
                    src_dst: RegId::new(3),
                    val: RegId::new(7),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 8,
        file_count: 0,
    };

    let result = lower_hir_to_mir_with_hints(
        &HirProgram::new(func, HashMap::new(), vec![], None),
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("record spread should preserve metadata-backed string field semantics");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected spread string field projection to remain a stack-backed string value"
    );
}

#[test]
fn test_lower_list_spread_uses_runtime_length_guards() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::List { capacity: 8 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::List { capacity: 4 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(10),
                },
                HirStmt::ListPush {
                    src_dst: RegId::new(1),
                    item: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(20),
                },
                HirStmt::ListPush {
                    src_dst: RegId::new(1),
                    item: RegId::new(3),
                },
                HirStmt::ListSpread {
                    src_dst: RegId::new(0),
                    items: RegId::new(1),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };

    let result = lower_hir_to_mir_with_hints(
        &HirProgram::new(func, HashMap::new(), vec![], None),
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("list spread should lower");

    let blocks = &result.program.main.blocks;
    let len_vreg = blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::ListLen { dst, .. } => Some(*dst),
            _ => None,
        })
        .expect("expected list spread to load source runtime length");

    let guarded_indices: Vec<i64> = blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter_map(|inst| match inst {
            MirInst::BinOp {
                op: BinOpKind::Lt,
                lhs: MirValue::Const(idx),
                rhs: MirValue::VReg(rhs),
                ..
            } if *rhs == len_vreg => Some(*idx),
            _ => None,
        })
        .collect();

    assert_eq!(
        guarded_indices,
        vec![0, 1, 2, 3],
        "expected list spread to guard each source slot against the runtime list length"
    );
}

#[test]
fn test_lower_upsert_cell_path_on_metadata_only_record_builder_materializes_base() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("msg".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("hi".into()),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(0),
                    key: RegId::new(1),
                    val: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(0),
                    key: RegId::new(3),
                    val: RegId::new(4),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("msg")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::String("bye".into()),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(5),
                    new_value: RegId::new(6),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(5),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::String("!".into()),
                },
                HirStmt::StringAppend {
                    src_dst: RegId::new(0),
                    val: RegId::new(7),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 8,
        file_count: 0,
    };

    let result = lower_hir_to_mir_with_hints(
        &HirProgram::new(func, HashMap::new(), vec![], None),
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("metadata-only record builder cell path update should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected metadata-only record builder update to preserve stack-backed string semantics"
    );
}

#[test]
fn test_lower_nested_field_access_rejects_nonaggregate_ctx_value() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("tv_nsec")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "ksys_read");

    let err = match lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    ) {
        Ok(_) => panic!("non-aggregate trampoline field projection should fail"),
        Err(err) => err,
    };

    assert!(err.to_string().contains(
        "nested ctx field access requires a struct/union trampoline value or pointer to one"
    ));
}

#[test]
fn test_lower_struct_ops_named_arg_alias() {
    let Some((value_type_name, callback_name, arg_name, expected_idx)) =
        find_struct_ops_named_arg_candidate()
    else {
        return;
    };
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg"), string_member(&arg_name)],
    });
    let probe_ctx = ProbeContext::new_struct_ops_callback(&value_type_name, &callback_name);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("named struct_ops arg alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Arg(idx),
            ..
        } if *idx == expected_idx
    )));
}

#[test]
fn test_lower_struct_ops_named_arg_alias_nested_projection() {
    let Some((value_type_name, callback_name, arg_name, field_name)) =
        find_struct_ops_named_pointer_projection_candidate()
    else {
        return;
    };
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("arg"),
            string_member(&arg_name),
            string_member(&field_name),
        ],
    });
    let probe_ctx = ProbeContext::new_struct_ops_callback(&value_type_name, &callback_name);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("named struct_ops arg alias nested projection should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Arg(0),
                    ..
                }
            )),
        "expected named struct_ops arg alias to resolve through ctx.arg0 before nested projection"
    );
}

#[test]
fn test_lower_tp_btf_named_arg_alias() {
    let Some((tracepoint_name, arg_name, expected_idx)) = find_tp_btf_named_arg_candidate() else {
        return;
    };
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg"), string_member(&arg_name)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::TpBtf, &tracepoint_name);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("named tp_btf arg alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Arg(idx),
            ..
        } if *idx == expected_idx
    )));
}

#[test]
fn test_lower_tp_btf_named_arg_alias_nested_projection() {
    let Some((tracepoint_name, arg_name, field_name)) =
        find_tp_btf_named_pointer_projection_candidate()
    else {
        return;
    };
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("arg"),
            string_member(&arg_name),
            string_member(&field_name),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::TpBtf, &tracepoint_name);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("named tp_btf arg alias nested projection should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Arg(0),
                    ..
                }
            )),
        "expected named tp_btf arg alias to resolve through ctx.arg0 before nested projection"
    );
}

#[test]
fn test_lower_function_trampoline_named_arg_alias() {
    let Some((function_name, arg_name, expected_idx)) =
        find_function_trampoline_named_arg_candidate()
    else {
        return;
    };
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg"), string_member(&arg_name)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, &function_name);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("named BTF trampoline arg alias should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Arg(idx),
            ..
        } if *idx == expected_idx
    )));
}

#[test]
fn test_lower_lsm_named_arg_alias_nested_projection() {
    let Some((hook_name, arg_name, expected_idx)) = find_lsm_named_arg_candidate() else {
        return;
    };
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("arg"),
            string_member(&arg_name),
            string_member("f_flags"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Lsm, &hook_name);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("named LSM arg alias nested projection should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Arg(idx),
                    ..
                } if *idx == expected_idx
            )),
        "expected named LSM arg alias to resolve through ctx.arg0 before nested projection"
    );
}

#[test]
fn test_lower_captured_int_variable() {
    let capture_var = VarId::new(7);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadVariable {
                dst: RegId::new(0),
                var_id: capture_var,
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 1,
        file_count: 0,
    };
    let hir = HirProgram::new(
        func,
        HashMap::new(),
        vec![(capture_var, Value::int(7, Span::test_data()))],
        None,
    );

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("captured integer should lower");

    assert!(matches!(
        result.program.main.blocks[0].instructions.as_slice(),
        [MirInst::Copy {
            src: MirValue::Const(7),
            ..
        }]
    ));
}

#[test]
fn test_inline_where_closure_preserves_captured_bool() {
    let capture_var = VarId::new(9);
    let closure_block_id = nu_protocol::BlockId::new(1);
    let where_decl = DeclId::new(77);

    let main = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(42),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Closure(closure_block_id),
                },
                HirStmt::Call {
                    decl_id: where_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 2,
        file_count: 0,
    };

    let closure = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadVariable {
                dst: RegId::new(0),
                var_id: capture_var,
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 1,
        file_count: 0,
    };

    let hir = HirProgram::new(
        main,
        HashMap::from([(closure_block_id, closure)]),
        vec![(capture_var, Value::bool(true, Span::test_data()))],
        None,
    );
    let decl_names = HashMap::from([(where_decl, "where".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("where closure capture should lower");

    let has_captured_true = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .any(|inst| {
            matches!(
                inst,
                MirInst::Copy {
                    src: MirValue::Const(1),
                    ..
                }
            )
        });

    assert!(
        has_captured_true,
        "expected inlined where closure to materialize the captured bool literal"
    );
}

#[test]
fn test_inline_where_closure_bounded_list_iterate_lowers() {
    let closure_block_id = nu_protocol::BlockId::new(1);
    let where_decl = DeclId::new(77);

    let main = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(42),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Closure(closure_block_id),
                },
                HirStmt::Call {
                    decl_id: where_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 2,
        file_count: 0,
    };

    let closure = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::List { capacity: 2 },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::Int(7),
                    },
                    HirStmt::ListPush {
                        src_dst: RegId::new(0),
                        item: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::Int(8),
                    },
                    HirStmt::ListPush {
                        src_dst: RegId::new(0),
                        item: RegId::new(1),
                    },
                ],
                terminator: HirTerminator::Jump {
                    target: HirBlockId(1),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![],
                terminator: HirTerminator::Iterate {
                    dst: RegId::new(2),
                    stream: RegId::new(0),
                    body: HirBlockId(2),
                    end: HirBlockId(3),
                },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![],
                terminator: HirTerminator::Jump {
                    target: HirBlockId(1),
                },
            },
            HirBlock {
                id: HirBlockId(3),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Bool(true),
                }],
                terminator: HirTerminator::Return { src: RegId::new(3) },
            },
        ],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };

    let hir = HirProgram::new(
        main,
        HashMap::from([(closure_block_id, closure)]),
        vec![],
        None,
    );
    let decl_names = HashMap::from([(where_decl, "where".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("where closure bounded-list iterate should lower");

    let saw_loop = result
        .program
        .main
        .blocks
        .iter()
        .any(|block| matches!(block.terminator, MirInst::LoopHeader { .. }));
    assert!(
        saw_loop,
        "expected inlined where closure iterate to lower a loop header"
    );
}

#[test]
fn test_lower_leading_annotated_mut_scalar_uses_global_backing_and_skips_init_store() {
    let global_var = VarId::new(250);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::StoreVariable {
                    var_id: global_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(1),
                    var_id: global_var,
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(1) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 2,
        file_count: 0,
    };
    let mut hir = HirProgram::new(func, HashMap::new(), vec![], None);
    hir.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Int,
        initial_value: Value::int(7, Span::test_data()),
    }];

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("leading annotated mutable scalar should lower through a data global");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_local_global_250");
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadGlobal {
                    symbol,
                    ty: MirType::I64,
                    ..
                } if symbol == "__nu_local_global_250"
            )),
        "expected leading annotated mutable scalar to load from its global backing"
    );
    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::Store { .. })),
        "expected declaration-time store to be absorbed into .data instead of executing at runtime"
    );
}

#[test]
fn test_lower_leading_annotated_mut_scalar_null_uses_bss_global() {
    let global_var = VarId::new(349);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadVariable {
                dst: RegId::new(0),
                var_id: global_var,
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 1,
        file_count: 0,
    };
    let mut hir = HirProgram::new(func, HashMap::new(), vec![], None);
    hir.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Int,
        initial_value: Value::nothing(Span::test_data()),
    }];

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("leading annotated mutable scalar null should lower through a bss global");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_local_global_349");
    assert_eq!(result.bss_globals[0].size, 8);
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadGlobal {
                    symbol,
                    ty: MirType::I64,
                    ..
                } if symbol == "__nu_local_global_349"
            )),
        "expected leading annotated mutable null scalar to load from its global backing"
    );
}

#[test]
fn test_lower_leading_annotated_mut_record_uses_declared_field_order() {
    let global_var = VarId::new(251);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadVariable {
                dst: RegId::new(0),
                var_id: global_var,
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 1,
        file_count: 0,
    };

    let mut initial = Record::new();
    initial.push("ok", Value::bool(false, Span::test_data()));
    initial.push("pid", Value::int(7, Span::test_data()));

    let mut hir = HirProgram::new(func, HashMap::new(), vec![], None);
    hir.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Record(Box::new([
            ("pid".to_string(), Type::Int),
            ("ok".to_string(), Type::Bool),
        ])),
        initial_value: Value::record(initial, Span::test_data()),
    }];

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("typed annotated mutable record should lower through a data global");

    assert_eq!(result.data_globals.len(), 1);
    let data = &result.data_globals[0].data;
    assert_eq!(data.len(), 16);
    assert_eq!(&data[..8], &7i64.to_le_bytes());
    assert_eq!(data[8], 0);
    assert!(data[9..].iter().all(|byte| *byte == 0));
}

#[test]
fn test_lower_leading_annotated_mut_record_partial_initializer_zero_fills_missing_fields() {
    let global_var = VarId::new(355);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadVariable {
                dst: RegId::new(0),
                var_id: global_var,
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 1,
        file_count: 0,
    };

    let mut initial = Record::new();
    initial.push("pid", Value::int(7, Span::test_data()));

    let mut hir = HirProgram::new(func, HashMap::new(), vec![], None);
    hir.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Record(Box::new([
            ("pid".to_string(), Type::Int),
            (
                "stats".to_string(),
                Type::Record(Box::new([
                    ("hits".to_string(), Type::Int),
                    ("ok".to_string(), Type::Bool),
                ])),
            ),
        ])),
        initial_value: Value::record(initial, Span::test_data()),
    }];

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("partial annotated mutable record initializer should zero-fill fixed-layout fields");

    assert_eq!(result.data_globals.len(), 1);
    let data = &result.data_globals[0].data;
    assert_eq!(data.len(), 24);
    assert_eq!(&data[..8], &7i64.to_le_bytes());
    assert!(data[8..].iter().all(|byte| *byte == 0));
}

#[test]
fn test_lower_leading_annotated_mut_record_null_uses_declared_scalar_layout() {
    let global_var = VarId::new(351);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadVariable {
                dst: RegId::new(0),
                var_id: global_var,
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 1,
        file_count: 0,
    };

    let mut hir = HirProgram::new(func, HashMap::new(), vec![], None);
    hir.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Record(Box::new([
            ("pid".to_string(), Type::Int),
            (
                "stats".to_string(),
                Type::Record(Box::new([
                    ("hits".to_string(), Type::Int),
                    ("ok".to_string(), Type::Bool),
                ])),
            ),
        ])),
        initial_value: Value::nothing(Span::test_data()),
    }];

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("leading annotated mutable null record should lower through a bss global");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_local_global_351");
    assert_eq!(result.bss_globals[0].size, 24);
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadGlobal {
                    symbol,
                    ty: MirType::Struct { .. },
                    ..
                } if symbol == "__nu_local_global_351"
            )),
        "expected leading annotated mutable null record to load from its global backing"
    );
}

#[test]
fn test_lower_leading_annotated_mut_record_partial_initializer_rejects_unknown_field() {
    let global_var = VarId::new(356);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadVariable {
                dst: RegId::new(0),
                var_id: global_var,
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 1,
        file_count: 0,
    };

    let mut initial = Record::new();
    initial.push("pid", Value::int(7, Span::test_data()));
    initial.push("ok", Value::bool(true, Span::test_data()));

    let mut hir = HirProgram::new(func, HashMap::new(), vec![], None);
    hir.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Record(Box::new([("pid".to_string(), Type::Int)])),
        initial_value: Value::record(initial, Span::test_data()),
    }];

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("extra record fields should be rejected for annotated mutable globals");

    assert!(
        err.to_string().contains("unexpected record field 'ok'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_leading_annotated_mut_record_partial_initializer_rejects_missing_string_capacity() {
    let global_var = VarId::new(357);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadVariable {
                dst: RegId::new(0),
                var_id: global_var,
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 1,
        file_count: 0,
    };

    let mut initial = Record::new();
    initial.push("pid", Value::int(7, Span::test_data()));

    let mut hir = HirProgram::new(func, HashMap::new(), vec![], None);
    hir.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Record(Box::new([
            ("pid".to_string(), Type::Int),
            ("comm".to_string(), Type::String),
        ])),
        initial_value: Value::record(initial, Span::test_data()),
    }];

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("missing string field without explicit capacity should be rejected");

    assert!(
        err.to_string().contains("omitted record field 'comm'"),
        "unexpected error: {err}"
    );
    assert!(
        err.to_string()
            .contains("global-define --type 'record{...}'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_leading_annotated_mut_null_string_without_exemplar_is_rejected() {
    let global_var = VarId::new(353);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadVariable {
                dst: RegId::new(0),
                var_id: global_var,
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 1,
        file_count: 0,
    };

    let mut hir = HirProgram::new(func, HashMap::new(), vec![], None);
    hir.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::String,
        initial_value: Value::nothing(Span::test_data()),
    }];

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("annotated mutable null string without exemplar should be rejected");

    assert!(
        err.to_string()
            .contains("cannot use `null` as the initializer"),
        "unexpected error: {err}"
    );
    assert!(
        err.to_string().contains("global-define --type string:N"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_leading_annotated_mut_null_record_with_string_field_is_rejected_helpfully() {
    let global_var = VarId::new(354);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadVariable {
                dst: RegId::new(0),
                var_id: global_var,
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 1,
        file_count: 0,
    };

    let mut hir = HirProgram::new(func, HashMap::new(), vec![], None);
    hir.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Record(Box::new([
            ("pid".to_string(), Type::Int),
            ("comm".to_string(), Type::String),
        ])),
        initial_value: Value::nothing(Span::test_data()),
    }];

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("annotated mutable null record with string field should be rejected");

    assert!(
        err.to_string().contains("nested field 'comm'"),
        "unexpected error: {err}"
    );
    assert!(
        err.to_string().contains("record{...}"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_leading_annotated_mut_duration_and_filesize_use_i64_globals() {
    let duration_var = VarId::new(351);
    let filesize_var = VarId::new(352);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: duration_var,
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(1),
                    var_id: filesize_var,
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(1) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 2,
        file_count: 0,
    };

    let mut hir = HirProgram::new(func, HashMap::new(), vec![], None);
    hir.annotated_mut_globals = vec![
        AnnotatedMutGlobal {
            var_id: duration_var,
            declared_type: Type::Duration,
            initial_value: Value::duration(1234, Span::test_data()),
        },
        AnnotatedMutGlobal {
            var_id: filesize_var,
            declared_type: Type::Filesize,
            initial_value: Value::filesize(4096, Span::test_data()),
        },
    ];

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("annotated mutable duration/filesize globals should lower through i64 data globals");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 2);
    assert_eq!(result.bss_globals.len(), 0);
    assert!(result.data_globals.iter().any(|global| {
        global.name == "__nu_local_global_351" && global.data == 1234i64.to_le_bytes()
    }));
    assert!(result.data_globals.iter().any(|global| {
        global.name == "__nu_local_global_352" && global.data == 4096i64.to_le_bytes()
    }));
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .filter(|inst| matches!(
                inst,
                MirInst::LoadGlobal {
                    ty: MirType::I64,
                    ..
                }
            ))
            .count()
            >= 2,
        "expected annotated duration/filesize globals to load as i64-backed globals"
    );
}

#[test]
fn test_lower_leading_annotated_mut_record_list_field_supports_get() {
    let global_var = VarId::new(252);
    let get_decl = DeclId::new(900);
    let count_decl = DeclId::new(901);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: global_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("vals")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        ..Default::default()
                    },
                },
                HirStmt::Call {
                    decl_id: count_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 3,
        file_count: 0,
    };

    let mut initial = Record::new();
    initial.push(
        "vals",
        Value::list(
            vec![
                Value::int(11, Span::test_data()),
                Value::int(22, Span::test_data()),
            ],
            Span::test_data(),
        ),
    );
    initial.push("pid", Value::int(0, Span::test_data()));

    let mut hir = HirProgram::new(func, HashMap::new(), vec![], None);
    hir.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Record(Box::new([
            ("vals".to_string(), Type::List(Box::new(Type::Int))),
            ("pid".to_string(), Type::Int),
        ])),
        initial_value: Value::record(initial, Span::test_data()),
    }];

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::from([
            (get_decl, "get".to_string()),
            (count_decl, "count".to_string()),
        ]),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("annotated mutable record list field should lower as a stack-backed list value");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListGet { .. })),
        "expected projected annotated-global list field to lower through ListGet"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::MapUpdate {
                    map: MapRef { name, .. },
                    ..
                } if name == COUNTER_MAP_NAME
            )),
        "expected list get result to be typed as a scalar key, not a bytes counter key"
    );
}

#[test]
fn test_lower_leading_annotated_mut_record_array_with_nested_numeric_list_field() {
    let global_var = VarId::new(251);
    let count_decl = DeclId::new(902);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: global_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1), string_member("samples"), int_member(1)],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::Call {
                    decl_id: count_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 2,
        file_count: 0,
    };

    let mut first = Record::new();
    first.push(
        "samples",
        Value::list(
            vec![
                Value::int(1, Span::test_data()),
                Value::int(2, Span::test_data()),
            ],
            Span::test_data(),
        ),
    );
    let mut second = Record::new();
    second.push(
        "samples",
        Value::list(
            vec![
                Value::int(3, Span::test_data()),
                Value::int(4, Span::test_data()),
            ],
            Span::test_data(),
        ),
    );

    let mut hir = HirProgram::new(func, HashMap::new(), vec![], None);
    hir.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::List(Box::new(Type::Record(Box::new([(
            "samples".to_string(),
            Type::List(Box::new(Type::Int)),
        )])))),
        initial_value: Value::list(
            vec![
                Value::record(first, Span::test_data()),
                Value::record(second, Span::test_data()),
            ],
            Span::test_data(),
        ),
    }];

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::from([(count_decl, "count".to_string())]),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("annotated fixed record arrays should allow nested numeric-list fields");

    let mut expected = Vec::new();
    expected.extend_from_slice(&2u64.to_le_bytes());
    expected.extend_from_slice(&1i64.to_le_bytes());
    expected.extend_from_slice(&2i64.to_le_bytes());
    expected.extend_from_slice(&2u64.to_le_bytes());
    expected.extend_from_slice(&3i64.to_le_bytes());
    expected.extend_from_slice(&4i64.to_le_bytes());

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.data_globals[0].data, expected);
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::MapUpdate {
                    map: MapRef { name, .. },
                    ..
                } if name == COUNTER_MAP_NAME
            )),
        "expected nested numeric-list field to project as a scalar key"
    );
}

#[test]
fn test_lower_leading_annotated_mut_record_array_with_nested_string_field() {
    let global_var = VarId::new(250);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: global_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1), string_member("name")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("!".into()),
                },
                HirStmt::StringAppend {
                    src_dst: RegId::new(0),
                    val: RegId::new(2),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 3,
        file_count: 0,
    };

    let mut first = Record::new();
    first.push("name", Value::string("aa", Span::test_data()));
    let mut second = Record::new();
    second.push("name", Value::string("bb", Span::test_data()));

    let mut hir = HirProgram::new(func, HashMap::new(), vec![], None);
    hir.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::List(Box::new(Type::Record(Box::new([(
            "name".to_string(),
            Type::String,
        )])))),
        initial_value: Value::list(
            vec![
                Value::record(first, Span::test_data()),
                Value::record(second, Span::test_data()),
            ],
            Span::test_data(),
        ),
    }];

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("annotated fixed record arrays should materialize nested string fields");

    assert_eq!(result.data_globals.len(), 1);
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected projected nested string field to lower through StringAppend"
    );
}

#[test]
fn test_lower_get_with_single_int_cell_path_uses_constant_list_index() {
    let global_var = VarId::new(254);
    let get_decl = DeclId::new(600);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: global_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1)],
                    })),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 2,
        file_count: 0,
    };

    let mut hir = HirProgram::new(func, HashMap::new(), vec![], None);
    hir.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::List(Box::new(Type::Int)),
        initial_value: Value::list(
            vec![
                Value::int(11, Span::test_data()),
                Value::int(22, Span::test_data()),
            ],
            Span::test_data(),
        ),
    }];

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::from([(get_decl, "get".to_string())]),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("get with a single-int cell path should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::ListGet {
                    idx: MirValue::Const(1),
                    ..
                }
            )),
        "expected single-int cell path get argument to lower as a constant list index"
    );
}

#[test]
fn test_lower_leading_annotated_mut_record_string_field_supports_string_append() {
    let global_var = VarId::new(253);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: global_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("comm")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("!".into()),
                },
                HirStmt::StringAppend {
                    src_dst: RegId::new(0),
                    val: RegId::new(2),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 3,
        file_count: 0,
    };

    let mut initial = Record::new();
    initial.push("comm", Value::string("hi", Span::test_data()));
    initial.push("pid", Value::int(0, Span::test_data()));

    let mut hir = HirProgram::new(func, HashMap::new(), vec![], None);
    hir.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Record(Box::new([
            ("comm".to_string(), Type::String),
            ("pid".to_string(), Type::Int),
        ])),
        initial_value: Value::record(initial, Span::test_data()),
    }];

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("annotated mutable record string field should lower as a stack-backed string value");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected projected annotated-global string field to lower through StringAppend"
    );
}
