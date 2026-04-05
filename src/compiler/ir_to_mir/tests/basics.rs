use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::hir::{
    HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
};
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::{AddressSpace, BYTES_COUNTER_MAP_NAME, StructField};
use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector, TypeInfo};
use nu_protocol::ast::{CellPath, Comparison, Math, Operator, PathMember, RangeInclusion};
use nu_protocol::casing::Casing;
use nu_protocol::{DeclId, Record, RegId, Span, Value, VarId};
use std::collections::HashMap;

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

fn make_ctx_path_call_program(path: CellPath, decl_id: DeclId) -> HirProgram {
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
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 4],
        ast: vec![None; 4],
        comments: vec![],
        register_count: 2,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_map_put_get_projection_program(
    map_put_decl: DeclId,
    map_get_decl: DeclId,
    count_decl: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let lookup_var = VarId::new(1);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("arg0"), string_member("f_path")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String(b"cached_path".to_vec()),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(3),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("pid")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(3),
                        path: RegId::new(4),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(5),
                        lit: HirLiteral::String(b"hash".to_vec()),
                    },
                    HirStmt::Call {
                        decl_id: map_put_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2), RegId::new(3)],
                            named: vec![(b"kind".to_vec(), RegId::new(5))],
                            ..Default::default()
                        },
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(4),
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            named: vec![(b"kind".to_vec(), RegId::new(5))],
                            ..Default::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(6),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(6),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: lookup_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("dentry"), string_member("d_flags")],
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
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                }],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 21],
        ast: vec![None; 21],
        comments: vec![],
        register_count: 7,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_map_get_projection_program(map_get_decl: DeclId, count_decl: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let lookup_var = VarId::new(1);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("pid")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String(b"cached_path".to_vec()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::String(b"hash".to_vec()),
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            named: vec![(b"kind".to_vec(), RegId::new(3))],
                            ..Default::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(4),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: lookup_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("dentry"), string_member("d_flags")],
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
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 12],
        ast: vec![None; 12],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_map_get_whole_value_program(map_get_decl: DeclId, terminal_decl: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let lookup_var = VarId::new(1);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("pid")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String(b"cached_path".to_vec()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::String(b"hash".to_vec()),
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            named: vec![(b"kind".to_vec(), RegId::new(3))],
                            ..Default::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(4),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: lookup_var,
                    },
                    HirStmt::Call {
                        decl_id: terminal_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs::default(),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 10],
        ast: vec![None; 10],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_map_get_record_emit_program(map_get_decl: DeclId, emit_decl: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let lookup_var = VarId::new(1);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("pid")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String(b"cached_path".to_vec()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::String(b"hash".to_vec()),
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            named: vec![(b"kind".to_vec(), RegId::new(3))],
                            ..Default::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(4),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::Record { capacity: 1 },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::String(b"path".to_vec()),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(2),
                        var_id: lookup_var,
                    },
                    HirStmt::RecordInsert {
                        src_dst: RegId::new(0),
                        key: RegId::new(1),
                        val: RegId::new(2),
                    },
                    HirStmt::Call {
                        decl_id: emit_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs::default(),
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                }],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 16],
        ast: vec![None; 16],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_map_put_program(map_put_decl: DeclId, flags: i64, kind: &str) -> HirProgram {
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
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("arg0"), string_member("f_path")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"cached_path".to_vec()),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(3),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("pid")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String(kind.as_bytes().to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Int(flags),
                },
                HirStmt::Call {
                    decl_id: map_put_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2), RegId::new(3)],
                        named: vec![
                            (b"kind".to_vec(), RegId::new(5)),
                            (b"flags".to_vec(), RegId::new(6)),
                        ],
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 11],
        ast: vec![None; 11],
        comments: vec![],
        register_count: 7,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_map_copy_projection_program(
    map_put_decl: DeclId,
    map_get_decl: DeclId,
    count_decl: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let lookup_var = VarId::new(1);
    let copied_var = VarId::new(2);
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("arg0"), string_member("f_path")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String(b"cached_path".to_vec()),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(3),
                        var_id: ctx_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("pid")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(3),
                        path: RegId::new(4),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(5),
                        lit: HirLiteral::String(b"hash".to_vec()),
                    },
                    HirStmt::Call {
                        decl_id: map_put_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2), RegId::new(3)],
                            named: vec![(b"kind".to_vec(), RegId::new(5))],
                            ..Default::default()
                        },
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(4),
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            named: vec![(b"kind".to_vec(), RegId::new(5))],
                            ..Default::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(6),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(6),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(3),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: lookup_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(7),
                        lit: HirLiteral::String(b"copied_path".to_vec()),
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(3),
                        var_id: ctx_var,
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(3),
                        path: RegId::new(4),
                    },
                    HirStmt::Call {
                        decl_id: map_put_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(7), RegId::new(3)],
                            named: vec![(b"kind".to_vec(), RegId::new(5))],
                            ..Default::default()
                        },
                    },
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: ctx_var,
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(4),
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(7)],
                            named: vec![(b"kind".to_vec(), RegId::new(5))],
                            ..Default::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: copied_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(8),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(8),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(2),
                    if_false: HirBlockId(3),
                },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: copied_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("dentry"), string_member("d_flags")],
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
            },
            HirBlock {
                id: HirBlockId(3),
                stmts: vec![],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 30],
        ast: vec![None; 30],
        comments: vec![],
        register_count: 9,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_map_delete_program(map_delete_decl: DeclId, kind: &str) -> HirProgram {
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
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("pid")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"cached_path".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(kind.as_bytes().to_vec()),
                },
                HirStmt::Call {
                    decl_id: map_delete_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        named: vec![(b"kind".to_vec(), RegId::new(3))],
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 7],
        ast: vec![None; 7],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_captured_map_delete_program(
    map_delete_decl: DeclId,
    map_name_var: VarId,
    kind: &str,
) -> HirProgram {
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
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("pid")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: map_name_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(kind.as_bytes().to_vec()),
                },
                HirStmt::Call {
                    decl_id: map_delete_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        named: vec![(b"kind".to_vec(), RegId::new(3))],
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 7],
        ast: vec![None; 7],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(
        func,
        HashMap::new(),
        vec![(
            map_name_var,
            Value::string("captured_path", Span::test_data()),
        )],
        Some(ctx_var),
    )
}

fn make_chained_ctx_path_program(paths: Vec<CellPath>) -> HirProgram {
    let ctx_var = VarId::new(0);
    let mut stmts = vec![HirStmt::LoadVariable {
        dst: RegId::new(0),
        var_id: ctx_var,
    }];
    for (idx, path) in paths.into_iter().enumerate() {
        let path_reg = RegId::new((idx + 1) as u32);
        stmts.push(HirStmt::LoadLiteral {
            dst: path_reg,
            lit: HirLiteral::CellPath(Box::new(path)),
        });
        stmts.push(HirStmt::FollowCellPath {
            src_dst: RegId::new(0),
            path: path_reg,
        });
    }
    let register_count = 1 + stmts
        .iter()
        .filter(|stmt| matches!(stmt, HirStmt::LoadLiteral { .. }))
        .count() as u32;
    let span_count = stmts.len() + 1;
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); span_count],
        ast: vec![None; span_count],
        comments: vec![],
        register_count,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_bound_ctx_path_program(binding: CellPath, access: CellPath) -> HirProgram {
    let ctx_var = VarId::new(0);
    let local_var = VarId::new(1);
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
                    lit: HirLiteral::CellPath(Box::new(binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::StoreVariable {
                    var_id: local_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: local_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::CellPath(Box::new(access)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(2),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 8],
        ast: vec![None; 8],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_bound_ctx_get_program(binding: CellPath, access: CellPath, decl_id: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let bound_var = VarId::new(1);
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
                    lit: HirLiteral::CellPath(Box::new(binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::StoreVariable {
                    var_id: bound_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: bound_var,
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::CellPath(Box::new(access)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(3),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 9],
        ast: vec![None; 9],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_bound_ctx_runtime_get_program(
    binding: CellPath,
    idx_binding: CellPath,
    modulus: i64,
    decl_id: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let bound_var = VarId::new(1);
    let idx_var = VarId::new(2);
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
                    lit: HirLiteral::CellPath(Box::new(idx_binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(modulus),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Math(Math::Modulo),
                    rhs: RegId::new(2),
                },
                HirStmt::StoreVariable {
                    var_id: idx_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::StoreVariable {
                    var_id: bound_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: bound_var,
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: idx_var,
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 13],
        ast: vec![None; 13],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_bound_ctx_runtime_get_path_program(
    binding: CellPath,
    idx_binding: CellPath,
    modulus: i64,
    access: CellPath,
    decl_id: DeclId,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let bound_var = VarId::new(1);
    let idx_var = VarId::new(2);
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
                    lit: HirLiteral::CellPath(Box::new(idx_binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(modulus),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Math(Math::Modulo),
                    rhs: RegId::new(2),
                },
                HirStmt::StoreVariable {
                    var_id: idx_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(binding)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::StoreVariable {
                    var_id: bound_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: bound_var,
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: idx_var,
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(access)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 15],
        ast: vec![None; 15],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_range_iterate_program(start: i64, step: HirLiteral, end: i64) -> HirProgram {
    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::Int(start),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: step,
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
                stmts: vec![],
                terminator: HirTerminator::Jump {
                    target: HirBlockId(0),
                },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 5],
        ast: vec![None; 5],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
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
                limit,
                body,
                exit,
                ..
            } => Some((*start, *limit, *body, *exit)),
            _ => None,
        })
        .expect("expected loop header");
    assert_eq!(loop_header.0, 0);
    assert_eq!(loop_header.1, 2);
    assert_eq!(
        result.program.main.block(loop_header.2).instructions.len(),
        1
    );
    assert!(
        result
            .program
            .main
            .block(loop_header.3)
            .instructions
            .iter()
            .any(|inst| matches!(
                inst,
                MirInst::Copy {
                    src: MirValue::Const(0),
                    ..
                }
            )),
        "expected exit edge to initialize the loop result register"
    );
}

#[test]
fn test_lower_descending_range_iterate_is_rejected() {
    let hir = make_range_iterate_program(3, HirLiteral::Int(-1), 0);

    let err = match lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    ) {
        Ok(_) => panic!("descending iterate should be rejected"),
        Err(err) => err,
    };

    assert!(
        err.to_string()
            .contains("descending ranges are not supported"),
        "unexpected error: {err}"
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

    assert!(eq_consts.contains(&0x8100));
    assert!(eq_consts.contains(&0x88a8));
    assert!(eq_consts.contains(&0x9100));
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
    assert!(
        helper_reads >= 2,
        "expected chained kernel reads for intermediate pointer hop"
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
                    ty: MirType::Ptr {
                        address_space: AddressSpace::Kernel,
                        ..
                    },
                    ..
                }
            )),
        "expected intermediate pointer load from helper scratch slot"
    );
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
        helper_reads >= 3,
        "expected chained kernel reads across a deeper post-binding pointer path"
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
        helper_reads >= 5,
        "expected chained helper reads across the intermediate pointer, multi-level pointer hop, and scalar leaf"
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
        helper_reads >= 5,
        "expected chained helper reads across direct pointer indexing and subsequent pointer hops"
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
        helper_reads >= 5,
        "expected chained helper reads across a bound multi-level pointer path"
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
        helper_reads >= 4,
        "expected chained helper reads after binding a root trampoline pointer arg"
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
        helper_reads >= 4,
        "expected helper reads across bound pointer indexing and subsequent pointer hops"
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
                MirInst::BinOp {
                    op: BinOpKind::Mul,
                    rhs: MirValue::Const(8),
                    ..
                }
            )),
        "expected numeric get to scale the pointer index by element size"
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
fn test_lower_map_get_preserves_prior_typed_struct_schema() {
    let hir =
        make_map_put_get_projection_program(DeclId::new(42), DeclId::new(43), DeclId::new(44));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-put".to_string());
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "count".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("typed map put/get projection should lower");

    assert!(result.type_hints.main.values().any(|ty| matches!(
        ty,
        MirType::Ptr {
            pointee,
            address_space: AddressSpace::Map,
        } if matches!(
            pointee.as_ref(),
            MirType::Struct { name, fields, .. }
                if name.as_deref() == Some("path")
                    && fields.len() == 2
                    && fields[0].name == "mnt"
                    && fields[0].offset == 0
                    && fields[1].name == "dentry"
                    && fields[1].offset == 8
        )
    )));

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| matches!(block.terminator, MirInst::Branch { .. })),
        "expected null-check branch around typed map-get result"
    );
}

#[test]
fn test_lower_map_get_uses_external_typed_struct_schema() {
    let hir = make_map_get_projection_program(DeclId::new(43), DeclId::new(44));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "count".to_string());

    let external_schema = HashMap::from([(
        MapRef {
            name: "cached_path".to_string(),
            kind: MapKind::Hash,
        },
        MirType::Struct {
            name: Some("path".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "mnt".to_string(),
                    ty: MirType::U64,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "dentry".to_string(),
                    ty: MirType::Ptr {
                        pointee: Box::new(MirType::Struct {
                            name: Some("dentry".to_string()),
                            kernel_btf_type_id: None,
                            fields: vec![StructField {
                                name: "d_flags".to_string(),
                                ty: MirType::U32,
                                offset: 0,
                                synthetic: false,
                                bitfield: None,
                            }],
                        }),
                        address_space: AddressSpace::Kernel,
                    },
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        },
    )]);

    let result = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("external typed map schema should lower");

    assert_eq!(result.generic_map_value_types, external_schema);
    assert!(result.type_hints.main.values().any(|ty| matches!(
        ty,
        MirType::Ptr {
            pointee,
            address_space: AddressSpace::Map,
        } if matches!(
            pointee.as_ref(),
            MirType::Struct { name, fields, .. }
                if name.as_deref() == Some("path")
                    && fields.len() == 2
                    && fields[0].name == "mnt"
                    && fields[1].name == "dentry"
        )
    )));
}

#[test]
fn test_lower_map_put_rejects_conflicting_external_schema() {
    let hir = make_map_put_program(DeclId::new(42), 0, "hash");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-put".to_string());

    let external_schema = HashMap::from([(
        MapRef {
            name: "cached_path".to_string(),
            kind: MapKind::Hash,
        },
        MirType::I64,
    )]);

    let err = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("conflicting pinned schema should fail");

    assert!(err.to_string().contains("conflicts with pinned map schema"));
}

#[test]
fn test_lower_map_get_whole_struct_count_uses_bytes_counters() {
    let hir = make_map_get_whole_value_program(DeclId::new(43), DeclId::new(44));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "count".to_string());

    let external_schema = HashMap::from([(
        MapRef {
            name: "cached_path".to_string(),
            kind: MapKind::Hash,
        },
        MirType::Struct {
            name: Some("path".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "mnt".to_string(),
                    ty: MirType::U64,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "dentry".to_string(),
                    ty: MirType::Ptr {
                        pointee: Box::new(MirType::Struct {
                            name: Some("dentry".to_string()),
                            kernel_btf_type_id: None,
                            fields: vec![StructField {
                                name: "d_flags".to_string(),
                                ty: MirType::U32,
                                offset: 0,
                                synthetic: false,
                                bitfield: None,
                            }],
                        }),
                        address_space: AddressSpace::Kernel,
                    },
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        },
    )]);

    let result = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("whole-value typed map-get count should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::MapUpdate { map, .. } if map.name == BYTES_COUNTER_MAP_NAME
            ))
    );
}

#[test]
fn test_lower_map_get_whole_struct_emit_uses_full_struct_size() {
    let hir = make_map_get_whole_value_program(DeclId::new(43), DeclId::new(44));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "emit".to_string());

    let external_schema = HashMap::from([(
        MapRef {
            name: "cached_path".to_string(),
            kind: MapKind::Hash,
        },
        MirType::Struct {
            name: Some("path".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "mnt".to_string(),
                    ty: MirType::U64,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "dentry".to_string(),
                    ty: MirType::Ptr {
                        pointee: Box::new(MirType::Struct {
                            name: Some("dentry".to_string()),
                            kernel_btf_type_id: None,
                            fields: vec![StructField {
                                name: "d_flags".to_string(),
                                ty: MirType::U32,
                                offset: 0,
                                synthetic: false,
                                bitfield: None,
                            }],
                        }),
                        address_space: AddressSpace::Kernel,
                    },
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        },
    )]);

    let result = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("whole-value typed map-get emit should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::EmitEvent { size, .. } if *size == 16))
    );
}

#[test]
fn test_lower_map_get_record_emit_preserves_nested_struct_field_type() {
    let hir = make_map_get_record_emit_program(DeclId::new(43), DeclId::new(44));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "emit".to_string());

    let external_schema = HashMap::from([(
        MapRef {
            name: "cached_path".to_string(),
            kind: MapKind::Hash,
        },
        MirType::Struct {
            name: Some("path".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "mnt".to_string(),
                    ty: MirType::U64,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "dentry".to_string(),
                    ty: MirType::Ptr {
                        pointee: Box::new(MirType::Struct {
                            name: Some("dentry".to_string()),
                            kernel_btf_type_id: None,
                            fields: vec![StructField {
                                name: "d_flags".to_string(),
                                ty: MirType::U32,
                                offset: 0,
                                synthetic: false,
                                bitfield: None,
                            }],
                        }),
                        address_space: AddressSpace::Kernel,
                    },
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        },
    )]);

    let result = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("record emit around typed map-get should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::EmitRecord { fields }
                    if fields.len() == 1
                        && fields[0].name == "path"
                        && matches!(
                            fields[0].ty,
                            MirType::Struct { ref name, ref fields, .. }
                                if name.as_deref() == Some("path")
                                    && fields.len() == 2
                                    && fields[0].name == "mnt"
                                    && fields[1].name == "dentry"
                        )
            ))
    );
}

#[test]
fn test_lower_map_put_respects_kind_and_flags() {
    let hir = make_map_put_program(DeclId::new(42), 1, "per-cpu-hash");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-put".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-put should lower");

    let update = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapUpdate {
                map, key, flags, ..
            } if map.name == "cached_path" => Some((map.kind, *key, *flags)),
            _ => None,
        })
        .expect("expected generic map update");
    assert_eq!(update.0, MapKind::PerCpuHash);
    assert_eq!(update.2, 1);
}

#[test]
fn test_lower_map_put_respects_lru_hash_kind() {
    let hir = make_map_put_program(DeclId::new(42), 1, "lru-hash");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-put".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("lru map-put should lower");

    let update = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapUpdate {
                map, key, flags, ..
            } if map.name == "cached_path" => Some((map.kind, *key, *flags)),
            _ => None,
        })
        .expect("expected generic map update");
    assert_eq!(update.0, MapKind::LruHash);
    assert_eq!(update.2, 1);
}

#[test]
fn test_lower_map_put_of_map_get_root_preserves_copied_map_schema() {
    let hir = make_map_copy_projection_program(DeclId::new(42), DeclId::new(43), DeclId::new(44));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-put".to_string());
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "count".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-to-map copy projection should lower");

    assert!(matches!(
        result.generic_map_value_types.get(&MapRef {
            name: "copied_path".to_string(),
            kind: MapKind::Hash,
        }),
        Some(MirType::Struct { name, fields, .. })
            if name.as_deref() == Some("path")
                && fields.len() == 2
                && fields[0].name == "mnt"
                && fields[1].name == "dentry"
    ));
}

#[test]
fn test_lower_map_delete_respects_kind() {
    let hir = make_map_delete_program(DeclId::new(42), "per-cpu-hash");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-delete".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-delete should lower");

    let kind = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapDelete { map, .. } if map.name == "cached_path" => Some(map.kind),
            _ => None,
        })
        .expect("expected generic map delete");
    assert_eq!(kind, MapKind::PerCpuHash);
}

#[test]
fn test_lower_captured_string_map_name_respects_literal_metadata() {
    let hir = make_captured_map_delete_program(DeclId::new(42), VarId::new(11), "hash");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-delete".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("captured string map name should lower");

    let map_name = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapDelete { map, .. } => Some(map.name.as_str()),
            _ => None,
        })
        .expect("expected generic map delete");

    assert_eq!(map_name, "captured_path");
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
fn test_lower_load_value_duration_as_const() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadValue {
                dst: RegId::new(0),
                val: Box::new(Value::duration(1234, Span::test_data())),
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("duration load value should lower");

    assert!(matches!(
        result.program.main.blocks[0].instructions.as_slice(),
        [MirInst::Copy {
            src: MirValue::Const(1234),
            ..
        }]
    ));
}

#[test]
fn test_lower_load_value_string_can_drive_map_get_name() {
    let map_get_decl = DeclId::new(77);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::string("demo_map", Span::test_data())),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: map_get_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0), RegId::new(1)],
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);
    let decl_names = HashMap::from([(map_get_decl, "map-get".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("string load value should satisfy map-get literal name");

    let has_lookup = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .any(|inst| {
            matches!(
                inst,
                MirInst::MapLookup { map, .. }
                    if map.name == "demo_map" && map.kind == MapKind::Hash
            )
        });

    assert!(
        has_lookup,
        "expected map-get to use the loaded string value as its map name"
    );
}

#[test]
fn test_lower_glob_pattern_literal_can_drive_map_get_name() {
    let map_get_decl = DeclId::new(78);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::GlobPattern {
                        val: b"demo_glob_map".to_vec(),
                        no_expand: true,
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: map_get_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0), RegId::new(1)],
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);
    let decl_names = HashMap::from([(map_get_decl, "map-get".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("glob pattern literal should satisfy map-get literal name");

    let has_lookup = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .any(|inst| {
            matches!(
                inst,
                MirInst::MapLookup { map, .. }
                    if map.name == "demo_glob_map" && map.kind == MapKind::Hash
            )
        });

    assert!(
        has_lookup,
        "expected map-get to use the glob-pattern literal as its map name"
    );
}

#[test]
fn test_lower_load_value_record_emit_preserves_nested_struct_field_type() {
    let emit_decl = DeclId::new(79);

    let mut path = Record::new();
    path.push("mnt", Value::int(1, Span::test_data()));
    path.push("dentry", Value::int(2, Span::test_data()));

    let mut outer = Record::new();
    outer.push("path", Value::record(path, Span::test_data()));
    outer.push("pid", Value::int(7, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::record(outer, Span::test_data())),
                },
                HirStmt::Call {
                    decl_id: emit_decl,
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
        register_count: 1,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);
    let decl_names = HashMap::from([(emit_decl, "emit".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("constant record load value should emit as a typed record");

    assert_eq!(
        result.readonly_globals.len(),
        1,
        "expected constant record lowering to emit one readonly global"
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
                MirInst::LoadReadonlyGlobal { symbol, .. }
                    if symbol == &result.readonly_globals[0].name
            )),
        "expected constant record lowering to load from the emitted readonly global"
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
                MirInst::EmitRecord { fields }
                    if fields.len() == 2
                        && fields[0].name == "path"
                        && matches!(
                            fields[0].ty,
                            MirType::Struct { ref fields, .. }
                                if fields.len() == 2
                                    && fields[0].name == "mnt"
                                    && fields[1].name == "dentry"
                        )
                        && fields[1].name == "pid"
                        && fields[1].ty == MirType::I64
            ))
    );
}

#[test]
fn test_lower_load_value_numeric_list_builds_list_pushes() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadValue {
                dst: RegId::new(0),
                val: Box::new(Value::list(
                    vec![
                        Value::int(1, Span::test_data()),
                        Value::duration(2, Span::test_data()),
                        Value::bool(true, Span::test_data()),
                    ],
                    Span::test_data(),
                )),
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("numeric constant list load values should lower");

    let has_list_new = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .any(|inst| matches!(inst, MirInst::ListNew { max_len, .. } if *max_len == 3));
    let list_push_count = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::ListPush { .. }))
        .count();

    assert!(
        has_list_new,
        "expected numeric constant list to allocate a list buffer"
    );
    assert_eq!(
        list_push_count, 3,
        "expected one ListPush per constant list element"
    );
}

#[test]
fn test_lower_load_value_non_numeric_list_is_rejected() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadValue {
                dst: RegId::new(0),
                val: Box::new(Value::list(
                    vec![
                        Value::int(1, Span::test_data()),
                        Value::string("bad", Span::test_data()),
                    ],
                    Span::test_data(),
                )),
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("non-numeric constant list values should remain unsupported");

    assert!(
        err.to_string()
            .contains("constant lists currently only support numeric scalar elements")
    );
}

#[test]
fn test_lower_load_value_record_with_nested_list_is_rejected() {
    let mut rec = Record::new();
    rec.push(
        "numbers",
        Value::list(
            vec![
                Value::int(1, Span::test_data()),
                Value::int(2, Span::test_data()),
            ],
            Span::test_data(),
        ),
    );

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadValue {
                dst: RegId::new(0),
                val: Box::new(Value::record(rec, Span::test_data())),
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("records with nested lists should remain unsupported");

    assert!(
        err.to_string()
            .contains("constant lists nested inside records are not yet supported")
    );
}

#[test]
fn test_lower_captured_record_emit_preserves_nested_struct_field_type() {
    let capture_var = VarId::new(13);
    let emit_decl = DeclId::new(80);

    let mut path = Record::new();
    path.push("mnt", Value::int(1, Span::test_data()));
    path.push("dentry", Value::int(2, Span::test_data()));

    let mut outer = Record::new();
    outer.push("path", Value::record(path, Span::test_data()));
    outer.push("pid", Value::int(7, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: capture_var,
                },
                HirStmt::Call {
                    decl_id: emit_decl,
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
        register_count: 1,
        file_count: 0,
    };
    let hir = HirProgram::new(
        func,
        HashMap::new(),
        vec![(capture_var, Value::record(outer, Span::test_data()))],
        None,
    );
    let decl_names = HashMap::from([(emit_decl, "emit".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("captured constant record should emit as a typed record");

    assert_eq!(
        result.readonly_globals.len(),
        1,
        "expected captured constant record lowering to emit one readonly global"
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
                MirInst::LoadReadonlyGlobal { symbol, .. }
                    if symbol == &result.readonly_globals[0].name
            )),
        "expected captured constant record lowering to load from the emitted readonly global"
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
                MirInst::EmitRecord { fields }
                    if fields.len() == 2
                        && fields[0].name == "path"
                        && matches!(
                            fields[0].ty,
                            MirType::Struct { ref fields, .. }
                                if fields.len() == 2
                                    && fields[0].name == "mnt"
                                    && fields[1].name == "dentry"
                        )
                        && fields[1].name == "pid"
                        && fields[1].ty == MirType::I64
            ))
    );
}

#[test]
fn test_lower_captured_numeric_list_builds_list_pushes() {
    let capture_var = VarId::new(15);
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
        vec![(
            capture_var,
            Value::list(
                vec![
                    Value::int(1, Span::test_data()),
                    Value::duration(2, Span::test_data()),
                    Value::bool(true, Span::test_data()),
                ],
                Span::test_data(),
            ),
        )],
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
    .expect("captured numeric list should lower");

    let list_push_count = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::ListPush { .. }))
        .count();

    assert_eq!(
        list_push_count, 3,
        "expected one ListPush per captured list element"
    );
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
