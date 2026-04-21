use super::*;
use crate::compiler::hir::{
    HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
};
use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector};
use nu_protocol::ast::{CellPath, Comparison, Math, Operator, PathMember, RangeInclusion};
use nu_protocol::casing::Casing;
use nu_protocol::{DeclId, RegId, Span, Value, VarId};
use std::collections::HashMap;

pub(super) fn string_member(name: &str) -> PathMember {
    PathMember::test_string(name.to_string(), false, Casing::Sensitive)
}

pub(super) fn int_member(index: usize) -> PathMember {
    PathMember::Int {
        val: index,
        span: Span::test_data(),
        optional: false,
    }
}

pub(super) fn make_ctx_path_program(path: CellPath) -> HirProgram {
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

pub(super) fn make_ctx_path_call_program(path: CellPath, decl_id: DeclId) -> HirProgram {
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

pub(super) fn make_ctx_iterate_count_program(path: CellPath, decl_id: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
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
                        lit: HirLiteral::CellPath(Box::new(path)),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
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
                stmts: vec![HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(2),
                    args: HirCallArgs::default(),
                }],
                terminator: HirTerminator::Jump {
                    target: HirBlockId(1),
                },
            },
            HirBlock {
                id: HirBlockId(3),
                stmts: vec![],
                terminator: HirTerminator::Return { src: RegId::new(2) },
            },
        ],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 4],
        ast: vec![None; 4],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

pub(super) fn make_ctx_upsert_program(path: CellPath, lit: HirLiteral) -> HirProgram {
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
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit,
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(1),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 5],
        ast: vec![None; 5],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

pub(super) fn make_return_literal_program(lit: HirLiteral) -> HirProgram {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadLiteral {
                dst: RegId::new(0),
                lit,
            }],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data()],
        ast: vec![None],
        comments: vec![],
        register_count: 1,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

pub(super) fn find_struct_ops_named_arg_candidate() -> Option<(String, String, String, u8)> {
    for (value_type_name, callback_name, arg_name, expected_idx) in [
        ("sched_ext_ops", "select_cpu", "p", 0u8),
        ("sched_ext_ops", "select_cpu", "prev_cpu", 1),
        ("tcp_congestion_ops", "ssthresh", "sk", 0),
        ("tcp_congestion_ops", "cong_avoid", "sk", 0),
        ("tcp_congestion_ops", "init", "sk", 0),
    ] {
        if matches!(
            KernelBtf::get().struct_ops_callback_arg_index_by_name(
                value_type_name,
                callback_name,
                arg_name
            ),
            Ok(Some(idx)) if idx == expected_idx as usize
        ) {
            return Some((
                value_type_name.to_string(),
                callback_name.to_string(),
                arg_name.to_string(),
                expected_idx,
            ));
        }
    }
    None
}

pub(super) fn find_tp_btf_named_arg_candidate() -> Option<(String, String, u8)> {
    for (tracepoint_name, arg_name) in [
        ("sys_enter", "regs"),
        ("sys_enter", "id"),
        ("sys_exit", "regs"),
        ("sys_exit", "ret"),
        ("sched_process_fork", "parent"),
        ("sched_process_fork", "child"),
        ("sched_process_exec", "bprm"),
    ] {
        if let Ok(Some(idx)) = KernelBtf::get().tp_btf_arg_index_by_name(tracepoint_name, arg_name)
        {
            if let Ok(idx) = u8::try_from(idx) {
                return Some((tracepoint_name.to_string(), arg_name.to_string(), idx));
            }
        }
    }
    None
}

pub(super) fn find_tp_btf_named_pointer_projection_candidate() -> Option<(String, String, String)> {
    for (tracepoint_name, arg_name, field_name) in [
        ("sys_enter", "regs", "orig_ax"),
        ("sys_exit", "regs", "orig_ax"),
    ] {
        let path = [TrampolineFieldSelector::Field(field_name.to_string())];
        if let Ok(Some(arg_idx)) =
            KernelBtf::get().tp_btf_arg_index_by_name(tracepoint_name, arg_name)
            && matches!(
                KernelBtf::get().tp_btf_arg_field(tracepoint_name, arg_idx, &path),
                Ok(Some(_))
            )
        {
            return Some((
                tracepoint_name.to_string(),
                arg_name.to_string(),
                field_name.to_string(),
            ));
        }
    }
    None
}

pub(super) fn find_function_trampoline_named_arg_candidate() -> Option<(String, String, u8)> {
    for (function_name, arg_name, expected_idx) in [
        ("security_file_open", "file", 0u8),
        ("do_close_on_exec", "files", 0),
    ] {
        if matches!(
            KernelBtf::get().function_trampoline_arg_index_by_name(function_name, arg_name),
            Ok(Some(idx)) if idx == expected_idx as usize
        ) {
            return Some((
                function_name.to_string(),
                arg_name.to_string(),
                expected_idx,
            ));
        }
    }
    None
}

pub(super) fn find_lsm_named_arg_candidate() -> Option<(String, String, u8)> {
    for (hook_name, arg_name, expected_idx) in [("file_open", "file", 0u8)] {
        if matches!(
            KernelBtf::get().lsm_hook_arg_index_by_name(hook_name, arg_name),
            Ok(Some(idx)) if idx == expected_idx as usize
        ) {
            return Some((hook_name.to_string(), arg_name.to_string(), expected_idx));
        }
    }
    None
}

pub(super) fn find_struct_ops_named_pointer_projection_candidate()
-> Option<(String, String, String, String)> {
    for (value_type_name, callback_name, arg_name, arg_idx, field_name) in
        [("sched_ext_ops", "select_cpu", "p", 0usize, "pid")]
    {
        let path = [TrampolineFieldSelector::Field(field_name.to_string())];
        if matches!(
            KernelBtf::get().struct_ops_callback_arg_index_by_name(
                value_type_name,
                callback_name,
                arg_name
            ),
            Ok(Some(idx)) if idx == arg_idx
        ) && matches!(
            KernelBtf::get().struct_ops_callback_arg_field(
                value_type_name,
                callback_name,
                arg_idx,
                &path,
            ),
            Ok(Some(_))
        ) {
            return Some((
                value_type_name.to_string(),
                callback_name.to_string(),
                arg_name.to_string(),
                field_name.to_string(),
            ));
        }
    }
    None
}

pub(super) fn make_map_put_get_projection_program(
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

pub(super) fn make_map_get_projection_program(
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

pub(super) fn make_map_get_whole_value_program(
    map_get_decl: DeclId,
    terminal_decl: DeclId,
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

pub(super) fn make_map_take_whole_value_program(
    map_take_decl: DeclId,
    terminal_decl: DeclId,
    kind: &str,
) -> HirProgram {
    let lookup_var = VarId::new(1);
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
                        lit: HirLiteral::String(b"recent_paths".to_vec()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String(kind.as_bytes().to_vec()),
                    },
                    HirStmt::Call {
                        decl_id: map_take_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(1)],
                            named: vec![(b"kind".to_vec(), RegId::new(2))],
                            ..Default::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(3),
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
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

pub(super) fn make_map_get_record_emit_program(
    map_get_decl: DeclId,
    emit_decl: DeclId,
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

pub(super) fn make_map_put_program(map_put_decl: DeclId, flags: i64, kind: &str) -> HirProgram {
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

pub(super) fn make_map_push_program(map_push_decl: DeclId, flags: i64, kind: &str) -> HirProgram {
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
                    lit: HirLiteral::String(b"recent_pids".to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String(kind.as_bytes().to_vec()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(flags),
                },
                HirStmt::Call {
                    decl_id: map_push_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        named: vec![
                            (b"kind".to_vec(), RegId::new(3)),
                            (b"flags".to_vec(), RegId::new(4)),
                        ],
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 8],
        ast: vec![None; 8],
        comments: vec![],
        register_count: 5,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

pub(super) fn make_map_peek_program(
    map_push_decl: Option<DeclId>,
    map_peek_decl: DeclId,
    kind: &str,
) -> HirProgram {
    make_map_take_program(map_push_decl, map_peek_decl, kind)
}

pub(super) fn make_map_pop_program(
    map_push_decl: Option<DeclId>,
    map_pop_decl: DeclId,
    kind: &str,
) -> HirProgram {
    make_map_take_program(map_push_decl, map_pop_decl, kind)
}

fn make_map_take_program(
    map_push_decl: Option<DeclId>,
    map_take_decl: DeclId,
    kind: &str,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let seeded = map_push_decl.is_some();
    let mut stmts = vec![
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
            lit: HirLiteral::String(b"recent_pids".to_vec()),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(3),
            lit: HirLiteral::String(kind.as_bytes().to_vec()),
        },
    ];

    if let Some(map_push_decl) = map_push_decl {
        stmts.push(HirStmt::LoadLiteral {
            dst: RegId::new(4),
            lit: HirLiteral::Int(0),
        });
        stmts.push(HirStmt::Call {
            decl_id: map_push_decl,
            src_dst: RegId::new(0),
            args: HirCallArgs {
                positional: vec![RegId::new(2)],
                named: vec![
                    (b"kind".to_vec(), RegId::new(3)),
                    (b"flags".to_vec(), RegId::new(4)),
                ],
                ..Default::default()
            },
        });
    }

    stmts.push(HirStmt::Call {
        decl_id: map_take_decl,
        src_dst: RegId::new(0),
        args: HirCallArgs {
            positional: vec![RegId::new(2)],
            named: vec![(b"kind".to_vec(), RegId::new(3))],
            ..Default::default()
        },
    });

    let spans_len = stmts.len().max(1) + 1;
    let register_count = if seeded { 5 } else { 4 };
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); spans_len],
        ast: vec![None; spans_len],
        comments: vec![],
        register_count,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

pub(super) fn make_map_copy_projection_program(
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

pub(super) fn make_map_delete_program(map_delete_decl: DeclId, kind: &str) -> HirProgram {
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

pub(super) fn make_captured_map_delete_program(
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

pub(super) fn make_chained_ctx_path_program(paths: Vec<CellPath>) -> HirProgram {
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

pub(super) fn make_bound_ctx_path_program(binding: CellPath, access: CellPath) -> HirProgram {
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

pub(super) fn make_bound_ctx_get_program(
    binding: CellPath,
    access: CellPath,
    decl_id: DeclId,
) -> HirProgram {
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

pub(super) fn make_bound_ctx_runtime_get_program(
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

pub(super) fn make_bound_ctx_runtime_get_path_program(
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

pub(super) fn make_range_iterate_program(start: i64, step: HirLiteral, end: i64) -> HirProgram {
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
