use super::*;
use crate::compiler::hir::{
    HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
};
use crate::compiler::mir::AddressSpace;
use crate::compiler::passes::optimize_with_ssa_hints;
use crate::compiler::{EbpfProgramType, compile_mir_to_ebpf_with_hints};
use nu_protocol::ast::{CellPath, Comparison, Operator, PathMember, RangeInclusion};
use nu_protocol::casing::Casing;
use nu_protocol::{DeclId, IN_VARIABLE_ID, Record, RegId, Span, Value, VarId};
use std::collections::HashMap;

fn string_member(name: &str) -> PathMember {
    PathMember::test_string(name.to_string(), false, Casing::Sensitive)
}

fn make_numeric_list_pipeline_call_program(decl_id: DeclId, count: Option<i64>) -> HirProgram {
    let mut stmts = vec![HirStmt::LoadValue {
        dst: RegId::new(0),
        val: Box::new(Value::list(
            vec![
                Value::int(10, Span::test_data()),
                Value::int(20, Span::test_data()),
                Value::int(30, Span::test_data()),
            ],
            Span::test_data(),
        )),
    }];
    let positional = if let Some(count) = count {
        stmts.push(HirStmt::LoadLiteral {
            dst: RegId::new(2),
            lit: HirLiteral::Int(count),
        });
        vec![RegId::new(2)]
    } else {
        Vec::new()
    };

    stmts.push(HirStmt::Call {
        decl_id,
        src_dst: RegId::new(1),
        args: HirCallArgs {
            positional,
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
            terminator: HirTerminator::Return { src: RegId::new(1) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_empty_numeric_list_pipeline_call_program(decl_id: DeclId) -> HirProgram {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::list(Vec::new(), Span::test_data())),
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
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
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_numeric_list_call_then_get_program(
    command_decl: DeclId,
    get_decl: DeclId,
    count: Option<i64>,
    get_index: i64,
) -> HirProgram {
    let mut stmts = vec![HirStmt::LoadValue {
        dst: RegId::new(0),
        val: Box::new(Value::list(
            vec![
                Value::int(10, Span::test_data()),
                Value::int(20, Span::test_data()),
                Value::int(30, Span::test_data()),
            ],
            Span::test_data(),
        )),
    }];
    let command_positional = if let Some(count) = count {
        stmts.push(HirStmt::LoadLiteral {
            dst: RegId::new(2),
            lit: HirLiteral::Int(count),
        });
        vec![RegId::new(2)]
    } else {
        Vec::new()
    };
    stmts.push(HirStmt::Call {
        decl_id: command_decl,
        src_dst: RegId::new(1),
        args: HirCallArgs {
            positional: command_positional,
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });
    stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(3),
        lit: HirLiteral::Int(get_index),
    });
    stmts.push(HirStmt::Call {
        decl_id: get_decl,
        src_dst: RegId::new(4),
        args: HirCallArgs {
            positional: vec![RegId::new(3)],
            pipeline_input: Some(RegId::new(1)),
            ..HirCallArgs::default()
        },
    });

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
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

fn make_numeric_list_call_then_length_program(
    command_decl: DeclId,
    length_decl: DeclId,
    count: Option<i64>,
) -> HirProgram {
    let mut stmts = vec![HirStmt::LoadValue {
        dst: RegId::new(0),
        val: Box::new(Value::list(
            vec![
                Value::int(10, Span::test_data()),
                Value::int(20, Span::test_data()),
                Value::int(30, Span::test_data()),
            ],
            Span::test_data(),
        )),
    }];
    let command_positional = if let Some(count) = count {
        stmts.push(HirStmt::LoadLiteral {
            dst: RegId::new(2),
            lit: HirLiteral::Int(count),
        });
        vec![RegId::new(2)]
    } else {
        Vec::new()
    };
    stmts.push(HirStmt::Call {
        decl_id: command_decl,
        src_dst: RegId::new(1),
        args: HirCallArgs {
            positional: command_positional,
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });
    stmts.push(HirStmt::Call {
        decl_id: length_decl,
        src_dst: RegId::new(3),
        args: HirCallArgs {
            pipeline_input: Some(RegId::new(1)),
            ..HirCallArgs::default()
        },
    });

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_numeric_list_get_program(get_decl: DeclId, get_index: i64) -> HirProgram {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::list(
                        vec![
                            Value::int(10, Span::test_data()),
                            Value::int(20, Span::test_data()),
                            Value::int(30, Span::test_data()),
                        ],
                        Span::test_data(),
                    )),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(get_index),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(2) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_numeric_list_item_call_then_get_program(
    command_decl: DeclId,
    get_decl: DeclId,
    item: i64,
    get_index: i64,
) -> HirProgram {
    let mut stmts = vec![HirStmt::LoadValue {
        dst: RegId::new(0),
        val: Box::new(Value::list(
            vec![
                Value::int(10, Span::test_data()),
                Value::int(20, Span::test_data()),
                Value::int(30, Span::test_data()),
            ],
            Span::test_data(),
        )),
    }];
    stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(2),
        lit: HirLiteral::Int(item),
    });
    stmts.push(HirStmt::Call {
        decl_id: command_decl,
        src_dst: RegId::new(1),
        args: HirCallArgs {
            positional: vec![RegId::new(2)],
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });
    stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(3),
        lit: HirLiteral::Int(get_index),
    });
    stmts.push(HirStmt::Call {
        decl_id: get_decl,
        src_dst: RegId::new(4),
        args: HirCallArgs {
            positional: vec![RegId::new(3)],
            pipeline_input: Some(RegId::new(1)),
            ..HirCallArgs::default()
        },
    });

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
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

fn make_numeric_list_predicate_call_program(
    command_decl: DeclId,
    command_name: &str,
    values: &[i64],
    threshold: i64,
) -> (HirProgram, HashMap<DeclId, String>) {
    let closure_block_id = nu_protocol::BlockId::new(1);
    let list_values = values
        .iter()
        .map(|value| Value::int(*value, Span::test_data()))
        .collect::<Vec<_>>();
    let main = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::list(list_values, Span::test_data())),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Closure(closure_block_id),
                },
                HirStmt::Call {
                    decl_id: command_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(1) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 3,
        file_count: 0,
    };
    let closure = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: IN_VARIABLE_ID,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(threshold),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Comparison(Comparison::GreaterThan),
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
    };
    (
        HirProgram::new(
            main,
            HashMap::from([(closure_block_id, closure)]),
            Vec::new(),
            None,
        ),
        HashMap::from([(command_decl, command_name.to_string())]),
    )
}

fn make_numeric_list_in_place_predicate_call_program(
    command_decl: DeclId,
    command_name: &str,
    threshold: i64,
) -> (HirProgram, HashMap<DeclId, String>) {
    let closure_block_id = nu_protocol::BlockId::new(1);
    let main = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::List { capacity: 3 },
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
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(20),
                },
                HirStmt::ListPush {
                    src_dst: RegId::new(0),
                    item: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(30),
                },
                HirStmt::ListPush {
                    src_dst: RegId::new(0),
                    item: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Closure(closure_block_id),
                },
                HirStmt::Call {
                    decl_id: command_decl,
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
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: VarId::new(80),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(threshold),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Comparison(Comparison::GreaterThan),
                    rhs: RegId::new(1),
                },
                HirStmt::Span {
                    src_dst: RegId::new(0),
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
    (
        HirProgram::new(
            main,
            HashMap::from([(closure_block_id, closure)]),
            Vec::new(),
            None,
        ),
        HashMap::from([(command_decl, command_name.to_string())]),
    )
}

fn make_string_pipeline_call_program(decl_id: DeclId, value: &str) -> HirProgram {
    make_string_pipeline_call_program_with_flags(decl_id, value, Vec::new())
}

fn make_string_pipeline_call_program_with_flags(
    decl_id: DeclId,
    value: &str,
    flags: Vec<Vec<u8>>,
) -> HirProgram {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::string(value, Span::test_data())),
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(0)),
                        flags,
                        ..HirCallArgs::default()
                    },
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
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_string_arg_pipeline_call_program(decl_id: DeclId, value: &str, arg: &str) -> HirProgram {
    make_string_arg_pipeline_call_program_with_flags(decl_id, value, arg, Vec::new())
}

fn make_string_arg_pipeline_call_program_with_flags(
    decl_id: DeclId,
    value: &str,
    arg: &str,
    flags: Vec<Vec<u8>>,
) -> HirProgram {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::string(value, Span::test_data())),
                },
                HirStmt::LoadValue {
                    dst: RegId::new(2),
                    val: Box::new(Value::string(arg, Span::test_data())),
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        pipeline_input: Some(RegId::new(0)),
                        flags,
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(1) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_string_index_of_range_program(
    decl_id: DeclId,
    value: &str,
    needle: &str,
    start: Option<i64>,
    end: Option<i64>,
    inclusion: RangeInclusion,
    flags: Vec<Vec<u8>>,
) -> HirProgram {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::string(value, Span::test_data())),
                },
                HirStmt::LoadValue {
                    dst: RegId::new(2),
                    val: Box::new(Value::string(needle, Span::test_data())),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: start.map_or(HirLiteral::Nothing, HirLiteral::Int),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: end.map_or(HirLiteral::Nothing, HirLiteral::Int),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Range {
                        start: RegId::new(3),
                        step: RegId::new(4),
                        end: RegId::new(5),
                        inclusion,
                    },
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        named: vec![(b"range".to_vec(), RegId::new(6))],
                        pipeline_input: Some(RegId::new(0)),
                        flags,
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(1) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 7,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_str_replace_then_starts_with_program(
    replace_decl: DeclId,
    starts_with_decl: DeclId,
    value: &str,
    find: &str,
    replacement: &str,
    prefix: &str,
    flags: Vec<Vec<u8>>,
) -> HirProgram {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::string(value, Span::test_data())),
                },
                HirStmt::LoadValue {
                    dst: RegId::new(2),
                    val: Box::new(Value::string(find, Span::test_data())),
                },
                HirStmt::LoadValue {
                    dst: RegId::new(3),
                    val: Box::new(Value::string(replacement, Span::test_data())),
                },
                HirStmt::Call {
                    decl_id: replace_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2), RegId::new(3)],
                        pipeline_input: Some(RegId::new(0)),
                        flags,
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadValue {
                    dst: RegId::new(4),
                    val: Box::new(Value::string(prefix, Span::test_data())),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(1)),
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(5) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 6,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_string_command_then_starts_with_program(
    command_decl: DeclId,
    starts_with_decl: DeclId,
    value: &str,
    prefix: &str,
) -> HirProgram {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::string(value, Span::test_data())),
                },
                HirStmt::Call {
                    decl_id: command_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadValue {
                    dst: RegId::new(2),
                    val: Box::new(Value::string(prefix, Span::test_data())),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        pipeline_input: Some(RegId::new(1)),
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_str_trim_then_starts_with_program(
    trim_decl: DeclId,
    starts_with_decl: DeclId,
    value: &str,
    prefix: &str,
    flags: Vec<Vec<u8>>,
    trim_char: Option<&str>,
) -> HirProgram {
    let mut stmts = vec![HirStmt::LoadValue {
        dst: RegId::new(0),
        val: Box::new(Value::string(value, Span::test_data())),
    }];
    let named = if let Some(trim_char) = trim_char {
        stmts.push(HirStmt::LoadValue {
            dst: RegId::new(2),
            val: Box::new(Value::string(trim_char, Span::test_data())),
        });
        vec![(b"char".to_vec(), RegId::new(2))]
    } else {
        Vec::new()
    };

    stmts.push(HirStmt::Call {
        decl_id: trim_decl,
        src_dst: RegId::new(1),
        args: HirCallArgs {
            named,
            flags,
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });
    stmts.push(HirStmt::LoadValue {
        dst: RegId::new(3),
        val: Box::new(Value::string(prefix, Span::test_data())),
    });
    stmts.push(HirStmt::Call {
        decl_id: starts_with_decl,
        src_dst: RegId::new(4),
        args: HirCallArgs {
            positional: vec![RegId::new(3)],
            pipeline_input: Some(RegId::new(1)),
            ..HirCallArgs::default()
        },
    });

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
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

fn make_string_substring_then_starts_with_program(
    substring_decl: DeclId,
    starts_with_decl: DeclId,
    value: &str,
    start: i64,
    end: i64,
    inclusion: RangeInclusion,
    prefix: &str,
    flags: Vec<Vec<u8>>,
) -> HirProgram {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::string(value, Span::test_data())),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(start),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(end),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Range {
                        start: RegId::new(2),
                        step: RegId::new(3),
                        end: RegId::new(4),
                        inclusion,
                    },
                },
                HirStmt::Call {
                    decl_id: substring_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5)],
                        pipeline_input: Some(RegId::new(0)),
                        flags,
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadValue {
                    dst: RegId::new(6),
                    val: Box::new(Value::string(prefix, Span::test_data())),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        positional: vec![RegId::new(6)],
                        pipeline_input: Some(RegId::new(1)),
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(7) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 8,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_record_projection_then_field_program(
    command_decl: DeclId,
    fields: &[&str],
    field_args_as_cell_paths: bool,
    return_field: &str,
) -> HirProgram {
    let mut rec = Record::new();
    rec.push("pid", Value::int(7, Span::test_data()));
    rec.push("cpu", Value::int(2, Span::test_data()));
    rec.push("ok", Value::bool(true, Span::test_data()));

    let mut stmts = vec![HirStmt::LoadValue {
        dst: RegId::new(0),
        val: Box::new(Value::record(rec, Span::test_data())),
    }];
    let mut positional = Vec::new();
    for (idx, field) in fields.iter().enumerate() {
        let reg = RegId::new((idx + 2) as u32);
        let lit = if field_args_as_cell_paths {
            HirLiteral::CellPath(Box::new(CellPath {
                members: vec![string_member(field)],
            }))
        } else {
            HirLiteral::String(field.as_bytes().to_vec())
        };
        stmts.push(HirStmt::LoadLiteral { dst: reg, lit });
        positional.push(reg);
    }

    stmts.push(HirStmt::Call {
        decl_id: command_decl,
        src_dst: RegId::new(1),
        args: HirCallArgs {
            positional,
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });

    let path_reg = RegId::new((fields.len() + 2) as u32);
    stmts.push(HirStmt::LoadLiteral {
        dst: path_reg,
        lit: HirLiteral::CellPath(Box::new(CellPath {
            members: vec![string_member(return_field)],
        })),
    });
    stmts.push(HirStmt::FollowCellPath {
        src_dst: RegId::new(1),
        path: path_reg,
    });

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
            terminator: HirTerminator::Return { src: RegId::new(1) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: (fields.len() + 3) as u32,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_record_set_then_field_program(
    command_decl: DeclId,
    field: &str,
    value: i64,
    return_field: &str,
) -> HirProgram {
    let mut rec = Record::new();
    rec.push("pid", Value::int(7, Span::test_data()));
    rec.push("cpu", Value::int(2, Span::test_data()));

    let field_reg = RegId::new(2);
    let value_reg = RegId::new(3);
    let path_reg = RegId::new(4);
    let mut stmts = vec![
        HirStmt::LoadValue {
            dst: RegId::new(0),
            val: Box::new(Value::record(rec, Span::test_data())),
        },
        HirStmt::LoadLiteral {
            dst: field_reg,
            lit: HirLiteral::CellPath(Box::new(CellPath {
                members: vec![string_member(field)],
            })),
        },
        HirStmt::LoadLiteral {
            dst: value_reg,
            lit: HirLiteral::Int(value),
        },
        HirStmt::Call {
            decl_id: command_decl,
            src_dst: RegId::new(1),
            args: HirCallArgs {
                positional: vec![field_reg, value_reg],
                pipeline_input: Some(RegId::new(0)),
                ..HirCallArgs::default()
            },
        },
    ];
    stmts.push(HirStmt::LoadLiteral {
        dst: path_reg,
        lit: HirLiteral::CellPath(Box::new(CellPath {
            members: vec![string_member(return_field)],
        })),
    });
    stmts.push(HirStmt::FollowCellPath {
        src_dst: RegId::new(1),
        path: path_reg,
    });

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
            terminator: HirTerminator::Return { src: RegId::new(1) },
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

fn make_record_merge_then_field_program(
    command_decl: DeclId,
    merge_fields: &[(&str, i64)],
    return_field: &str,
) -> HirProgram {
    let mut input = Record::new();
    input.push("pid", Value::int(7, Span::test_data()));
    input.push("cpu", Value::int(2, Span::test_data()));

    let mut merge = Record::new();
    for (name, value) in merge_fields {
        merge.push(*name, Value::int(*value, Span::test_data()));
    }

    let path_reg = RegId::new(3);
    let stmts = vec![
        HirStmt::LoadValue {
            dst: RegId::new(0),
            val: Box::new(Value::record(input, Span::test_data())),
        },
        HirStmt::LoadValue {
            dst: RegId::new(2),
            val: Box::new(Value::record(merge, Span::test_data())),
        },
        HirStmt::Call {
            decl_id: command_decl,
            src_dst: RegId::new(1),
            args: HirCallArgs {
                positional: vec![RegId::new(2)],
                pipeline_input: Some(RegId::new(0)),
                ..HirCallArgs::default()
            },
        },
        HirStmt::LoadLiteral {
            dst: path_reg,
            lit: HirLiteral::CellPath(Box::new(CellPath {
                members: vec![string_member(return_field)],
            })),
        },
        HirStmt::FollowCellPath {
            src_dst: RegId::new(1),
            path: path_reg,
        },
    ];

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
            terminator: HirTerminator::Return { src: RegId::new(1) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_record_get_field_program(get_decl: DeclId, field: &str) -> HirProgram {
    let mut record = Record::new();
    record.push("pid", Value::int(7, Span::test_data()));
    record.push("cpu", Value::int(2, Span::test_data()));

    let stmts = vec![
        HirStmt::LoadValue {
            dst: RegId::new(0),
            val: Box::new(Value::record(record, Span::test_data())),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(1),
            lit: HirLiteral::CellPath(Box::new(CellPath {
                members: vec![string_member(field)],
            })),
        },
        HirStmt::Call {
            decl_id: get_decl,
            src_dst: RegId::new(2),
            args: HirCallArgs {
                positional: vec![RegId::new(1)],
                pipeline_input: Some(RegId::new(0)),
                ..HirCallArgs::default()
            },
        },
    ];

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
            terminator: HirTerminator::Return { src: RegId::new(2) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 3,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_record_get_nested_list_item_program(get_decl: DeclId) -> HirProgram {
    let stmts = vec![
        HirStmt::LoadLiteral {
            dst: RegId::new(0),
            lit: HirLiteral::Record { capacity: 0 },
        },
        HirStmt::LoadValue {
            dst: RegId::new(1),
            val: Box::new(Value::list(
                vec![
                    Value::int(11, Span::test_data()),
                    Value::int(22, Span::test_data()),
                ],
                Span::test_data(),
            )),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(2),
            lit: HirLiteral::CellPath(Box::new(CellPath {
                members: vec![string_member("samples")],
            })),
        },
        HirStmt::UpsertCellPath {
            src_dst: RegId::new(0),
            path: RegId::new(2),
            new_value: RegId::new(1),
        },
        HirStmt::Call {
            decl_id: get_decl,
            src_dst: RegId::new(3),
            args: HirCallArgs {
                positional: vec![RegId::new(2)],
                pipeline_input: Some(RegId::new(0)),
                ..HirCallArgs::default()
            },
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(4),
            lit: HirLiteral::Int(1),
        },
        HirStmt::Call {
            decl_id: get_decl,
            src_dst: RegId::new(5),
            args: HirCallArgs {
                positional: vec![RegId::new(4)],
                pipeline_input: Some(RegId::new(3)),
                ..HirCallArgs::default()
            },
        },
    ];

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
            terminator: HirTerminator::Return { src: RegId::new(5) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 6,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_record_values_then_get_program(
    values_decl: DeclId,
    get_decl: DeclId,
    include_bool_field: bool,
    get_index: i64,
) -> HirProgram {
    let mut record = Record::new();
    record.push("pid", Value::int(7, Span::test_data()));
    record.push("cpu", Value::int(2, Span::test_data()));
    if include_bool_field {
        record.push("ok", Value::bool(true, Span::test_data()));
    }

    let stmts = vec![
        HirStmt::LoadValue {
            dst: RegId::new(0),
            val: Box::new(Value::record(record, Span::test_data())),
        },
        HirStmt::Call {
            decl_id: values_decl,
            src_dst: RegId::new(1),
            args: HirCallArgs {
                pipeline_input: Some(RegId::new(0)),
                ..HirCallArgs::default()
            },
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(2),
            lit: HirLiteral::Int(get_index),
        },
        HirStmt::Call {
            decl_id: get_decl,
            src_dst: RegId::new(3),
            args: HirCallArgs {
                positional: vec![RegId::new(2)],
                pipeline_input: Some(RegId::new(1)),
                ..HirCallArgs::default()
            },
        },
    ];

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], None)
}

fn make_record_empty_predicate_program(
    decl_id: DeclId,
    command_name: &str,
    empty_record: bool,
) -> (HirProgram, HashMap<DeclId, String>) {
    let mut record = Record::new();
    if !empty_record {
        record.push("pid", Value::int(7, Span::test_data()));
    }

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::record(record, Span::test_data())),
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
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
    (
        HirProgram::new(func, HashMap::new(), vec![], None),
        HashMap::from([(decl_id, command_name.to_string())]),
    )
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
fn test_lower_first_on_numeric_list_gets_first_element() {
    let first_decl = DeclId::new(78);
    let hir = make_numeric_list_pipeline_call_program(first_decl, None);
    let decl_names = HashMap::from([(first_decl, "first".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("first should lower on stack-backed numeric lists");

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
                    idx: MirValue::Const(0),
                    ..
                }
            )),
        "expected first to lower through ListGet at index 0"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("first on stack-backed numeric list should compile through codegen");
}

#[test]
fn test_lower_last_on_numeric_list_gets_length_minus_one() {
    let last_decl = DeclId::new(79);
    let hir = make_numeric_list_pipeline_call_program(last_decl, None);
    let decl_names = HashMap::from([(last_decl, "last".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("last should lower on stack-backed numeric lists");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListLen { .. })),
        "expected last to compute the list length"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Sub,
                rhs: MirValue::Const(1),
                ..
            }
        )),
        "expected last to subtract one from the list length"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::ListGet {
                idx: MirValue::VReg(_),
                ..
            }
        )),
        "expected last to lower through dynamic ListGet"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("last on stack-backed numeric list should compile through codegen");
}

#[test]
fn test_lower_first_on_empty_numeric_list_is_rejected() {
    let first_decl = DeclId::new(86);
    let hir = make_empty_numeric_list_pipeline_call_program(first_decl);
    let decl_names = HashMap::from([(first_decl, "first".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("scalar first on an empty list should be rejected");

    assert!(
        err.to_string()
            .contains("first requires a non-empty stack-backed numeric list"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_last_on_empty_numeric_list_is_rejected() {
    let last_decl = DeclId::new(87);
    let hir = make_empty_numeric_list_pipeline_call_program(last_decl);
    let decl_names = HashMap::from([(last_decl, "last".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("scalar last on an empty list should be rejected");

    assert!(
        err.to_string()
            .contains("last requires a non-empty stack-backed numeric list"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_first_count_on_numeric_list_rebuilds_prefix() {
    let first_decl = DeclId::new(80);
    let get_decl = DeclId::new(81);
    let hir = make_numeric_list_call_then_get_program(first_decl, get_decl, Some(2), 1);
    let decl_names = HashMap::from([
        (first_decl, "first".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("counted first should lower as a bounded stack-list prefix slice");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions
            .iter()
            .filter(|inst| matches!(inst, MirInst::ListPush { .. }))
            .count()
            >= 2,
        "expected counted first to rebuild the requested prefix"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("counted first should compile through codegen");
}

#[test]
fn test_lower_last_count_on_numeric_list_rebuilds_suffix() {
    let last_decl = DeclId::new(82);
    let get_decl = DeclId::new(83);
    let hir = make_numeric_list_call_then_get_program(last_decl, get_decl, Some(2), 0);
    let decl_names = HashMap::from([
        (last_decl, "last".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("counted last should lower as a bounded stack-list suffix slice");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::ListGet {
                idx: MirValue::Const(2),
                ..
            }
        )),
        "expected counted last to inspect the original tail slot"
    );
    assert!(
        instructions
            .iter()
            .filter(|inst| matches!(inst, MirInst::ListPush { .. }))
            .count()
            >= 2,
        "expected counted last to rebuild the suffix through bounded list pushes"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("counted last should compile through codegen");
}

#[test]
fn test_lower_first_negative_count_is_rejected() {
    let first_decl = DeclId::new(84);
    let hir = make_numeric_list_pipeline_call_program(first_decl, Some(-1));
    let decl_names = HashMap::from([(first_decl, "first".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("negative first count should be rejected");

    assert!(
        err.to_string().contains("first count must be non-negative"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_last_negative_count_is_rejected() {
    let last_decl = DeclId::new(85);
    let hir = make_numeric_list_pipeline_call_program(last_decl, Some(-1));
    let decl_names = HashMap::from([(last_decl, "last".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("negative last count should be rejected");

    assert!(
        err.to_string().contains("last count must be non-negative"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_get_negative_index_on_numeric_list_is_rejected() {
    let get_decl = DeclId::new(86);
    let hir = make_numeric_list_get_program(get_decl, -1);
    let decl_names = HashMap::from([(get_decl, "get".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("negative get index should be rejected for stack-backed numeric lists");

    assert!(
        err.to_string().contains("get index must be non-negative"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_get_out_of_bounds_index_on_numeric_list_is_rejected() {
    let get_decl = DeclId::new(87);
    let hir = make_numeric_list_get_program(get_decl, 3);
    let decl_names = HashMap::from([(get_decl, "get".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("known out-of-bounds get should be rejected for stack-backed numeric lists");

    assert!(
        err.to_string()
            .contains("get index 3 is out of bounds for stack-backed numeric list"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_skip_default_on_numeric_list_rebuilds_tail() {
    let skip_decl = DeclId::new(81);
    let get_decl = DeclId::new(82);
    let hir = make_numeric_list_call_then_get_program(skip_decl, get_decl, None, 0);
    let decl_names = HashMap::from([
        (skip_decl, "skip".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bare skip should lower as skip 1 on stack-backed numeric lists");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListNew { max_len: 2, .. })),
        "expected skip to allocate a two-element tail list"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::ListGet {
                idx: MirValue::Const(1),
                ..
            }
        )),
        "expected skip to copy the original element at index 1"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::ListGet {
                idx: MirValue::Const(2),
                ..
            }
        )),
        "expected skip to copy the original element at index 2"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("skip tail followed by get should compile through codegen");
}

#[test]
fn test_lower_skip_count_beyond_numeric_list_capacity_returns_empty_list() {
    let skip_decl = DeclId::new(83);
    let length_decl = DeclId::new(84);
    let hir = make_numeric_list_call_then_length_program(skip_decl, length_decl, Some(4));
    let decl_names = HashMap::from([
        (skip_decl, "skip".to_string()),
        (length_decl, "length".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("oversized skip should lower to an empty stack-backed numeric list");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListNew { max_len: 0, .. })),
        "expected oversized skip to allocate an empty list"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("empty skip result followed by length should compile through codegen");
}

#[test]
fn test_lower_skip_negative_count_is_rejected() {
    let skip_decl = DeclId::new(85);
    let hir = make_numeric_list_pipeline_call_program(skip_decl, Some(-1));
    let decl_names = HashMap::from([(skip_decl, "skip".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("negative skip should be rejected rather than silently miscompiled");

    assert!(
        err.to_string().contains("skip count must be non-negative"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_take_count_on_numeric_list_rebuilds_prefix() {
    let take_decl = DeclId::new(86);
    let get_decl = DeclId::new(87);
    let hir = make_numeric_list_call_then_get_program(take_decl, get_decl, Some(2), 1);
    let decl_names = HashMap::from([
        (take_decl, "take".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("take count should lower to a bounded stack-backed numeric list");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListNew { max_len: 2, .. })),
        "expected take 2 to allocate a two-element prefix list"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::ListGet {
                idx: MirValue::Const(0),
                ..
            }
        )),
        "expected take to copy the original element at index 0"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::ListGet {
                idx: MirValue::Const(1),
                ..
            }
        )),
        "expected take to copy the original element at index 1"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("take prefix followed by get should compile through codegen");
}

#[test]
fn test_lower_take_count_beyond_numeric_list_capacity_caps_to_input_capacity() {
    let take_decl = DeclId::new(88);
    let get_decl = DeclId::new(89);
    let hir = make_numeric_list_call_then_get_program(take_decl, get_decl, Some(4), 2);
    let decl_names = HashMap::from([
        (take_decl, "take".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("oversized take should cap to the stack-backed numeric list capacity");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListNew { max_len: 3, .. })),
        "expected oversized take to allocate the original list capacity"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("oversized take followed by get should compile through codegen");
}

#[test]
fn test_lower_take_negative_count_is_rejected() {
    let take_decl = DeclId::new(90);
    let hir = make_numeric_list_pipeline_call_program(take_decl, Some(-1));
    let decl_names = HashMap::from([(take_decl, "take".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("negative take should be rejected rather than silently miscompiled");

    assert!(
        err.to_string().contains("take count must be non-negative"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_drop_default_on_numeric_list_rebuilds_prefix() {
    let drop_decl = DeclId::new(91);
    let get_decl = DeclId::new(92);
    let hir = make_numeric_list_call_then_get_program(drop_decl, get_decl, None, 1);
    let decl_names = HashMap::from([
        (drop_decl, "drop".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bare drop should lower as drop 1 on stack-backed numeric lists");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListNew { max_len: 2, .. })),
        "expected drop to allocate a two-element prefix list"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Lt,
                lhs: MirValue::Const(2),
                ..
            }
        )),
        "expected drop to guard the last copied source index by index + count < runtime length"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("drop prefix followed by get should compile through codegen");
}

#[test]
fn test_lower_drop_count_beyond_numeric_list_capacity_returns_empty_list() {
    let drop_decl = DeclId::new(93);
    let length_decl = DeclId::new(94);
    let hir = make_numeric_list_call_then_length_program(drop_decl, length_decl, Some(4));
    let decl_names = HashMap::from([
        (drop_decl, "drop".to_string()),
        (length_decl, "length".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("oversized drop should lower to an empty stack-backed numeric list");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListNew { max_len: 0, .. })),
        "expected oversized drop to allocate an empty list"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("empty drop result followed by length should compile through codegen");
}

#[test]
fn test_lower_drop_negative_count_is_rejected() {
    let drop_decl = DeclId::new(95);
    let hir = make_numeric_list_pipeline_call_program(drop_decl, Some(-1));
    let decl_names = HashMap::from([(drop_decl, "drop".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("negative drop should be rejected rather than silently miscompiled");

    assert!(
        err.to_string().contains("drop count must be non-negative"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_reverse_on_numeric_list_rebuilds_with_descending_constant_indexes() {
    let reverse_decl = DeclId::new(96);
    let get_decl = DeclId::new(97);
    let hir = make_numeric_list_call_then_get_program(reverse_decl, get_decl, None, 0);
    let decl_names = HashMap::from([
        (reverse_decl, "reverse".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("reverse should lower to a bounded stack-backed numeric list");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListNew { max_len: 3, .. })),
        "expected reverse to allocate a list with the original capacity"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::ListGet {
                idx: MirValue::Const(2),
                ..
            }
        )),
        "expected reverse to copy the original tail element first"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::ListGet {
                idx: MirValue::Const(0),
                ..
            }
        )),
        "expected reverse to copy the original head element last"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("reverse followed by get should compile through codegen");
}

#[test]
fn test_lower_append_on_numeric_list_rebuilds_with_extra_capacity() {
    let append_decl = DeclId::new(86);
    let get_decl = DeclId::new(87);
    let hir = make_numeric_list_item_call_then_get_program(append_decl, get_decl, 40, 3);
    let decl_names = HashMap::from([
        (append_decl, "append".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("append should lower on stack-backed numeric lists");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListNew { max_len: 4, .. })),
        "expected append to allocate a four-element result list"
    );
    assert!(
        instructions
            .iter()
            .filter(|inst| matches!(inst, MirInst::ListPush { .. }))
            .count()
            >= 4,
        "expected append to copy existing items and push the appended item"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("append followed by get should compile through codegen");
}

#[test]
fn test_lower_prepend_on_numeric_list_rebuilds_with_extra_capacity() {
    let prepend_decl = DeclId::new(88);
    let get_decl = DeclId::new(89);
    let hir = make_numeric_list_item_call_then_get_program(prepend_decl, get_decl, 5, 0);
    let decl_names = HashMap::from([
        (prepend_decl, "prepend".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("prepend should lower on stack-backed numeric lists");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListNew { max_len: 4, .. })),
        "expected prepend to allocate a four-element result list"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("prepend followed by get should compile through codegen");
}

#[test]
fn test_lower_each_on_numeric_list_guards_runtime_length() {
    let each_decl = DeclId::new(90);
    let get_decl = DeclId::new(91);
    let closure_block_id = nu_protocol::BlockId::new(1);

    let main = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::List { capacity: 3 },
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
                    lit: HirLiteral::Closure(closure_block_id),
                },
                HirStmt::Call {
                    decl_id: each_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(5) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 6,
        file_count: 0,
    };
    let closure = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadVariable {
                dst: RegId::new(0),
                var_id: IN_VARIABLE_ID,
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
        Vec::new(),
        None,
    );
    let decl_names = HashMap::from([
        (each_decl, "each".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("each should lower on stack-backed numeric lists");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListLen { .. })),
        "expected each to inspect the input list runtime length"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Lt,
                lhs: MirValue::Const(1),
                rhs: MirValue::VReg(_),
                ..
            }
        )),
        "expected each to guard capacity slots against the runtime length"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("each followed by get should compile through codegen");
}

#[test]
fn test_lower_where_on_numeric_list_filters_with_runtime_length_guard() {
    let where_decl = DeclId::new(102);
    let get_decl = DeclId::new(103);
    let closure_block_id = nu_protocol::BlockId::new(1);

    let main = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::List { capacity: 3 },
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
                    lit: HirLiteral::Closure(closure_block_id),
                },
                HirStmt::Call {
                    decl_id: where_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(5) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 6,
        file_count: 0,
    };
    let closure = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadLiteral {
                dst: RegId::new(0),
                lit: HirLiteral::Bool(true),
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
        Vec::new(),
        None,
    );
    let decl_names = HashMap::from([
        (where_decl, "where".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("where should filter stack-backed numeric lists");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListLen { .. })),
        "expected where to inspect the input list runtime length"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Lt,
                lhs: MirValue::Const(1),
                rhs: MirValue::VReg(_),
                ..
            }
        )),
        "expected where to guard capacity slots against the runtime length"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("where followed by get should compile through codegen");
}

#[test]
fn test_lower_any_on_numeric_list_short_circuits_to_true() {
    let any_decl = DeclId::new(117);
    let (hir, decl_names) =
        make_numeric_list_predicate_call_program(any_decl, "any", &[10, 20, 30], 15);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("any should lower on stack-backed numeric lists");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListLen { .. })),
        "expected any to inspect the input list runtime length"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Gt,
                ..
            }
        )),
        "expected any to inline the closure predicate"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::Copy {
                src: MirValue::Const(1),
                ..
            }
        )),
        "expected any to assign true in the short-circuit path"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("any should compile through codegen");
}

#[test]
fn test_lower_any_on_in_place_numeric_list_writes_fresh_scalar_result() {
    let any_decl = DeclId::new(120);
    let (hir, decl_names) = make_numeric_list_in_place_predicate_call_program(any_decl, "any", 15);

    let hir_types = crate::compiler::hir_type_infer::infer_hir_types(&hir, &decl_names)
        .expect("source-like any HIR should type-check");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("any should lower when the source IR reuses the list register as src_dst");

    let return_vreg = result
        .program
        .main
        .blocks
        .iter()
        .find_map(|block| match block.terminator {
            MirInst::Return {
                val: Some(MirValue::VReg(vreg)),
            } => Some(vreg),
            _ => None,
        })
        .expect("expected scalar any result to be returned");
    assert_eq!(
        result.type_hints.main.get(&return_vreg),
        Some(&MirType::Bool),
        "expected in-place any lowering to return the fresh boolean result vreg"
    );
    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    compile_mir_to_ebpf_with_hints(&result.program, Some(&probe_ctx), Some(&result.type_hints))
        .expect("optimized in-place any should compile through codegen");
}

#[test]
fn test_lower_all_on_numeric_list_short_circuits_to_false() {
    let all_decl = DeclId::new(118);
    let (hir, decl_names) =
        make_numeric_list_predicate_call_program(all_decl, "all", &[10, 20, 30], 15);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("all should lower on stack-backed numeric lists");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions
            .iter()
            .filter(|inst| matches!(inst, MirInst::ListGet { .. }))
            .count()
            >= 3,
        "expected all to unroll capacity slots with constant-index reads"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::Copy {
                src: MirValue::Const(0),
                ..
            }
        )),
        "expected all to assign false in the short-circuit path"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("all should compile through codegen");
}

#[test]
fn test_lower_all_on_empty_numeric_list_uses_true_identity() {
    let all_decl = DeclId::new(119);
    let (hir, decl_names) = make_numeric_list_predicate_call_program(all_decl, "all", &[], 0);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("all should lower on empty stack-backed numeric lists");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::Copy {
                src: MirValue::Const(1),
                ..
            }
        )),
        "expected all over an empty list to use true as the identity"
    );
    assert!(
        instructions
            .iter()
            .all(|inst| !matches!(inst, MirInst::ListGet { .. })),
        "expected empty all lowering not to read list elements"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("empty all should compile through codegen");
}

#[test]
fn test_lower_is_empty_on_numeric_list_compares_length_to_zero() {
    let is_empty_decl = DeclId::new(92);
    let hir = make_numeric_list_pipeline_call_program(is_empty_decl, None);
    let decl_names = HashMap::from([(is_empty_decl, "is-empty".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("is-empty should lower on stack-backed numeric lists");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListLen { .. })),
        "expected is-empty to inspect the list length"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Eq,
                rhs: MirValue::Const(0),
                ..
            }
        )),
        "expected is-empty to compare length to zero"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("is-empty on stack-backed numeric list should compile through codegen");
}

#[test]
fn test_lower_is_empty_on_string_compares_length_to_zero() {
    let is_empty_decl = DeclId::new(93);
    let hir = make_string_pipeline_call_program(is_empty_decl, "");
    let decl_names = HashMap::from([(is_empty_decl, "is-empty".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("is-empty should lower on tracked strings");

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
                    op: BinOpKind::Eq,
                    rhs: MirValue::Const(0),
                    ..
                }
            )),
        "expected is-empty to compare string length to zero"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("is-empty on tracked string should compile through codegen");
}

#[test]
fn test_lower_str_length_on_string_copies_tracked_length() {
    let str_length_decl = DeclId::new(117);
    let hir = make_string_pipeline_call_program(str_length_decl, "abc");
    let decl_names = HashMap::from([(str_length_decl, "str length".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str length should lower on tracked strings");

    let tracked_len = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::StringAppend { dst_len, .. } => Some(*dst_len),
            _ => None,
        })
        .expect("expected string literal lowering to track a length vreg");
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
                    src: MirValue::VReg(src),
                    ..
                } if *src == tracked_len
            )),
        "expected str length to copy the tracked string length"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str length on tracked string should compile through codegen");
}

#[test]
fn test_lower_str_length_grapheme_clusters_on_known_string_materializes_count() {
    let str_length_decl = DeclId::new(162);
    let hir = make_string_pipeline_call_program_with_flags(
        str_length_decl,
        "🇯🇵ほげ",
        vec![b"grapheme-clusters".to_vec()],
    );
    let decl_names = HashMap::from([(str_length_decl, "str length".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str length --grapheme-clusters should lower on compile-time known strings");

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
                    src: MirValue::Const(3),
                    ..
                }
            )),
        "expected str length --grapheme-clusters to materialize the grapheme count"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str length --grapheme-clusters should compile through codegen");
}

#[test]
fn test_lower_str_starts_with_on_string_uses_bounded_strcmp() {
    let starts_with_decl = DeclId::new(118);
    let hir = make_string_arg_pipeline_call_program(starts_with_decl, "abcdef", "abc");
    let decl_names = HashMap::from([(starts_with_decl, "str starts-with".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str starts-with should lower on tracked strings with literal prefixes");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { len: 3, .. })),
        "expected str starts-with to lower to a bounded prefix StrCmp"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str starts-with on tracked strings should compile through codegen");
}

#[test]
fn test_lower_str_starts_with_prefix_beyond_capacity_is_false() {
    let starts_with_decl = DeclId::new(119);
    let hir = make_string_arg_pipeline_call_program(starts_with_decl, "a", "abcdefghijklmnopqrstu");
    let decl_names = HashMap::from([(starts_with_decl, "str starts-with".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str starts-with should prove too-long prefixes false");

    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { .. })),
        "expected over-capacity str starts-with to avoid out-of-slot StrCmp"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("false str starts-with result should compile through codegen");
}

#[test]
fn test_lower_str_starts_with_ignore_case_on_known_string_materializes_bool() {
    let starts_with_decl = DeclId::new(150);
    let hir = make_string_arg_pipeline_call_program_with_flags(
        starts_with_decl,
        "AbCd",
        "ab",
        vec![b"ignore-case".to_vec()],
    );
    let decl_names = HashMap::from([(starts_with_decl, "str starts-with".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str starts-with --ignore-case should lower on compile-time known strings");

    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { .. })),
        "expected case-insensitive starts-with to materialize a constant bool"
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
                    src: MirValue::Const(1),
                    ..
                }
            )),
        "expected case-insensitive starts-with to return true"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str starts-with --ignore-case constant bool should compile through codegen");
}

#[test]
fn test_lower_str_ends_with_on_known_string_uses_offset_strcmp() {
    let ends_with_decl = DeclId::new(120);
    let hir = make_string_arg_pipeline_call_program(ends_with_decl, "abcdef", "def");
    let decl_names = HashMap::from([(ends_with_decl, "str ends-with".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str ends-with should lower on tracked strings with known lengths");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StrCmp {
                    lhs_offset: 3,
                    rhs_offset: 0,
                    len: 3,
                    ..
                }
            )),
        "expected str ends-with to compare the suffix at a fixed offset"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str ends-with on known tracked strings should compile through codegen");
}

#[test]
fn test_lower_str_ends_with_suffix_longer_than_known_string_is_false() {
    let ends_with_decl = DeclId::new(121);
    let hir = make_string_arg_pipeline_call_program(ends_with_decl, "a", "abcdef");
    let decl_names = HashMap::from([(ends_with_decl, "str ends-with".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str ends-with should prove impossible suffixes false");

    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { .. })),
        "expected too-long str ends-with suffix to avoid out-of-slot StrCmp"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("false str ends-with result should compile through codegen");
}

#[test]
fn test_lower_str_ends_with_ignore_case_on_known_string_materializes_bool() {
    let ends_with_decl = DeclId::new(151);
    let hir = make_string_arg_pipeline_call_program_with_flags(
        ends_with_decl,
        "AbCd",
        "CD",
        vec![b"ignore-case".to_vec()],
    );
    let decl_names = HashMap::from([(ends_with_decl, "str ends-with".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str ends-with --ignore-case should lower on compile-time known strings");

    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { .. })),
        "expected case-insensitive ends-with to materialize a constant bool"
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
                    src: MirValue::Const(1),
                    ..
                }
            )),
        "expected case-insensitive ends-with to return true"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str ends-with --ignore-case constant bool should compile through codegen");
}

#[test]
fn test_lower_str_contains_on_known_string_uses_offset_strcmps() {
    let contains_decl = DeclId::new(122);
    let hir = make_string_arg_pipeline_call_program(contains_decl, "abcdef", "cd");
    let decl_names = HashMap::from([(contains_decl, "str contains".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str contains should lower on tracked strings with known lengths");

    let comparisons = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::StrCmp { len: 2, .. }))
        .count();
    assert_eq!(
        comparisons, 5,
        "expected str contains to test each possible fixed substring offset"
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
                MirInst::StrCmp {
                    lhs_offset: 2,
                    rhs_offset: 0,
                    len: 2,
                    ..
                }
            )),
        "expected str contains to compare the matching middle offset"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str contains on known tracked strings should compile through codegen");
}

#[test]
fn test_lower_str_contains_ignore_case_on_known_string_materializes_bool() {
    let contains_decl = DeclId::new(152);
    let hir = make_string_arg_pipeline_call_program_with_flags(
        contains_decl,
        "AbCd",
        "bc",
        vec![b"ignore-case".to_vec()],
    );
    let decl_names = HashMap::from([(contains_decl, "str contains".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str contains --ignore-case should lower on compile-time known strings");

    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { .. })),
        "expected case-insensitive contains to materialize a constant bool"
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
                    src: MirValue::Const(1),
                    ..
                }
            )),
        "expected case-insensitive contains to return true"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str contains --ignore-case constant bool should compile through codegen");
}

#[test]
fn test_lower_str_contains_too_long_substring_is_false() {
    let contains_decl = DeclId::new(123);
    let hir = make_string_arg_pipeline_call_program(contains_decl, "a", "abcdef");
    let decl_names = HashMap::from([(contains_decl, "str contains".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str contains should prove impossible substrings false");

    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { .. })),
        "expected too-long str contains substring to avoid out-of-slot StrCmp"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("false str contains result should compile through codegen");
}

#[test]
fn test_lower_str_index_of_on_known_string_returns_first_offset() {
    let index_of_decl = DeclId::new(124);
    let hir = make_string_arg_pipeline_call_program(index_of_decl, "ababa", "ba");
    let decl_names = HashMap::from([(index_of_decl, "str index-of".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str index-of should lower on tracked strings with known lengths");

    let comparisons = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::StrCmp { len: 2, .. }))
        .count();
    assert_eq!(
        comparisons, 4,
        "expected str index-of to test each possible fixed substring offset"
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
                    src: MirValue::Const(1),
                    ..
                }
            )),
        "expected str index-of to emit the first matching byte offset"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str index-of on known tracked strings should compile through codegen");
}

#[test]
fn test_lower_str_index_of_missing_substring_returns_minus_one() {
    let index_of_decl = DeclId::new(125);
    let hir = make_string_arg_pipeline_call_program(index_of_decl, "a", "abcdef");
    let decl_names = HashMap::from([(index_of_decl, "str index-of".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str index-of should prove impossible substrings missing");

    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { .. })),
        "expected too-long str index-of substring to avoid out-of-slot StrCmp"
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
                    src: MirValue::Const(-1),
                    ..
                }
            )),
        "expected str index-of to return -1 when the substring cannot match"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("missing str index-of result should compile through codegen");
}

#[test]
fn test_lower_str_index_of_from_end_on_known_string_returns_last_offset() {
    let index_of_decl = DeclId::new(153);
    let hir = make_string_arg_pipeline_call_program_with_flags(
        index_of_decl,
        "ababa",
        "ba",
        vec![b"end".to_vec()],
    );
    let decl_names = HashMap::from([(index_of_decl, "str index-of".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str index-of --end should lower on tracked strings with known lengths");

    let comparisons = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::StrCmp { len: 2, .. }))
        .count();
    assert_eq!(
        comparisons, 4,
        "expected str index-of --end to test each possible fixed substring offset"
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
                MirInst::StrCmp {
                    lhs_offset: 3,
                    rhs_offset: 0,
                    len: 2,
                    ..
                }
            )),
        "expected str index-of --end to probe the last matching byte offset first"
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
                    src: MirValue::Const(3),
                    ..
                }
            )),
        "expected str index-of --end to return the last matching byte offset"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str index-of --end should compile through codegen");
}

#[test]
fn test_lower_str_index_of_range_on_known_string_limits_search_offsets() {
    let index_of_decl = DeclId::new(154);
    let hir = make_string_index_of_range_program(
        index_of_decl,
        "abcabc",
        "bc",
        Some(2),
        Some(5),
        RangeInclusion::Inclusive,
        Vec::new(),
    );
    let decl_names = HashMap::from([(index_of_decl, "str index-of".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str index-of --range should lower on tracked strings with known lengths");

    let comparisons = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::StrCmp { len: 2, .. }))
        .count();
    assert_eq!(
        comparisons, 3,
        "expected str index-of --range to probe only offsets inside the bounded byte window"
    );
    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { lhs_offset: 1, .. })),
        "expected str index-of --range to skip matches before the bounded window"
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
                    src: MirValue::Const(4),
                    ..
                }
            )),
        "expected str index-of --range to return the absolute byte offset"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str index-of --range should compile through codegen");
}

#[test]
fn test_lower_str_index_of_open_end_range_on_known_string_uses_input_length() {
    let index_of_decl = DeclId::new(155);
    let hir = make_string_index_of_range_program(
        index_of_decl,
        "abcabc",
        "bc",
        Some(2),
        None,
        RangeInclusion::Inclusive,
        Vec::new(),
    );
    let decl_names = HashMap::from([(index_of_decl, "str index-of".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str index-of --range with omitted end should use the input length");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StrCmp {
                    lhs_offset: 4,
                    rhs_offset: 0,
                    len: 2,
                    ..
                }
            )),
        "expected open-ended str index-of --range to probe through the input length"
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
                    src: MirValue::Const(4),
                    ..
                }
            )),
        "expected open-ended str index-of --range to return the absolute byte offset"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str index-of open-ended --range should compile through codegen");
}

#[test]
fn test_lower_str_index_of_grapheme_clusters_on_known_string_returns_grapheme_offset() {
    let index_of_decl = DeclId::new(158);
    let hir = make_string_arg_pipeline_call_program_with_flags(
        index_of_decl,
        "🇯🇵ほげ ふが ぴよ",
        "ふが",
        vec![b"grapheme-clusters".to_vec()],
    );
    let decl_names = HashMap::from([(index_of_decl, "str index-of".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str index-of --grapheme-clusters should lower on known strings");

    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { .. })),
        "expected compile-time grapheme index-of to avoid byte probing"
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
                    src: MirValue::Const(4),
                    ..
                }
            )),
        "expected str index-of --grapheme-clusters to return the grapheme offset"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str index-of --grapheme-clusters should compile through codegen");
}

#[test]
fn test_lower_str_index_of_grapheme_clusters_from_end_returns_last_grapheme_offset() {
    let index_of_decl = DeclId::new(159);
    let hir = make_string_arg_pipeline_call_program_with_flags(
        index_of_decl,
        "a🇯🇵b🇯🇵c",
        "🇯🇵",
        vec![b"grapheme-clusters".to_vec(), b"end".to_vec()],
    );
    let decl_names = HashMap::from([(index_of_decl, "str index-of".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str index-of --grapheme-clusters --end should lower on known strings");

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
                    src: MirValue::Const(3),
                    ..
                }
            )),
        "expected str index-of --grapheme-clusters --end to return the last grapheme offset"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str index-of --grapheme-clusters --end should compile through codegen");
}

#[test]
fn test_lower_str_index_of_grapheme_clusters_with_range_returns_absolute_grapheme_offset() {
    let index_of_decl = DeclId::new(160);
    let hir = make_string_index_of_range_program(
        index_of_decl,
        "ほげ ふが",
        "ふ",
        Some(6),
        Some(9),
        RangeInclusion::Inclusive,
        vec![b"grapheme-clusters".to_vec()],
    );
    let decl_names = HashMap::from([(index_of_decl, "str index-of".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str index-of --grapheme-clusters --range should lower on UTF-8-aligned bounds");

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
                    src: MirValue::Const(3),
                    ..
                }
            )),
        "expected str index-of --grapheme-clusters --range to return the absolute grapheme offset"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str index-of --grapheme-clusters --range should compile through codegen");
}

#[test]
fn test_lower_str_index_of_grapheme_clusters_with_non_boundary_range_is_rejected() {
    let index_of_decl = DeclId::new(161);
    let hir = make_string_index_of_range_program(
        index_of_decl,
        "🇯🇵ほげ ふが ぴよ",
        "ふが",
        Some(4),
        Some(5),
        RangeInclusion::Inclusive,
        vec![b"grapheme-clusters".to_vec()],
    );
    let decl_names = HashMap::from([(index_of_decl, "str index-of".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("str index-of --grapheme-clusters --range should reject non-boundary ranges");

    assert!(
        matches!(
            err,
            CompileError::UnsupportedInstruction(ref msg)
                if msg.contains("--range bounds must align to UTF-8 character boundaries")
        ),
        "expected targeted UTF-8 boundary diagnostic, got {err:?}"
    );
}

#[test]
fn test_lower_str_replace_on_known_string_materializes_replaced_literal() {
    let replace_decl = DeclId::new(126);
    let starts_with_decl = DeclId::new(128);
    let hir = make_str_replace_then_starts_with_program(
        replace_decl,
        starts_with_decl,
        "abcabc",
        "ab",
        "XY",
        "XYc",
        Vec::new(),
    );
    let decl_names = HashMap::from([
        (replace_decl, "str replace".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str replace should lower for compile-time known string input");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StringAppend {
                    val_type: StringAppendType::Literal { bytes },
                    ..
                } if bytes.starts_with(b"XYcabc\0")
            )),
        "expected str replace to materialize the first substring replacement"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str replace result consumed by str starts-with should compile through codegen");
}

#[test]
fn test_lower_str_replace_missing_pattern_materializes_original_literal() {
    let replace_decl = DeclId::new(127);
    let starts_with_decl = DeclId::new(129);
    let hir = make_str_replace_then_starts_with_program(
        replace_decl,
        starts_with_decl,
        "abc",
        "zz",
        "XY",
        "abc",
        Vec::new(),
    );
    let decl_names = HashMap::from([
        (replace_decl, "str replace".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str replace should preserve known strings when the pattern is missing");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StringAppend {
                    val_type: StringAppendType::Literal { bytes },
                    ..
                } if bytes.starts_with(b"abc\0")
            )),
        "expected str replace with a missing pattern to materialize the original string"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("missing-pattern str replace result consumed by str starts-with should compile through codegen");
}

#[test]
fn test_lower_str_replace_all_on_known_string_materializes_all_replacements() {
    let replace_decl = DeclId::new(144);
    let starts_with_decl = DeclId::new(145);
    let hir = make_str_replace_then_starts_with_program(
        replace_decl,
        starts_with_decl,
        "abcabc",
        "ab",
        "XY",
        "XYcXYc",
        vec![b"all".to_vec()],
    );
    let decl_names = HashMap::from([
        (replace_decl, "str replace".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str replace --all should lower for compile-time known string input");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StringAppend {
                    val_type: StringAppendType::Literal { bytes },
                    ..
                } if bytes.starts_with(b"XYcXYc\0")
            )),
        "expected str replace --all to materialize every substring replacement"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints)).expect(
        "str replace --all result consumed by str starts-with should compile through codegen",
    );
}

#[test]
fn test_lower_str_trim_on_known_string_materializes_trimmed_literal() {
    let trim_decl = DeclId::new(130);
    let starts_with_decl = DeclId::new(131);
    let hir =
        make_string_command_then_starts_with_program(trim_decl, starts_with_decl, "  abc  ", "abc");
    let decl_names = HashMap::from([
        (trim_decl, "str trim".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str trim should lower for compile-time known string input");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StringAppend {
                    val_type: StringAppendType::Literal { bytes },
                    ..
                } if bytes.starts_with(b"abc\0")
            )),
        "expected str trim to materialize the trimmed string"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str trim result consumed by str starts-with should compile through codegen");
}

#[test]
fn test_lower_str_trim_left_on_known_string_materializes_left_trimmed_literal() {
    let trim_decl = DeclId::new(146);
    let starts_with_decl = DeclId::new(147);
    let hir = make_str_trim_then_starts_with_program(
        trim_decl,
        starts_with_decl,
        "  abc  ",
        "abc  ",
        vec![b"left".to_vec()],
        None,
    );
    let decl_names = HashMap::from([
        (trim_decl, "str trim".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str trim --left should lower for compile-time known string input");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StringAppend {
                    val_type: StringAppendType::Literal { bytes },
                    ..
                } if bytes.starts_with(b"abc  \0")
            )),
        "expected str trim --left to materialize the left-trimmed string"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints)).expect(
        "str trim --left result consumed by str starts-with should compile through codegen",
    );
}

#[test]
fn test_lower_str_trim_right_char_on_known_string_materializes_trimmed_literal() {
    let trim_decl = DeclId::new(148);
    let starts_with_decl = DeclId::new(149);
    let hir = make_str_trim_then_starts_with_program(
        trim_decl,
        starts_with_decl,
        "xxabcxx",
        "xxabc",
        vec![b"right".to_vec()],
        Some("x"),
    );
    let decl_names = HashMap::from([
        (trim_decl, "str trim".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str trim --right --char should lower for compile-time known string input");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StringAppend {
                    val_type: StringAppendType::Literal { bytes },
                    ..
                } if bytes.starts_with(b"xxabc\0")
            )),
        "expected str trim --right --char to materialize the trimmed string"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints)).expect(
        "str trim --right --char result consumed by str starts-with should compile through codegen",
    );
}

#[test]
fn test_lower_str_downcase_on_known_string_materializes_lowercase_literal() {
    let downcase_decl = DeclId::new(132);
    let starts_with_decl = DeclId::new(133);
    let hir =
        make_string_command_then_starts_with_program(downcase_decl, starts_with_decl, "AbC", "abc");
    let decl_names = HashMap::from([
        (downcase_decl, "str downcase".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str downcase should lower for compile-time known string input");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StringAppend {
                    val_type: StringAppendType::Literal { bytes },
                    ..
                } if bytes.starts_with(b"abc\0")
            )),
        "expected str downcase to materialize the lowercase string"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str downcase result consumed by str starts-with should compile through codegen");
}

#[test]
fn test_lower_str_upcase_on_known_string_materializes_uppercase_literal() {
    let upcase_decl = DeclId::new(134);
    let starts_with_decl = DeclId::new(135);
    let hir =
        make_string_command_then_starts_with_program(upcase_decl, starts_with_decl, "AbC", "ABC");
    let decl_names = HashMap::from([
        (upcase_decl, "str upcase".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str upcase should lower for compile-time known string input");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StringAppend {
                    val_type: StringAppendType::Literal { bytes },
                    ..
                } if bytes.starts_with(b"ABC\0")
            )),
        "expected str upcase to materialize the uppercase string"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str upcase result consumed by str starts-with should compile through codegen");
}

#[test]
fn test_lower_str_reverse_on_known_string_materializes_reversed_literal() {
    let reverse_decl = DeclId::new(136);
    let starts_with_decl = DeclId::new(137);
    let hir =
        make_string_command_then_starts_with_program(reverse_decl, starts_with_decl, "abc", "cba");
    let decl_names = HashMap::from([
        (reverse_decl, "str reverse".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str reverse should lower for compile-time known string input");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StringAppend {
                    val_type: StringAppendType::Literal { bytes },
                    ..
                } if bytes.starts_with(b"cba\0")
            )),
        "expected str reverse to materialize the reversed string"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str reverse result consumed by str starts-with should compile through codegen");
}

#[test]
fn test_lower_str_capitalize_on_known_string_materializes_capitalized_literal() {
    let capitalize_decl = DeclId::new(138);
    let starts_with_decl = DeclId::new(139);
    let hir = make_string_command_then_starts_with_program(
        capitalize_decl,
        starts_with_decl,
        "abc",
        "Abc",
    );
    let decl_names = HashMap::from([
        (capitalize_decl, "str capitalize".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str capitalize should lower for compile-time known string input");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StringAppend {
                    val_type: StringAppendType::Literal { bytes },
                    ..
                } if bytes.starts_with(b"Abc\0")
            )),
        "expected str capitalize to materialize the capitalized string"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str capitalize result consumed by str starts-with should compile through codegen");
}

#[test]
fn test_lower_str_substring_on_known_string_materializes_slice_literal() {
    let substring_decl = DeclId::new(140);
    let starts_with_decl = DeclId::new(141);
    let hir = make_string_substring_then_starts_with_program(
        substring_decl,
        starts_with_decl,
        "abcdef",
        1,
        3,
        RangeInclusion::Inclusive,
        "bcd",
        Vec::new(),
    );
    let decl_names = HashMap::from([
        (substring_decl, "str substring".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str substring should lower for compile-time known string input and range");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StringAppend {
                    val_type: StringAppendType::Literal { bytes },
                    ..
                } if bytes.starts_with(b"bcd\0")
            )),
        "expected str substring to materialize the sliced string"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str substring result consumed by str starts-with should compile through codegen");
}

#[test]
fn test_lower_str_substring_negative_end_materializes_slice_literal() {
    let substring_decl = DeclId::new(142);
    let starts_with_decl = DeclId::new(143);
    let hir = make_string_substring_then_starts_with_program(
        substring_decl,
        starts_with_decl,
        "abcdef",
        1,
        -2,
        RangeInclusion::Inclusive,
        "bcde",
        Vec::new(),
    );
    let decl_names = HashMap::from([
        (substring_decl, "str substring".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str substring should support compile-time known negative end indexes");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StringAppend {
                    val_type: StringAppendType::Literal { bytes },
                    ..
                } if bytes.starts_with(b"bcde\0")
            )),
        "expected str substring to materialize the negative-end sliced string"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("str substring result consumed by str starts-with should compile through codegen");
}

#[test]
fn test_lower_str_substring_grapheme_clusters_on_known_string_materializes_slice_literal() {
    let substring_decl = DeclId::new(156);
    let starts_with_decl = DeclId::new(157);
    let hir = make_string_substring_then_starts_with_program(
        substring_decl,
        starts_with_decl,
        "🇯🇵ほげ ふが ぴよ",
        4,
        5,
        RangeInclusion::Inclusive,
        "ふが",
        vec![b"grapheme-clusters".to_vec()],
    );
    let decl_names = HashMap::from([
        (substring_decl, "str substring".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("str substring --grapheme-clusters should lower for known string input");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StringAppend {
                    val_type: StringAppendType::Literal { bytes },
                    ..
                } if bytes.starts_with("ふが\0".as_bytes())
            )),
        "expected grapheme-cluster substring to materialize the sliced string"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints)).expect(
        "str substring --grapheme-clusters result consumed by str starts-with should compile",
    );
}

#[test]
fn test_lower_is_empty_on_metadata_record_uses_known_field_count() {
    let is_empty_decl = DeclId::new(114);
    let (hir, decl_names) = make_record_empty_predicate_program(is_empty_decl, "is-empty", false);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("is-empty should lower on metadata-backed records");

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
                    src: MirValue::Const(0),
                    ..
                }
            )),
        "expected non-empty metadata record to lower to false"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("is-empty on metadata-backed record should compile through codegen");
}

#[test]
fn test_lower_is_not_empty_on_metadata_record_uses_known_field_count() {
    let is_not_empty_decl = DeclId::new(115);
    let (hir, decl_names) =
        make_record_empty_predicate_program(is_not_empty_decl, "is-not-empty", true);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("is-not-empty should lower on metadata-backed records");

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
                    src: MirValue::Const(0),
                    ..
                }
            )),
        "expected empty metadata record to lower to false for is-not-empty"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("is-not-empty on metadata-backed record should compile through codegen");
}

#[test]
fn test_lower_is_not_empty_on_numeric_list_compares_length_to_zero() {
    let is_not_empty_decl = DeclId::new(116);
    let hir = make_numeric_list_pipeline_call_program(is_not_empty_decl, None);
    let decl_names = HashMap::from([(is_not_empty_decl, "is-not-empty".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("is-not-empty should lower on stack-backed numeric lists");

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
                    op: BinOpKind::Ne,
                    rhs: MirValue::Const(0),
                    ..
                }
            )),
        "expected is-not-empty to compare length != zero"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("is-not-empty on stack-backed numeric list should compile through codegen");
}

#[test]
fn test_lower_length_on_numeric_list_reads_runtime_length() {
    let length_decl = DeclId::new(104);
    let hir = make_numeric_list_pipeline_call_program(length_decl, None);
    let decl_names = HashMap::from([(length_decl, "length".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("length should lower on stack-backed numeric lists");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListLen { .. })),
        "expected length to inspect the list runtime length"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("length on stack-backed numeric list should compile through codegen");
}

#[test]
fn test_lower_math_sum_on_numeric_list_accumulates_items() {
    let sum_decl = DeclId::new(106);
    let hir = make_numeric_list_pipeline_call_program(sum_decl, None);
    let decl_names = HashMap::from([(sum_decl, "math sum".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("math sum should lower on known non-empty stack-backed numeric lists");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListLen { .. })),
        "expected math sum to inspect the input list runtime length"
    );
    assert!(
        instructions
            .iter()
            .filter(|inst| matches!(inst, MirInst::ListGet { .. }))
            .count()
            >= 3,
        "expected math sum to use bounded constant-index list reads"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Add,
                ..
            }
        )),
        "expected math sum to accumulate with Add"
    );
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::StoreSlot { .. }))
            && instructions
                .iter()
                .any(|inst| matches!(inst, MirInst::LoadSlot { .. })),
        "expected math sum to accumulate through a stack scalar slot"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("math sum should compile through codegen");
}

#[test]
fn test_lower_math_sum_on_empty_numeric_list_is_rejected() {
    let sum_decl = DeclId::new(107);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::list(Vec::new(), Span::test_data())),
                },
                HirStmt::Call {
                    decl_id: sum_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);
    let decl_names = HashMap::from([(sum_decl, "math sum".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("math sum over an empty list should keep Nushell's rejection semantics");

    assert!(
        err.to_string()
            .contains("math sum requires a non-empty stack-backed numeric list"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_math_product_min_max_on_numeric_lists() {
    for (offset, command_name, expected_op) in [
        (0, "math product", BinOpKind::Mul),
        (1, "math min", BinOpKind::Lt),
        (2, "math max", BinOpKind::Gt),
    ] {
        let decl = DeclId::new(108 + offset);
        let hir = make_numeric_list_pipeline_call_program(decl, None);
        let decl_names = HashMap::from([(decl, command_name.to_string())]);

        let result = lower_hir_to_mir_with_hints(
            &hir,
            None,
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|err| panic!("{command_name} should lower on numeric lists: {err}"));
        let instructions = result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .collect::<Vec<_>>();

        assert!(
            instructions.iter().any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op,
                    ..
                } if *op == expected_op
            )),
            "expected {command_name} to lower with {expected_op:?}"
        );
        compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
            .unwrap_or_else(|err| panic!("{command_name} should compile through codegen: {err}"));
    }
}

#[test]
fn test_lower_uniq_on_numeric_list_removes_duplicate_values() {
    let uniq_decl = DeclId::new(111);
    let get_decl = DeclId::new(112);
    let hir = HirProgram::new(
        HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadValue {
                        dst: RegId::new(0),
                        val: Box::new(Value::list(
                            vec![
                                Value::int(10, Span::test_data()),
                                Value::int(20, Span::test_data()),
                                Value::int(10, Span::test_data()),
                                Value::int(30, Span::test_data()),
                                Value::int(20, Span::test_data()),
                            ],
                            Span::test_data(),
                        )),
                    },
                    HirStmt::Call {
                        decl_id: uniq_decl,
                        src_dst: RegId::new(1),
                        args: HirCallArgs {
                            pipeline_input: Some(RegId::new(0)),
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(2),
                    },
                    HirStmt::Call {
                        decl_id: get_decl,
                        src_dst: RegId::new(3),
                        args: HirCallArgs {
                            pipeline_input: Some(RegId::new(1)),
                            positional: vec![RegId::new(2)],
                            ..HirCallArgs::default()
                        },
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(3) },
            }],
            entry: HirBlockId(0),
            spans: Vec::new(),
            ast: Vec::new(),
            comments: Vec::new(),
            register_count: 4,
            file_count: 0,
        },
        HashMap::new(),
        vec![],
        None,
    );
    let decl_names = HashMap::from([
        (uniq_decl, "uniq".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("uniq should lower on stack-backed numeric lists");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Eq,
                ..
            }
        )),
        "expected uniq to compare each item against earlier values"
    );
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "expected uniq to rebuild a deduplicated stack list"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("uniq should compile through codegen");
}

#[test]
fn test_lower_sort_on_numeric_list_uses_bounded_compare_swaps() {
    let sort_decl = DeclId::new(121);
    let get_decl = DeclId::new(122);
    let hir = HirProgram::new(
        HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadValue {
                        dst: RegId::new(0),
                        val: Box::new(Value::list(
                            vec![
                                Value::int(30, Span::test_data()),
                                Value::int(10, Span::test_data()),
                                Value::int(20, Span::test_data()),
                            ],
                            Span::test_data(),
                        )),
                    },
                    HirStmt::Call {
                        decl_id: sort_decl,
                        src_dst: RegId::new(1),
                        args: HirCallArgs {
                            pipeline_input: Some(RegId::new(0)),
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::Call {
                        decl_id: get_decl,
                        src_dst: RegId::new(3),
                        args: HirCallArgs {
                            pipeline_input: Some(RegId::new(1)),
                            positional: vec![RegId::new(2)],
                            ..HirCallArgs::default()
                        },
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(3) },
            }],
            entry: HirBlockId(0),
            spans: Vec::new(),
            ast: Vec::new(),
            comments: Vec::new(),
            register_count: 4,
            file_count: 0,
        },
        HashMap::new(),
        vec![],
        None,
    );
    let decl_names = HashMap::from([
        (sort_decl, "sort".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sort should lower on small stack-backed numeric lists");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Gt,
                ..
            }
        )),
        "expected ascending sort to swap when the left value is greater"
    );
    assert!(
        instructions
            .iter()
            .filter(|inst| matches!(inst, MirInst::StoreSlot { .. }))
            .count()
            >= 2,
        "expected sort to rewrite stack slots during compare/swap"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("sort followed by get should compile through codegen");
}

#[test]
fn test_lower_sort_reverse_on_numeric_list_uses_descending_compare() {
    let sort_decl = DeclId::new(123);
    let get_decl = DeclId::new(124);
    let mut hir = make_numeric_list_call_then_get_program(sort_decl, get_decl, None, 0);
    let HirStmt::Call { args, .. } = &mut hir.main.blocks[0].stmts[1] else {
        panic!("expected sort call");
    };
    args.flags.push(b"reverse".to_vec());
    let decl_names = HashMap::from([
        (sort_decl, "sort".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sort --reverse should lower on small stack-backed numeric lists");

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
                    op: BinOpKind::Lt,
                    ..
                }
            )),
        "expected reverse sort to swap when the left value is smaller"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("sort --reverse followed by get should compile through codegen");
}

#[test]
fn test_lower_sort_large_numeric_list_capacity_is_rejected() {
    let sort_decl = DeclId::new(125);
    let values = (0..17)
        .map(|value| Value::int(value, Span::test_data()))
        .collect::<Vec<_>>();
    let hir = HirProgram::new(
        HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadValue {
                        dst: RegId::new(0),
                        val: Box::new(Value::list(values, Span::test_data())),
                    },
                    HirStmt::Call {
                        decl_id: sort_decl,
                        src_dst: RegId::new(1),
                        args: HirCallArgs {
                            pipeline_input: Some(RegId::new(0)),
                            ..HirCallArgs::default()
                        },
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
        },
        HashMap::new(),
        vec![],
        None,
    );
    let decl_names = HashMap::from([(sort_decl, "sort".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("large-capacity sort should be rejected instead of generating huge MIR");

    assert!(
        err.to_string()
            .contains("sort supports stack-backed numeric lists with capacity <= 16"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_compact_on_numeric_list_is_passthrough() {
    let compact_decl = DeclId::new(126);
    let get_decl = DeclId::new(127);
    let hir = make_numeric_list_call_then_get_program(compact_decl, get_decl, None, 1);
    let decl_names = HashMap::from([
        (compact_decl, "compact".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("compact should lower as identity on stack-backed numeric lists");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::Copy {
                src: MirValue::VReg(_),
                ..
            }
        )),
        "expected compact to pass through the tracked list pointer"
    );
    assert!(
        instructions
            .iter()
            .all(|inst| !matches!(inst, MirInst::ListPush { .. })),
        "compact should not rebuild numeric lists that cannot contain null values"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("compact followed by get should compile through codegen");
}

#[test]
fn test_lower_compact_empty_on_numeric_list_is_passthrough() {
    let compact_decl = DeclId::new(128);
    let get_decl = DeclId::new(129);
    let mut hir = make_numeric_list_call_then_get_program(compact_decl, get_decl, None, 1);
    let HirStmt::Call { args, .. } = &mut hir.main.blocks[0].stmts[1] else {
        panic!("expected compact call");
    };
    args.flags.push(b"empty".to_vec());
    let decl_names = HashMap::from([
        (compact_decl, "compact".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("compact --empty should still be identity on stack-backed numeric lists");

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("compact --empty followed by get should compile through codegen");
}

#[test]
fn test_lower_compact_column_argument_on_numeric_list_is_rejected() {
    let compact_decl = DeclId::new(130);
    let hir = make_numeric_list_pipeline_call_program(compact_decl, Some(0));
    let decl_names = HashMap::from([(compact_decl, "compact".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("compact column arguments should be rejected for numeric lists");

    assert!(
        err.to_string()
            .contains("compact does not accept column arguments"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_find_on_numeric_list_filters_equal_values() {
    let find_decl = DeclId::new(131);
    let get_decl = DeclId::new(132);
    let hir = make_numeric_list_item_call_then_get_program(find_decl, get_decl, 20, 0);
    let decl_names = HashMap::from([
        (find_decl, "find".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("find should lower on stack-backed numeric lists");
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Eq,
                ..
            }
        )),
        "expected find to compare list items against the search value"
    );
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "expected find to rebuild a filtered stack list"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Lt,
                ..
            }
        )),
        "expected find to guard each list access with runtime length"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("find followed by get should compile through codegen");
}

#[test]
fn test_lower_find_missing_on_numeric_list_returns_empty_list() {
    let find_decl = DeclId::new(133);
    let length_decl = DeclId::new(134);
    let hir = make_numeric_list_call_then_length_program(find_decl, length_decl, Some(99));
    let decl_names = HashMap::from([
        (find_decl, "find".to_string()),
        (length_decl, "length".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("find with no matching constants should lower to an empty stack-backed list");

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("find followed by length should compile through codegen");
}

#[test]
fn test_lower_find_large_integer_needle_materializes_operand() {
    let find_decl = DeclId::new(135);
    let get_decl = DeclId::new(136);
    let large = 1_i64 << 40;
    let hir = HirProgram::new(
        HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadValue {
                        dst: RegId::new(0),
                        val: Box::new(Value::list(
                            vec![
                                Value::int(large, Span::test_data()),
                                Value::int(20, Span::test_data()),
                            ],
                            Span::test_data(),
                        )),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(large),
                    },
                    HirStmt::Call {
                        decl_id: find_decl,
                        src_dst: RegId::new(1),
                        args: HirCallArgs {
                            pipeline_input: Some(RegId::new(0)),
                            positional: vec![RegId::new(2)],
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::Call {
                        decl_id: get_decl,
                        src_dst: RegId::new(4),
                        args: HirCallArgs {
                            pipeline_input: Some(RegId::new(1)),
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
        },
        HashMap::new(),
        vec![],
        None,
    );
    let decl_names = HashMap::from([
        (find_decl, "find".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("find should lower large integer needles without truncating immediates");
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
                    op: BinOpKind::Eq,
                    rhs: MirValue::VReg(_),
                    ..
                }
            )),
        "expected large find needle to be materialized before equality comparison"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("find with a large integer needle should compile through codegen");
}

#[test]
fn test_lower_length_on_null_returns_zero() {
    let length_decl = DeclId::new(105);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Nothing,
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);
    let decl_names = HashMap::from([(length_decl, "length".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("length should lower on literal null");

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
                    src: MirValue::Const(0),
                    ..
                }
            )),
        "expected null length to lower to zero"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("length on literal null should compile through codegen");
}

#[test]
fn test_lower_length_on_binary_returns_byte_len() {
    let length_decl = DeclId::new(106);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Binary(vec![1, 2, 3]),
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);
    let decl_names = HashMap::from([(length_decl, "length".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("length should lower on literal binary");

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
                    src: MirValue::Const(3),
                    ..
                }
            )),
        "expected binary length to lower to its byte count"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("length on literal binary should compile through codegen");
}

#[test]
fn test_lower_select_on_metadata_record_materializes_requested_layout() {
    let select_decl = DeclId::new(94);
    let hir = make_record_projection_then_field_program(select_decl, &["cpu", "pid"], true, "pid");
    let decl_names = HashMap::from([(select_decl, "select".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("select should lower on metadata-backed records");
    let store_offsets = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter_map(|inst| match inst {
            MirInst::StoreSlot {
                offset,
                ty: MirType::I64,
                ..
            } => Some(*offset),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(
        store_offsets.contains(&0) && store_offsets.contains(&8),
        "expected select to materialize the projected record layout, got offsets {store_offsets:?}"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("select on metadata-backed record should compile through codegen");
}

#[test]
fn test_lower_reject_on_metadata_record_materializes_remaining_layout() {
    let reject_decl = DeclId::new(95);
    let hir = make_record_projection_then_field_program(reject_decl, &["pid"], false, "cpu");
    let decl_names = HashMap::from([(reject_decl, "reject".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("reject should lower on metadata-backed records");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StoreSlot { offset: 0, .. })),
        "expected reject to materialize a remaining-field record"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("reject on metadata-backed record should compile through codegen");
}

#[test]
fn test_lower_select_missing_metadata_record_field_is_rejected() {
    let select_decl = DeclId::new(96);
    let hir = make_record_projection_then_field_program(select_decl, &["missing"], true, "missing");
    let decl_names = HashMap::from([(select_decl, "select".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("select of a missing metadata-backed record field should be rejected");

    assert!(
        err.to_string()
            .contains("cannot find record field 'missing'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_rename_metadata_record_fields_by_position() {
    let rename_decl = DeclId::new(102);
    let hir =
        make_record_projection_then_field_program(rename_decl, &["tid", "core"], false, "tid");
    let decl_names = HashMap::from([(rename_decl, "rename".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("rename should rename metadata-backed record fields by position");

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("renamed record field projection should compile through codegen");
}

#[test]
fn test_lower_rename_leaves_trailing_metadata_record_fields_unchanged() {
    let rename_decl = DeclId::new(103);
    let hir = make_record_projection_then_field_program(rename_decl, &["tid"], false, "cpu");
    let decl_names = HashMap::from([(rename_decl, "rename".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("rename should leave trailing metadata-backed record fields unchanged");

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("trailing field projection after rename should compile through codegen");
}

#[test]
fn test_lower_merge_overwrites_metadata_record_field() {
    let merge_decl = DeclId::new(107);
    let hir = make_record_merge_then_field_program(merge_decl, &[("pid", 9), ("mem", 4)], "pid");
    let decl_names = HashMap::from([(merge_decl, "merge".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("merge should replace matching metadata-backed record fields");

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("merged replacement record field projection should compile through codegen");
}

#[test]
fn test_lower_merge_adds_metadata_record_field() {
    let merge_decl = DeclId::new(108);
    let hir = make_record_merge_then_field_program(merge_decl, &[("mem", 4)], "mem");
    let decl_names = HashMap::from([(merge_decl, "merge".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("merge should append missing metadata-backed record fields");

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("merged added record field projection should compile through codegen");
}

#[test]
fn test_lower_merge_rejects_non_record_argument() {
    let merge_decl = DeclId::new(109);
    let mut input = Record::new();
    input.push("pid", Value::int(7, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::record(input, Span::test_data())),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(9),
                },
                HirStmt::Call {
                    decl_id: merge_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(1) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 3,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);
    let decl_names = HashMap::from([(merge_decl, "merge".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("merge of a non-record argument should be rejected");

    assert!(
        err.to_string()
            .contains("merge requires a record argument with compiler-known fields"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_get_metadata_record_field_projects_value() {
    let get_decl = DeclId::new(114);
    let hir = make_record_get_field_program(get_decl, "cpu");
    let decl_names = HashMap::from([(get_decl, "get".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("get should project metadata-backed record fields");

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("metadata-backed record get should compile through codegen");
}

#[test]
fn test_lower_get_missing_metadata_record_field_is_rejected() {
    let get_decl = DeclId::new(115);
    let hir = make_record_get_field_program(get_decl, "missing");
    let decl_names = HashMap::from([(get_decl, "get".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("get of a missing metadata-backed record field should be rejected");

    assert!(
        err.to_string()
            .contains("get field 'missing' was not found"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_get_metadata_record_list_field_preserves_list_metadata() {
    let get_decl = DeclId::new(116);
    let hir = make_record_get_nested_list_item_program(get_decl);
    let decl_names = HashMap::from([(get_decl, "get".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("get should preserve nested metadata-backed list fields");

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
        "expected record field get followed by list get to preserve stack-list metadata"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("metadata-backed record list field get should compile through codegen");
}

#[test]
fn test_lower_values_on_integer_metadata_record_builds_numeric_list() {
    let values_decl = DeclId::new(110);
    let get_decl = DeclId::new(111);
    let hir = make_record_values_then_get_program(values_decl, get_decl, false, 1);
    let decl_names = HashMap::from([
        (values_decl, "values".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("values should lower integer metadata-backed record fields");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListNew { max_len: 2, .. })),
        "expected values to materialize a numeric list with one slot per record field"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("record values followed by get should compile through codegen");
}

#[test]
fn test_lower_values_rejects_non_integer_metadata_record_field() {
    let values_decl = DeclId::new(112);
    let get_decl = DeclId::new(113);
    let hir = make_record_values_then_get_program(values_decl, get_decl, true, 1);
    let decl_names = HashMap::from([
        (values_decl, "values".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("values of a record containing a bool field should be rejected");

    assert!(
        err.to_string()
            .contains("values supports only integer scalar record fields"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_insert_adds_metadata_record_field() {
    let insert_decl = DeclId::new(97);
    let hir = make_record_set_then_field_program(insert_decl, "mem", 9, "mem");
    let decl_names = HashMap::from([(insert_decl, "insert".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("insert should add a missing metadata-backed record field");

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("insert-added record field projection should compile through codegen");
}

#[test]
fn test_lower_update_replaces_metadata_record_field() {
    let update_decl = DeclId::new(98);
    let hir = make_record_set_then_field_program(update_decl, "pid", 9, "pid");
    let decl_names = HashMap::from([(update_decl, "update".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("update should replace an existing metadata-backed record field");

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("updated record field projection should compile through codegen");
}

#[test]
fn test_lower_upsert_adds_or_replaces_metadata_record_field() {
    let upsert_decl = DeclId::new(99);
    let insert_hir = make_record_set_then_field_program(upsert_decl, "mem", 9, "mem");
    let update_hir = make_record_set_then_field_program(upsert_decl, "pid", 9, "pid");
    let decl_names = HashMap::from([(upsert_decl, "upsert".to_string())]);

    let insert_result = lower_hir_to_mir_with_hints(
        &insert_hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("upsert should add a missing metadata-backed record field");
    compile_mir_to_ebpf_with_hints(
        &insert_result.program,
        None,
        Some(&insert_result.type_hints),
    )
    .expect("upsert-added record field projection should compile through codegen");

    let update_result = lower_hir_to_mir_with_hints(
        &update_hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("upsert should replace an existing metadata-backed record field");
    compile_mir_to_ebpf_with_hints(
        &update_result.program,
        None,
        Some(&update_result.type_hints),
    )
    .expect("upsert-updated record field projection should compile through codegen");
}

#[test]
fn test_lower_insert_existing_metadata_record_field_is_rejected() {
    let insert_decl = DeclId::new(100);
    let hir = make_record_set_then_field_program(insert_decl, "pid", 9, "pid");
    let decl_names = HashMap::from([(insert_decl, "insert".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("insert of an existing metadata-backed record field should be rejected");

    assert!(
        err.to_string()
            .contains("insert cannot replace existing record field 'pid'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_update_missing_metadata_record_field_is_rejected() {
    let update_decl = DeclId::new(101);
    let hir = make_record_set_then_field_program(update_decl, "mem", 9, "mem");
    let decl_names = HashMap::from([(update_decl, "update".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("update of a missing metadata-backed record field should be rejected");

    assert!(
        err.to_string()
            .contains("update cannot find record field 'mem'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_default_replaces_literal_null() {
    let default_decl = DeclId::new(97);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Nothing,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(9),
                },
                HirStmt::Call {
                    decl_id: default_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(2) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 3,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);
    let decl_names = HashMap::from([(default_decl, "default".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("default should replace literal null");

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("default replacing literal null should compile through codegen");
}

#[test]
fn test_lower_default_adds_missing_metadata_record_field() {
    let default_decl = DeclId::new(98);
    let mut rec = Record::new();
    rec.push("pid", Value::int(7, Span::test_data()));
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::record(rec, Span::test_data())),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("cpu")],
                    })),
                },
                HirStmt::Call {
                    decl_id: default_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1), RegId::new(2)],
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("cpu")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 5,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);
    let decl_names = HashMap::from([(default_decl, "default".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("default should add missing record fields");

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("default-added record field projection should compile through codegen");
}

#[test]
fn test_lower_default_replaces_null_metadata_record_field() {
    let default_decl = DeclId::new(99);
    let mut rec = Record::new();
    rec.push("pid", Value::nothing(Span::test_data()));
    rec.push("cpu", Value::int(2, Span::test_data()));
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::record(rec, Span::test_data())),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(b"pid".to_vec()),
                },
                HirStmt::Call {
                    decl_id: default_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1), RegId::new(2)],
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
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
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 5,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);
    let decl_names = HashMap::from([(default_decl, "default".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("default should replace constant null record fields");

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("default-replaced record field projection should compile through codegen");
}

#[test]
fn test_lower_default_empty_flag_replaces_literal_empty_string() {
    let default_decl = DeclId::new(100);
    let is_empty_decl = DeclId::new(101);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String(Vec::new()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(b"x".to_vec()),
                },
                HirStmt::Call {
                    decl_id: default_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        pipeline_input: Some(RegId::new(0)),
                        flags: vec![b"empty".to_vec()],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: is_empty_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(2)),
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);
    let decl_names = HashMap::from([
        (default_decl, "default".to_string()),
        (is_empty_decl, "is-empty".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("default --empty should replace known empty strings");

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("default --empty replacing a known empty string should compile through codegen");
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
fn test_lower_load_value_record_uses_natural_alignment() {
    let mut rec = Record::new();
    rec.push("pid", Value::int(7, Span::test_data()));
    rec.push("ok", Value::bool(true, Span::test_data()));

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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("constant records should lower through naturally aligned rodata");

    let mut expected = Vec::new();
    expected.extend_from_slice(&7i64.to_le_bytes());
    expected.push(1);
    expected.extend_from_slice(&[0u8; 7]);

    assert_eq!(result.readonly_globals.len(), 1);
    assert_eq!(result.readonly_globals[0].data, expected);

    let record_ty = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::LoadGlobal { ty, .. } => Some(ty),
            _ => None,
        })
        .expect("expected constant record to load from rodata");
    let MirType::Struct { fields, .. } = record_ty else {
        panic!("expected record rodata type, got {record_ty:?}");
    };
    let user_fields = fields
        .iter()
        .filter(|field| !field.synthetic)
        .collect::<Vec<_>>();
    assert_eq!(user_fields.len(), 2);
    assert_eq!(user_fields[0].name, "pid");
    assert_eq!(user_fields[0].offset, 0);
    assert_eq!(user_fields[1].name, "ok");
    assert_eq!(user_fields[1].offset, 8);
    assert_eq!(record_ty.size(), 16);
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
                MirInst::LoadGlobal { symbol, .. }
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
fn test_lower_load_value_numeric_list_uses_readonly_global_payload() {
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
    let readonly_load_count = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::LoadGlobal { .. }))
        .count();
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
        result.readonly_globals.len(),
        1,
        "expected numeric constant list lowering to emit one readonly global"
    );
    assert_eq!(
        readonly_load_count, 1,
        "expected numeric constant list lowering to load from readonly globals"
    );
    assert_eq!(
        list_push_count, 0,
        "expected numeric constant list lowering to avoid ListPush materialization"
    );
}

#[test]
fn test_lower_load_value_unsupported_non_numeric_list_is_rejected() {
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
    .expect_err("lists with unsupported fixed-array elements should remain unsupported");

    assert!(
        err.to_string()
            .contains("constant fixed arrays require homogeneous element layouts")
    );
}

#[test]
fn test_lower_load_value_record_list_uses_fixed_array_readonly_global() {
    let mut first = Record::new();
    first.push("pid", Value::int(7, Span::test_data()));
    first.push("cpu", Value::int(2, Span::test_data()));

    let mut second = Record::new();
    second.push("pid", Value::int(9, Span::test_data()));
    second.push("cpu", Value::int(3, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadValue {
                dst: RegId::new(0),
                val: Box::new(Value::list(
                    vec![
                        Value::record(first, Span::test_data()),
                        Value::record(second, Span::test_data()),
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
    .expect("homogeneous record constant lists should lower as fixed-array rodata");

    let mut expected = Vec::new();
    expected.extend_from_slice(&7i64.to_le_bytes());
    expected.extend_from_slice(&2i64.to_le_bytes());
    expected.extend_from_slice(&9i64.to_le_bytes());
    expected.extend_from_slice(&3i64.to_le_bytes());

    assert_eq!(result.readonly_globals.len(), 1);
    assert_eq!(result.readonly_globals[0].data, expected);
    assert!(
        result.program.main.blocks[0]
            .instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::LoadGlobal { .. })),
        "expected fixed-array constant lowering to load from readonly globals"
    );
}

#[test]
fn test_lower_load_value_record_list_with_nested_numeric_lists_uses_fixed_array_readonly_global() {
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

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadValue {
                dst: RegId::new(0),
                val: Box::new(Value::list(
                    vec![
                        Value::record(first, Span::test_data()),
                        Value::record(second, Span::test_data()),
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
    .expect("record fixed arrays with nested numeric-list fields should lower");

    let mut expected = Vec::new();
    expected.extend_from_slice(&2u64.to_le_bytes());
    expected.extend_from_slice(&1i64.to_le_bytes());
    expected.extend_from_slice(&2i64.to_le_bytes());
    expected.extend_from_slice(&2u64.to_le_bytes());
    expected.extend_from_slice(&3i64.to_le_bytes());
    expected.extend_from_slice(&4i64.to_le_bytes());

    assert_eq!(result.readonly_globals.len(), 1);
    assert_eq!(result.readonly_globals[0].data, expected);
}

#[test]
fn test_lower_load_value_record_list_with_nested_string_fields_uses_fixed_array_readonly_global() {
    fn push_string_repr(data: &mut Vec<u8>, value: &str) {
        data.extend_from_slice(&(value.len() as u64).to_le_bytes());
        let mut bytes = [0u8; 16];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        data.extend_from_slice(&bytes);
    }

    let mut first = Record::new();
    first.push("name", Value::string("aa", Span::test_data()));

    let mut second = Record::new();
    second.push("name", Value::string("bb", Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadValue {
                dst: RegId::new(0),
                val: Box::new(Value::list(
                    vec![
                        Value::record(first, Span::test_data()),
                        Value::record(second, Span::test_data()),
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
    .expect("record fixed arrays with nested string fields should lower");

    let mut expected = Vec::new();
    push_string_repr(&mut expected, "aa");
    push_string_repr(&mut expected, "bb");

    assert_eq!(result.readonly_globals.len(), 1);
    assert_eq!(result.readonly_globals[0].data, expected);
}

#[test]
fn test_lower_load_value_record_array_get_then_field_projection() {
    let get_decl = DeclId::new(900);
    let decl_names = HashMap::from([(get_decl, "get".to_string())]);

    let mut first = Record::new();
    first.push("pid", Value::int(7, Span::test_data()));
    first.push("cpu", Value::int(2, Span::test_data()));

    let mut second = Record::new();
    second.push("pid", Value::int(9, Span::test_data()));
    second.push("cpu", Value::int(3, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::list(
                        vec![
                            Value::record(first, Span::test_data()),
                            Value::record(second, Span::test_data()),
                        ],
                        Span::test_data(),
                    )),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("cpu")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(2),
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("get followed by field projection should work on constant record fixed arrays");

    assert_eq!(result.readonly_globals.len(), 1);
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
                    rhs: MirValue::Const(16),
                    ..
                }
            )),
        "expected `get 1` to offset by one fixed-size record element"
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
                    offset: 8,
                    ty: MirType::I64,
                    ..
                }
            )),
        "expected projected `cpu` field to load from the selected record element"
    );
}

#[test]
fn test_lower_load_value_record_array_iterate_projects_field() {
    let mut first = Record::new();
    first.push("pid", Value::int(7, Span::test_data()));
    first.push("cpu", Value::int(2, Span::test_data()));

    let mut second = Record::new();
    second.push("pid", Value::int(9, Span::test_data()));
    second.push("cpu", Value::int(3, Span::test_data()));

    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::list(
                        vec![
                            Value::record(first, Span::test_data()),
                            Value::record(second, Span::test_data()),
                        ],
                        Span::test_data(),
                    )),
                }],
                terminator: HirTerminator::Iterate {
                    dst: RegId::new(1),
                    stream: RegId::new(0),
                    body: HirBlockId(1),
                    end: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("pid")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(1),
                        path: RegId::new(2),
                    },
                ],
                terminator: HirTerminator::Jump {
                    target: HirBlockId(0),
                },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![],
                terminator: HirTerminator::Return { src: RegId::new(1) },
            },
        ],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 3,
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
    .expect("iterate should work on constant record fixed arrays");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| matches!(block.terminator, MirInst::LoopHeader { .. })),
        "expected fixed-array record iteration to emit a bounded loop"
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
                    offset: 0,
                    ty: MirType::I64,
                    ..
                }
            )),
        "expected loop body field projection to load the iterated record pid field"
    );
}

#[test]
fn test_lower_load_value_binary_uses_readonly_global() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadValue {
                dst: RegId::new(0),
                val: Box::new(Value::binary(vec![1, 2, 3], Span::test_data())),
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
    .expect("binary load values should lower through readonly globals");

    assert_eq!(result.readonly_globals.len(), 1);
    assert_eq!(result.readonly_globals[0].data, vec![1, 2, 3]);
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::LoadGlobal { .. })),
        "expected binary load value lowering to use a readonly global"
    );
}

#[test]
fn test_lower_load_value_record_with_binary_field_uses_readonly_global() {
    let mut rec = Record::new();
    rec.push("payload", Value::binary(vec![1, 2], Span::test_data()));
    rec.push("pid", Value::int(7, Span::test_data()));

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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("records with binary fields should lower through rodata");

    assert_eq!(result.readonly_globals.len(), 1);
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadGlobal { symbol, .. }
                    if symbol == &result.readonly_globals[0].name
            )),
        "expected binary record lowering to load from the emitted readonly global"
    );
}

#[test]
fn test_lower_load_value_record_with_nested_numeric_list_uses_readonly_global() {
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("records with nested numeric lists should lower through rodata");

    assert_eq!(
        result.readonly_globals.len(),
        1,
        "expected nested numeric record list lowering to emit one readonly global"
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
                MirInst::LoadGlobal { symbol, .. }
                    if symbol == &result.readonly_globals[0].name
            )),
        "expected nested numeric record list lowering to load from the emitted readonly global"
    );
}

#[test]
fn test_lower_load_value_record_with_nested_record_list_uses_readonly_global() {
    let mut first = Record::new();
    first.push("pid", Value::int(7, Span::test_data()));
    first.push("cpu", Value::int(2, Span::test_data()));

    let mut second = Record::new();
    second.push("pid", Value::int(9, Span::test_data()));
    second.push("cpu", Value::int(3, Span::test_data()));

    let mut rec = Record::new();
    rec.push(
        "entries",
        Value::list(
            vec![
                Value::record(first, Span::test_data()),
                Value::record(second, Span::test_data()),
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("records with nested homogeneous record lists should lower through rodata");

    let mut expected = Vec::new();
    expected.extend_from_slice(&7i64.to_le_bytes());
    expected.extend_from_slice(&2i64.to_le_bytes());
    expected.extend_from_slice(&9i64.to_le_bytes());
    expected.extend_from_slice(&3i64.to_le_bytes());

    assert_eq!(result.readonly_globals.len(), 1);
    assert_eq!(result.readonly_globals[0].data, expected);
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
                MirInst::LoadGlobal { symbol, .. }
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
fn test_lower_captured_record_with_nested_numeric_list_uses_readonly_global() {
    let capture_var = VarId::new(31);

    let mut rec = Record::new();
    rec.push(
        "numbers",
        Value::list(
            vec![
                Value::int(1, Span::test_data()),
                Value::duration(2, Span::test_data()),
                Value::bool(true, Span::test_data()),
            ],
            Span::test_data(),
        ),
    );

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
        vec![(capture_var, Value::record(rec, Span::test_data()))],
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
    .expect("captured records with nested numeric lists should lower through rodata");

    assert_eq!(
        result.readonly_globals.len(),
        1,
        "expected captured nested numeric record list lowering to emit one readonly global"
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
                MirInst::LoadGlobal { symbol, .. }
                    if symbol == &result.readonly_globals[0].name
            )),
        "expected captured nested numeric record list lowering to load from the emitted readonly global"
    );
}

#[test]
fn test_lower_captured_numeric_list_uses_readonly_global_payload() {
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

    let readonly_load_count = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::LoadGlobal { .. }))
        .count();
    let list_push_count = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::ListPush { .. }))
        .count();

    assert_eq!(
        result.readonly_globals.len(),
        1,
        "expected captured numeric list lowering to emit one readonly global"
    );
    assert_eq!(
        readonly_load_count, 1,
        "expected captured numeric list lowering to load from readonly globals"
    );
    assert_eq!(
        list_push_count, 0,
        "expected captured numeric list lowering to avoid ListPush materialization"
    );
}

#[test]
fn test_lower_captured_binary_uses_readonly_global_payload() {
    let capture_var = VarId::new(16);
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
            Value::binary(vec![0x61, 0x62, 0x63, 0], Span::test_data()),
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
    .expect("captured binary should lower through rodata");

    assert_eq!(
        result.readonly_globals.len(),
        1,
        "expected captured binary lowering to emit one readonly global"
    );
    assert_eq!(result.readonly_globals[0].data, vec![0x61, 0x62, 0x63, 0]);
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadGlobal { symbol, .. }
                    if symbol == &result.readonly_globals[0].name
            )),
        "expected captured binary lowering to load from the emitted readonly global"
    );
    assert!(
        result.type_hints.main.values().any(|ty| matches!(
            ty,
            MirType::Ptr {
                address_space: AddressSpace::Map,
                ..
            }
        )),
        "expected captured binary runtime value to be a map-backed pointer"
    );
}

#[test]
fn test_lower_captured_string_uses_stack_string_payload() {
    let capture_var = VarId::new(17);
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
        vec![(capture_var, Value::string("abc", Span::test_data()))],
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
    .expect("captured string should lower as a stack string");

    assert!(
        result.readonly_globals.is_empty(),
        "captured strings should preserve string-literal stack semantics"
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
        "expected captured string lowering to materialize a stack slot"
    );
    assert!(
        result.type_hints.main.values().any(|ty| matches!(
            ty,
            MirType::Ptr {
                address_space: AddressSpace::Stack,
                ..
            }
        )),
        "expected captured string runtime value to be a stack-backed pointer"
    );
}
