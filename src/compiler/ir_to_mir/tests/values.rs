use super::*;
use crate::compiler::compile_mir_to_ebpf_with_hints;
use crate::compiler::hir::{
    HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
};
use crate::compiler::mir::AddressSpace;
use nu_protocol::ast::{CellPath, PathMember};
use nu_protocol::casing::Casing;
use nu_protocol::{DeclId, Record, RegId, Span, Value, VarId};
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

fn make_numeric_list_skip_then_get_program(
    skip_decl: DeclId,
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
    let skip_positional = if let Some(count) = count {
        stmts.push(HirStmt::LoadLiteral {
            dst: RegId::new(2),
            lit: HirLiteral::Int(count),
        });
        vec![RegId::new(2)]
    } else {
        Vec::new()
    };
    stmts.push(HirStmt::Call {
        decl_id: skip_decl,
        src_dst: RegId::new(1),
        args: HirCallArgs {
            positional: skip_positional,
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

fn make_string_pipeline_call_program(decl_id: DeclId, value: &str) -> HirProgram {
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
fn test_lower_first_count_slice_is_rejected() {
    let first_decl = DeclId::new(80);
    let hir = make_numeric_list_pipeline_call_program(first_decl, Some(1));
    let decl_names = HashMap::from([(first_decl, "first".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("counted first should be rejected rather than silently miscompiled");

    assert!(
        err.to_string().contains("would produce a list slice"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_skip_default_on_numeric_list_rebuilds_tail() {
    let skip_decl = DeclId::new(81);
    let get_decl = DeclId::new(82);
    let hir = make_numeric_list_skip_then_get_program(skip_decl, get_decl, None, 0);
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
    let get_decl = DeclId::new(84);
    let hir = make_numeric_list_skip_then_get_program(skip_decl, get_decl, Some(4), 0);
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
        .expect("empty skip result followed by get should compile through codegen");
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
fn test_lower_is_empty_on_numeric_list_compares_length_to_zero() {
    let is_empty_decl = DeclId::new(90);
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
    let is_empty_decl = DeclId::new(91);
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
fn test_lower_select_on_metadata_record_materializes_requested_layout() {
    let select_decl = DeclId::new(92);
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
    let reject_decl = DeclId::new(93);
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
    let select_decl = DeclId::new(94);
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
