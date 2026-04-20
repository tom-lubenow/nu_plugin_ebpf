use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::hir::{
    HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
};
use crate::compiler::mir::{COUNTER_MAP_NAME, StructField};
use nu_protocol::ast::{CellPath, PathMember};
use nu_protocol::casing::Casing;
use nu_protocol::{Record, RegId, Span, Value, VarId};
use std::collections::HashMap;

fn string_member(name: &str) -> PathMember {
    PathMember::test_string(name.to_string(), false, Casing::Sensitive)
}

#[test]
fn test_lower_mutated_captured_int_variable_uses_data_global() {
    let capture_var = VarId::new(17);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: capture_var,
                },
                HirStmt::StoreVariable {
                    var_id: capture_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(1),
                    var_id: capture_var,
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
    .expect("mutated captured integer should lower through a writable global");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);

    let symbol = &result.data_globals[0].name;
    let global_load_count = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::LoadGlobal { symbol: inst_symbol, .. }
                    if inst_symbol == symbol
            )
        })
        .count();

    assert!(
        global_load_count >= 2,
        "expected mutable captured string lowering to load the backing global for both load/store paths"
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
                MirInst::Store {
                    ty: MirType::I64,
                    ..
                }
            )),
        "expected mutable captured integer lowering to emit a store to the writable global"
    );
}

#[test]
fn test_lower_mutated_zero_captured_int_variable_uses_bss_global() {
    let capture_var = VarId::new(18);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: capture_var,
                },
                HirStmt::StoreVariable {
                    var_id: capture_var,
                    src: RegId::new(0),
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
        vec![(capture_var, Value::int(0, Span::test_data()))],
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
    .expect("mutated zero captured integer should lower through bss");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
}

#[test]
fn test_lower_mutated_captured_string_variable_uses_data_global() {
    let capture_var = VarId::new(19);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: capture_var,
                },
                HirStmt::StoreVariable {
                    var_id: capture_var,
                    src: RegId::new(0),
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
        vec![(capture_var, Value::string("bad", Span::test_data()))],
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
    .expect("mutated captured strings should lower through a writable global");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);

    let symbol = &result.data_globals[0].name;
    let global_load_count = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::LoadGlobal { symbol: inst_symbol, .. }
                    if inst_symbol == symbol
            )
        })
        .count();

    assert!(
        global_load_count >= 2,
        "expected mutable captured string lowering to load the backing global for both load/store paths"
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
        "expected mutable captured string lowering to materialize a stack string buffer"
    );
}

#[test]
fn test_lower_mutated_empty_captured_string_variable_uses_bss_global() {
    let capture_var = VarId::new(26);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: capture_var,
                },
                HirStmt::StoreVariable {
                    var_id: capture_var,
                    src: RegId::new(0),
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
        vec![(capture_var, Value::string("", Span::test_data()))],
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
    .expect("mutated empty captured string should lower through bss");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
}

#[test]
fn test_lower_mutated_captured_string_variable_rejects_non_string_store() {
    let capture_var = VarId::new(27);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::StoreVariable {
                    var_id: capture_var,
                    src: RegId::new(0),
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
        vec![(capture_var, Value::string("seed", Span::test_data()))],
        None,
    );

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err(
        "storing a scalar into mutable captured string should require a materialized string",
    );

    assert!(
        err.to_string()
            .contains("requires a materialized string value with tracked length")
    );
}

#[test]
fn test_lower_mutated_captured_numeric_list_variable_uses_data_global() {
    let capture_var = VarId::new(23);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: capture_var,
                },
                HirStmt::StoreVariable {
                    var_id: capture_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(1),
                    var_id: capture_var,
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
    .expect("mutated captured numeric list should lower through a writable global");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);

    let symbol = &result.data_globals[0].name;
    let global_load_count = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::LoadGlobal { symbol: inst_symbol, .. }
                    if inst_symbol == symbol
            )
        })
        .count();

    assert_eq!(global_load_count, 3);
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
        "expected mutable captured numeric list loading to materialize a stack list buffer"
    );
}

#[test]
fn test_lower_mutated_empty_captured_numeric_list_variable_uses_bss_global() {
    let capture_var = VarId::new(24);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: capture_var,
                },
                HirStmt::StoreVariable {
                    var_id: capture_var,
                    src: RegId::new(0),
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
        vec![(capture_var, Value::list(Vec::new(), Span::test_data()))],
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
    .expect("mutated empty captured numeric list should lower through bss");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
}

#[test]
fn test_lower_mutated_captured_non_numeric_list_variable_is_rejected() {
    let capture_var = VarId::new(25);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: capture_var,
                },
                HirStmt::StoreVariable {
                    var_id: capture_var,
                    src: RegId::new(0),
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
        vec![(
            capture_var,
            Value::list(
                vec![Value::string("bad", Span::test_data())],
                Span::test_data(),
            ),
        )],
        None,
    );

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("mutated captured non-numeric lists should remain unsupported");

    assert!(
        err.to_string()
            .contains(
                "mutable captured globals currently only support numeric scalar values, strings, fixed binary values, numeric constant lists, and representable constant records"
            )
    );
}

#[test]
fn test_lower_mutated_captured_binary_variable_uses_data_global() {
    let capture_var = VarId::new(40);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: capture_var,
                },
                HirStmt::StoreVariable {
                    var_id: capture_var,
                    src: RegId::new(0),
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
        vec![(capture_var, Value::binary(vec![1, 2, 3], Span::test_data()))],
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
    .expect("mutated captured binary should lower through a writable global");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);

    let symbol = &result.data_globals[0].name;
    let global_load_count = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::LoadGlobal { symbol: inst_symbol, .. }
                    if inst_symbol == symbol
            )
        })
        .count();

    assert_eq!(global_load_count, 2);
}

#[test]
fn test_lower_global_set_and_get_nonzero_scalar_uses_named_data_global() {
    let get_decl = DeclId::new(90);
    let set_decl = DeclId::new(91);
    let decl_names = HashMap::from([
        (get_decl, "global-get".to_string()),
        (set_decl, "global-set".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_pid".into()),
                },
                HirStmt::Call {
                    decl_id: set_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-get/global-set scalar flow should lower");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_pid");
    assert_eq!(result.data_globals[0].data, 7i64.to_le_bytes().to_vec());

    let global_load_count = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::LoadGlobal { symbol, .. } if symbol == "__nu_global_seen_pid"
            )
        })
        .count();
    assert_eq!(global_load_count, 2);
}

#[test]
fn test_lower_global_set_and_get_zero_scalar_uses_named_bss_global() {
    let get_decl = DeclId::new(96);
    let set_decl = DeclId::new(97);
    let decl_names = HashMap::from([
        (get_decl, "global-get".to_string()),
        (set_decl, "global-set".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_zero".into()),
                },
                HirStmt::Call {
                    decl_id: set_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("zero-valued global-get/global-set scalar flow should lower");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_global_seen_zero");
}

#[test]
fn test_lower_global_set_and_get_string_materializes_string_slot() {
    let get_decl = DeclId::new(92);
    let set_decl = DeclId::new(93);
    let decl_names = HashMap::from([
        (get_decl, "global-get".to_string()),
        (set_decl, "global-set".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("hello".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_name".into()),
                },
                HirStmt::Call {
                    decl_id: set_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-get/global-set string flow should lower");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
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
        "expected global-get on string global to materialize a stack string slot"
    );
}

#[test]
fn test_lower_global_set_and_get_record_string_field_materializes_string_slot() {
    let capture_var = VarId::new(300);
    let get_decl = DeclId::new(94);
    let set_decl = DeclId::new(95);
    let decl_names = HashMap::from([
        (get_decl, "global-get".to_string()),
        (set_decl, "global-set".to_string()),
    ]);

    let mut record = Record::new();
    record.push("msg", Value::string("hi", Span::test_data()));
    record.push("pid", Value::int(0, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: capture_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_state".into()),
                },
                HirStmt::Call {
                    decl_id: set_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("msg")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(2),
                    path: RegId::new(3),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::String("!".into()),
                },
                HirStmt::StringAppend {
                    src_dst: RegId::new(2),
                    val: RegId::new(4),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(2) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 5,
        file_count: 0,
    };
    let hir = HirProgram::new(
        func,
        HashMap::new(),
        vec![(capture_var, Value::record(record, Span::test_data()))],
        None,
    );

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-get/global-set record string field should lower as a stack-backed string");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected global-get on record string field to materialize a stack string slot"
    );
}

#[test]
fn test_lower_global_set_from_runtime_record_value_preserves_string_field_semantics() {
    let define_decl = DeclId::new(201);
    let get_decl = DeclId::new(202);
    let set_decl = DeclId::new(203);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
        (set_decl, "global-set".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("src_state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("record{msg:string:15,pid:i64}".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("dst_state".into()),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: set_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(3)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(3)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("msg")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(5),
                    path: RegId::new(6),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::String("!".into()),
                },
                HirStmt::StringAppend {
                    src_dst: RegId::new(5),
                    val: RegId::new(7),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(5) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 8,
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
    .expect("runtime global-set record reexport should preserve string field semantics");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected runtime global-set/global-get record string field to materialize a stack string slot"
    );
}

#[test]
fn test_lower_global_set_from_runtime_record_value_preserves_list_field_semantics() {
    let define_decl = DeclId::new(204);
    let global_get_decl = DeclId::new(205);
    let global_set_decl = DeclId::new(206);
    let get_decl = DeclId::new(207);
    let count_decl = DeclId::new(208);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (global_set_decl, "global-set".to_string()),
        (get_decl, "get".to_string()),
        (count_decl, "count".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("src_state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("record{vals:list:i64:2,pid:i64}".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("dst_state".into()),
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_set_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(3)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(3)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("vals")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(5),
                    path: RegId::new(6),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(7)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: count_decl,
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
        register_count: 8,
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
    .expect("runtime global-set record reexport should preserve list field semantics");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListGet { .. })),
        "expected runtime global-set/global-get record list field to lower through ListGet"
    );
}

#[test]
fn test_lower_global_define_and_get_record_list_field_supports_get() {
    let capture_var = VarId::new(301);
    let define_decl = DeclId::new(96);
    let global_get_decl = DeclId::new(97);
    let get_decl = DeclId::new(98);
    let count_decl = DeclId::new(99);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (get_decl, "get".to_string()),
        (count_decl, "count".to_string()),
    ]);

    let mut record = Record::new();
    record.push(
        "vals",
        Value::list(
            vec![
                Value::int(11, Span::test_data()),
                Value::int(22, Span::test_data()),
            ],
            Span::test_data(),
        ),
    );
    record.push("pid", Value::int(0, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: capture_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_state".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("vals")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(2),
                    path: RegId::new(3),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        ..Default::default()
                    },
                },
                HirStmt::Call {
                    decl_id: count_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(2) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 5,
        file_count: 0,
    };
    let hir = HirProgram::new(
        func,
        HashMap::new(),
        vec![(capture_var, Value::record(record, Span::test_data()))],
        None,
    );

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-define/global-get record list field should lower as a stack-backed list");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListGet { .. })),
        "expected global-get on record list field to lower through ListGet"
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
        "expected global-get list field result to be typed as a scalar key"
    );
}

#[test]
fn test_lower_global_define_and_get_nonzero_scalar_uses_named_data_global() {
    let define_decl = DeclId::new(98);
    let get_decl = DeclId::new(99);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_pid".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-define/global-get scalar flow should lower");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_pid");
    assert_eq!(result.data_globals[0].data, 7i64.to_le_bytes().to_vec());

    let global_load_count = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::LoadGlobal { symbol, .. } if symbol == "__nu_global_seen_pid"
            )
        })
        .count();
    assert_eq!(global_load_count, 1);
}

#[test]
fn test_lower_global_get_before_later_global_define_uses_named_data_global() {
    let get_decl = DeclId::new(100);
    let define_decl = DeclId::new(101);
    let decl_names = HashMap::from([
        (get_decl, "global-get".to_string()),
        (define_decl, "global-define".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("state".into()),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("forward global-get/global-define flow should lower");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_state");
    assert_eq!(result.data_globals[0].data, 7i64.to_le_bytes().to_vec());
}

#[test]
fn test_lower_global_define_zero_with_runtime_exemplar_uses_named_bss_global() {
    let define_decl = DeclId::new(104);
    let get_decl = DeclId::new(105);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
    ]);
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
                    lit: HirLiteral::String("seen_pid".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        flags: vec![b"zero".to_vec()],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 6],
        ast: vec![None; 6],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-define --zero with runtime exemplar should lower");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_global_seen_pid");

    let global_load_count = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::LoadGlobal { symbol, .. } if symbol == "__nu_global_seen_pid"
            )
        })
        .count();
    assert_eq!(global_load_count, 1);
}

#[test]
fn test_lower_global_define_type_i64_uses_named_bss_global() {
    let define_decl = DeclId::new(106);
    let get_decl = DeclId::new(107);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("seen_pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("i64".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-define --type i64 should lower");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_global_seen_pid");

    let global_load_count = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::LoadGlobal { symbol, .. } if symbol == "__nu_global_seen_pid"
            )
        })
        .count();
    assert_eq!(global_load_count, 1);
}

#[test]
fn test_lower_global_get_before_later_typed_global_define_uses_named_bss_global() {
    let get_decl = DeclId::new(108);
    let define_decl = DeclId::new(109);
    let decl_names = HashMap::from([
        (get_decl, "global-get".to_string()),
        (define_decl, "global-define".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("state".into()),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("i64".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(2))],
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
        register_count: 4,
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
    .expect("forward global-get/global-define --type flow should lower");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_global_state");
}

#[test]
fn test_lower_global_get_before_later_typed_global_define_with_constant_upsert_uses_named_data_global(
) {
    let get_decl = DeclId::new(1070);
    let define_decl = DeclId::new(1071);
    let decl_names = HashMap::from([
        (get_decl, "global-get".to_string()),
        (define_decl, "global-define".to_string()),
    ]);

    let mut seed = Record::with_capacity(1);
    seed.push("pid", Value::int(0, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::record(seed, Span::test_data())),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("pid")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(8),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("state".into()),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(3)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String("record{pid:i64}".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(3)],
                        named: vec![(b"type".to_vec(), RegId::new(5))],
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
        register_count: 6,
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
    .expect("forward global-get/global-define --type with constant upsert should lower");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_state");
    assert_eq!(result.data_globals[0].data, 8i64.to_le_bytes().to_vec());
}

#[test]
fn test_lower_global_define_type_i64_with_constant_initializer_uses_named_data_global() {
    let define_decl = DeclId::new(1070);
    let get_decl = DeclId::new(1071);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("i64".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        named: vec![(b"type".to_vec(), RegId::new(2))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-define --type i64 with constant input should lower");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_pid");
    assert_eq!(result.data_globals[0].data, 7i64.to_le_bytes().to_vec());
}

#[test]
fn test_lower_global_define_type_i64_with_constant_binary_initializer_uses_named_data_global() {
    let define_decl = DeclId::new(1072);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(3),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(4),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: nu_protocol::ast::Operator::Math(nu_protocol::ast::Math::Add),
                    rhs: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("sum".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("i64".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        named: vec![(b"type".to_vec(), RegId::new(3))],
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
        register_count: 4,
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
    .expect("global-define --type i64 with constant binary input should lower");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_sum");
    assert_eq!(result.data_globals[0].data, 7i64.to_le_bytes().to_vec());
}

#[test]
fn test_lower_global_define_type_record_with_constant_upsert_initializer_uses_named_data_global() {
    let define_decl = DeclId::new(1073);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

    let mut seed = Record::with_capacity(1);
    seed.push("pid", Value::int(0, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::record(seed, Span::test_data())),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("pid")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(8),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                    new_value: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::String("record{pid:i64}".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(3)],
                        named: vec![(b"type".to_vec(), RegId::new(4))],
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
        register_count: 5,
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
    .expect("global-define --type record{...} with constant upsert input should lower");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_state");
    assert_eq!(result.data_globals[0].data, 8i64.to_le_bytes().to_vec());
}

#[test]
fn test_lower_global_define_type_i64_with_constant_follow_cell_path_initializer_uses_named_data_global(
) {
    let define_decl = DeclId::new(1078);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

    let mut seed = Record::with_capacity(1);
    seed.push("pid", Value::int(7, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::record(seed, Span::test_data())),
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
                    lit: HirLiteral::String("seen_pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("i64".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        named: vec![(b"type".to_vec(), RegId::new(3))],
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
        register_count: 4,
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
    .expect("global-define --type i64 with constant follow-cell-path input should lower");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_pid");
    assert_eq!(result.data_globals[0].data, 7i64.to_le_bytes().to_vec());
}

#[test]
fn test_lower_global_define_type_record_from_metadata_builder_uses_named_data_global() {
    let define_decl = DeclId::new(1074);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Record { capacity: 1 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(0),
                    key: RegId::new(1),
                    val: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::String("record{pid:i64}".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(3)],
                        named: vec![(b"type".to_vec(), RegId::new(4))],
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
        register_count: 5,
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
    .expect("global-define --type record{...} with metadata-only record builder should lower");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_state");
    assert_eq!(result.data_globals[0].data, 7i64.to_le_bytes().to_vec());
}

#[test]
fn test_lower_global_define_type_string_with_constant_string_append_initializer_uses_named_data_global(
) {
    let define_decl = DeclId::new(1079);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("hel".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("lo".into()),
                },
                HirStmt::StringAppend {
                    src_dst: RegId::new(0),
                    val: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("greeting".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("string:8".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        named: vec![(b"type".to_vec(), RegId::new(3))],
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
        register_count: 4,
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
    .expect("global-define --type string:N with constant string append input should lower");

    let mut expected = vec![0u8; 24];
    expected[..8].copy_from_slice(&(5u64).to_le_bytes());
    expected[8..13].copy_from_slice(b"hello");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_greeting");
    assert_eq!(result.data_globals[0].data, expected);
}

#[test]
fn test_lower_global_define_type_list_from_metadata_builder_uses_named_data_global() {
    let define_decl = DeclId::new(1075);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::List { capacity: 4 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(11),
                },
                HirStmt::ListPush {
                    src_dst: RegId::new(0),
                    item: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(22),
                },
                HirStmt::ListPush {
                    src_dst: RegId::new(0),
                    item: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("samples".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::String("list:i64:4".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(3)],
                        named: vec![(b"type".to_vec(), RegId::new(4))],
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
        register_count: 5,
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
    .expect("global-define --type list:i64:N with metadata-only list builder should lower");

    let mut expected = Vec::new();
    expected.extend_from_slice(&(2u64).to_le_bytes());
    expected.extend_from_slice(&11i64.to_le_bytes());
    expected.extend_from_slice(&22i64.to_le_bytes());
    expected.extend_from_slice(&0i64.to_le_bytes());
    expected.extend_from_slice(&0i64.to_le_bytes());

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_samples");
    assert_eq!(result.data_globals[0].data, expected);
}

#[test]
fn test_lower_global_define_type_record_with_list_initializer_uses_named_data_global() {
    let define_decl = DeclId::new(1076);
    let get_decl = DeclId::new(1077);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
    ]);

    let mut state = Record::with_capacity(2);
    state.push("pid", Value::int(7, Span::test_data()));
    state.push(
        "samples",
        Value::list(
            vec![
                Value::int(11, Span::test_data()),
                Value::int(22, Span::test_data()),
            ],
            Span::test_data(),
        ),
    );

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::record(state, Span::test_data())),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("record{pid:i64,samples:list:i64:4}".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        named: vec![(b"type".to_vec(), RegId::new(2))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-define --type record{...} with constant input should lower");

    let mut expected = Vec::new();
    expected.extend_from_slice(&7i64.to_le_bytes());
    expected.extend_from_slice(&(2u64).to_le_bytes());
    expected.extend_from_slice(&11i64.to_le_bytes());
    expected.extend_from_slice(&22i64.to_le_bytes());
    expected.extend_from_slice(&0i64.to_le_bytes());
    expected.extend_from_slice(&0i64.to_le_bytes());

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_state");
    assert_eq!(result.data_globals[0].data, expected);
}

#[test]
fn test_lower_global_define_type_record_partial_initializer_zero_fills_missing_fields() {
    let define_decl = DeclId::new(1074);
    let get_decl = DeclId::new(1075);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
    ]);

    let mut state = Record::with_capacity(1);
    state.push("pid", Value::int(7, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::record(state, Span::test_data())),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("record{pid:i64,samples:list:i64:2}".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        named: vec![(b"type".to_vec(), RegId::new(2))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-define --type record{...} should zero-fill omitted fields");

    let mut expected = Vec::new();
    expected.extend_from_slice(&7i64.to_le_bytes());
    expected.extend_from_slice(&0u64.to_le_bytes());
    expected.extend_from_slice(&0i64.to_le_bytes());
    expected.extend_from_slice(&0i64.to_le_bytes());

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_state");
    assert_eq!(result.data_globals[0].data, expected);
}

#[test]
fn test_lower_global_define_type_string_rejects_initializer_exceeding_capacity() {
    let define_decl = DeclId::new(1074);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("abcdef".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_name".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("string:4".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        named: vec![(b"type".to_vec(), RegId::new(2))],
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
        register_count: 3,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("oversized typed string initializer should be rejected");

    assert!(
        err.to_string().contains("capacity is 4"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_global_define_type_duration_and_filesize_use_i64_bss_globals() {
    let define_decl = DeclId::new(1100);
    let get_decl = DeclId::new(1101);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("seen_elapsed".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("duration".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("seen_size".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::String("filesize".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(3)],
                        named: vec![(b"type".to_vec(), RegId::new(4))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        positional: vec![RegId::new(3)],
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-define --type duration/filesize should lower");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 2);
    assert!(
        result
            .bss_globals
            .iter()
            .any(|global| global.name == "__nu_global_seen_elapsed" && global.size == 8)
    );
    assert!(
        result
            .bss_globals
            .iter()
            .any(|global| global.name == "__nu_global_seen_size" && global.size == 8)
    );
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
        "expected duration/filesize typed globals to load as i64-backed globals"
    );
}

#[test]
fn test_lower_global_define_type_string_materializes_string_slot() {
    let define_decl = DeclId::new(110);
    let get_decl = DeclId::new(111);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("seen_name".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("string:32".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-define --type string:N should lower");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_global_seen_name");
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
        "expected global-get on typed string global to materialize a stack string slot"
    );
}

#[test]
fn test_lower_global_define_type_list_i64_uses_named_bss_global() {
    let define_decl = DeclId::new(112);
    let get_decl = DeclId::new(113);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("seen_hist".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("list:i64:4".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-define --type list:i64:N should lower");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_global_seen_hist");
    assert_eq!(result.bss_globals[0].size, 5 * std::mem::size_of::<i64>());

    let global_load_count = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::LoadGlobal { symbol, .. } if symbol == "__nu_global_seen_hist"
            )
        })
        .count();
    assert_eq!(global_load_count, 1);
}

#[test]
fn test_lower_global_define_type_record_uses_named_bss_global() {
    let define_decl = DeclId::new(114);
    let get_decl = DeclId::new(115);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("seen_state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("record{pid:i64,comm:bytes:16}".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-define --type record{...} should lower");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_global_seen_state");
    assert_eq!(result.bss_globals[0].size, 24);

    let global_load = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::LoadGlobal { symbol, ty, .. } if symbol == "__nu_global_seen_state" => {
                Some(ty.clone())
            }
            _ => None,
        })
        .expect("expected typed global load for record global");

    assert_eq!(
        global_load,
        MirType::Struct {
            name: None,
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "pid".into(),
                    ty: MirType::I64,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "comm".into(),
                    ty: MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: 16,
                    },
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        }
    );
}

#[test]
fn test_lower_global_define_type_record_supports_field_projection() {
    let define_decl = DeclId::new(116);
    let get_decl = DeclId::new(117);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("seen_state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("record{pid:i64,uid:u32}".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
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
        spans: vec![Span::test_data(); 6],
        ast: vec![None; 6],
        comments: vec![],
        register_count: 5,
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
    .expect("global-define --type record{...} field projection should lower");

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
        "expected field projection to load the pid field at offset 0"
    );
}

#[test]
fn test_lower_global_define_type_record_string_field_supports_string_append() {
    let define_decl = DeclId::new(118);
    let get_decl = DeclId::new(119);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("seen_state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("record{msg:string:15,pid:i64}".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("msg")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String("!".into()),
                },
                HirStmt::StringAppend {
                    src_dst: RegId::new(3),
                    val: RegId::new(5),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 6,
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
    .expect("global-define --type record{...} string field should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected typed record global string field to materialize a stack string slot"
    );
}

#[test]
fn test_lower_global_define_type_record_list_field_supports_get() {
    let define_decl = DeclId::new(120);
    let global_get_decl = DeclId::new(121);
    let get_decl = DeclId::new(122);
    let count_decl = DeclId::new(123);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (get_decl, "get".to_string()),
        (count_decl, "count".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("seen_state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("record{vals:list:i64:2,pid:i64}".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("vals")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5)],
                        ..Default::default()
                    },
                },
                HirStmt::Call {
                    decl_id: count_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 6,
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
    .expect("global-define --type record{...} list field should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListGet { .. })),
        "expected typed record global list field to lower through ListGet"
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
        "expected typed record global list field result to be typed as a scalar key"
    );
}

#[test]
fn test_lower_global_define_type_nested_record_string_field_supports_string_append() {
    let define_decl = DeclId::new(124);
    let get_decl = DeclId::new(125);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("seen_state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(
                        "record{inner:record{msg:string:15,pid:i64},cpu:u32}".into(),
                    ),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("inner"), string_member("msg")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String("!".into()),
                },
                HirStmt::StringAppend {
                    src_dst: RegId::new(3),
                    val: RegId::new(5),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(3) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 6,
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
    .expect("global-define --type nested record string field should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected nested typed record global string field to materialize a stack string slot"
    );
}

#[test]
fn test_lower_global_get_before_later_record_typed_global_define_uses_named_bss_global() {
    let get_decl = DeclId::new(118);
    let define_decl = DeclId::new(119);
    let decl_names = HashMap::from([
        (get_decl, "global-get".to_string()),
        (define_decl, "global-define".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("state".into()),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("record{pid:i64}".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(2))],
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
        register_count: 4,
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
    .expect("forward global-get/global-define --type record{...} flow should lower");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_global_state");
    assert_eq!(result.bss_globals[0].size, 8);
}

#[test]
fn test_lower_global_get_before_later_constant_set_uses_named_bss_global() {
    let get_decl = DeclId::new(94);
    let set_decl = DeclId::new(95);
    let decl_names = HashMap::from([
        (get_decl, "global-get".to_string()),
        (set_decl, "global-set".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("state".into()),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::Call {
                    decl_id: set_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("forward global-get/global-set flow should lower");

    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_global_state");
}

#[test]
fn test_lower_global_get_without_any_same_program_set_is_rejected() {
    let get_decl = DeclId::new(102);
    let decl_names = HashMap::from([(get_decl, "global-get".to_string())]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("state".into()),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("global-get without any same-program global-set should be rejected");

    assert!(
        err.to_string()
            .contains("requires a same-program global-define or layout-establishing global-set")
    );
}

#[test]
fn test_lower_global_set_rejects_conflicting_layouts() {
    let set_decl = DeclId::new(103);
    let decl_names = HashMap::from([(set_decl, "global-set".to_string())]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("state".into()),
                },
                HirStmt::Call {
                    decl_id: set_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("oops".into()),
                },
                HirStmt::Call {
                    decl_id: set_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("conflicting global layouts should be rejected");

    assert!(
        err.to_string()
            .contains("global 'state' is used with incompatible layouts")
    );
}

#[test]
fn test_lower_mutated_zero_filled_captured_binary_variable_uses_bss_global() {
    let capture_var = VarId::new(41);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: capture_var,
                },
                HirStmt::StoreVariable {
                    var_id: capture_var,
                    src: RegId::new(0),
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
        vec![(capture_var, Value::binary(vec![0, 0, 0], Span::test_data()))],
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
    .expect("zero-filled captured binary should lower through bss");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
}

#[test]
fn test_lower_mutated_captured_record_variable_uses_data_global() {
    let capture_var = VarId::new(20);
    let mut record = Record::new();
    record.push("pid", Value::int(7, Span::test_data()));
    record.push("ok", Value::bool(true, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: capture_var,
                },
                HirStmt::StoreVariable {
                    var_id: capture_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(1),
                    var_id: capture_var,
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
    let hir = HirProgram::new(
        func,
        HashMap::new(),
        vec![(capture_var, Value::record(record, Span::test_data()))],
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
    .expect("mutated captured record should lower through a writable global");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);

    let symbol = &result.data_globals[0].name;
    let global_load_count = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::LoadGlobal { symbol: inst_symbol, .. }
                    if inst_symbol == symbol
            )
        })
        .count();

    assert_eq!(global_load_count, 3);
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::Store { .. })),
        "expected mutable captured record lowering to emit stores into the writable global"
    );
}

#[test]
fn test_lower_mutated_zero_captured_record_variable_uses_bss_global() {
    let capture_var = VarId::new(21);
    let mut record = Record::new();
    record.push("pid", Value::int(0, Span::test_data()));
    record.push("ok", Value::bool(false, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: capture_var,
                },
                HirStmt::StoreVariable {
                    var_id: capture_var,
                    src: RegId::new(0),
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
        vec![(capture_var, Value::record(record, Span::test_data()))],
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
    .expect("mutated zero captured record should lower through bss");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
}

#[test]
fn test_lower_mutated_captured_record_field_update_uses_global_backing() {
    let capture_var = VarId::new(210);
    let mut record = Record::new();
    record.push("pid", Value::int(0, Span::test_data()));
    record.push("ok", Value::bool(false, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(9),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(1),
                    var_id: capture_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("pid")],
                    })),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(1),
                    path: RegId::new(2),
                    new_value: RegId::new(0),
                },
                HirStmt::StoreVariable {
                    var_id: capture_var,
                    src: RegId::new(1),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(3),
                    var_id: capture_var,
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
    let hir = HirProgram::new(
        func,
        HashMap::new(),
        vec![(capture_var, Value::record(record, Span::test_data()))],
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
    .expect("mutated captured record field update should lower through writable globals");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::Store {
                    offset: 0,
                    ty: MirType::I64,
                    ..
                }
            )),
        "expected field update to emit a direct store to the pid field in the writable global"
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
        "expected reloading the record field after update to load the pid field"
    );
}

#[test]
fn test_lower_mutated_captured_record_list_field_supports_get() {
    let capture_var = VarId::new(212);
    let get_decl = DeclId::new(902);
    let count_decl = DeclId::new(903);

    let mut record = Record::new();
    record.push(
        "vals",
        Value::list(
            vec![
                Value::int(11, Span::test_data()),
                Value::int(22, Span::test_data()),
            ],
            Span::test_data(),
        ),
    );
    record.push("pid", Value::int(0, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: capture_var,
                },
                HirStmt::StoreVariable {
                    var_id: capture_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(1),
                    var_id: capture_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("vals")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(1),
                    path: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(3)],
                        ..Default::default()
                    },
                },
                HirStmt::Call {
                    decl_id: count_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(1) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(
        func,
        HashMap::new(),
        vec![(capture_var, Value::record(record, Span::test_data()))],
        None,
    );

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
    .expect("mutated captured record list field should lower as a stack-backed list value");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListGet { .. })),
        "expected projected captured-global list field to lower through ListGet"
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
fn test_lower_mutated_captured_record_string_field_supports_string_append() {
    let capture_var = VarId::new(213);

    let mut record = Record::new();
    record.push("msg", Value::string("hi", Span::test_data()));
    record.push("pid", Value::int(0, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: capture_var,
                },
                HirStmt::StoreVariable {
                    var_id: capture_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(1),
                    var_id: capture_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("msg")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(1),
                    path: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("!".into()),
                },
                HirStmt::StringAppend {
                    src_dst: RegId::new(1),
                    val: RegId::new(3),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(1) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };
    let hir = HirProgram::new(
        func,
        HashMap::new(),
        vec![(capture_var, Value::record(record, Span::test_data()))],
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
    .expect("mutated captured record string field should lower as a stack-backed string value");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected projected captured-global string field to lower through StringAppend"
    );
}

#[test]
fn test_lower_local_record_field_update_materializes_stack_backing() {
    let state_var = VarId::new(211);
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
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(0),
                    key: RegId::new(1),
                    val: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("ok".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Bool(false),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(0),
                    key: RegId::new(3),
                    val: RegId::new(4),
                },
                HirStmt::StoreVariable {
                    var_id: state_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(5),
                    var_id: state_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("pid")],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::Int(9),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(5),
                    path: RegId::new(6),
                    new_value: RegId::new(7),
                },
                HirStmt::StoreVariable {
                    var_id: state_var,
                    src: RegId::new(5),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(8),
                    var_id: state_var,
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(8),
                    path: RegId::new(6),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(8) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 9,
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
    .expect("local record field update should lower through a materialized stack record");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StoreSlot {
                    offset: 0,
                    ty: MirType::I64,
                    ..
                }
            )),
        "expected local record materialization to initialize the pid field in a stack slot"
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
                MirInst::Store {
                    offset: 0,
                    ty: MirType::I64,
                    ..
                }
            )),
        "expected field update to emit an in-place store to the materialized stack record"
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
        "expected reloading the local record field after update to load the pid field"
    );
}

#[test]
fn test_lower_local_nested_record_field_update_accepts_metadata_only_record_rhs() {
    let state_var = VarId::new(213);
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
                    lit: HirLiteral::Int(0),
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
                HirStmt::StoreVariable {
                    var_id: state_var,
                    src: RegId::new(5),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(9),
                    var_id: state_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(10),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(11),
                    lit: HirLiteral::String("msg".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(12),
                    lit: HirLiteral::String("bye".into()),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(10),
                    key: RegId::new(11),
                    val: RegId::new(12),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(13),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(14),
                    lit: HirLiteral::Int(9),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(10),
                    key: RegId::new(13),
                    val: RegId::new(14),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(15),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("inner")],
                    })),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(9),
                    path: RegId::new(15),
                    new_value: RegId::new(10),
                },
                HirStmt::StoreVariable {
                    var_id: state_var,
                    src: RegId::new(9),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(16),
                    var_id: state_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(17),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("inner"), string_member("msg")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(16),
                    path: RegId::new(17),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(18),
                    lit: HirLiteral::String("!".into()),
                },
                HirStmt::StringAppend {
                    src_dst: RegId::new(16),
                    val: RegId::new(18),
                },
            ],
            terminator: HirTerminator::Return {
                src: RegId::new(16),
            },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 19,
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
    .expect("local nested record field update should accept a metadata-only record rhs");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected updated nested record string field to preserve string semantics"
    );
}

#[test]
fn test_lower_local_record_string_field_preserves_semantics() {
    let state_var = VarId::new(212);
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
                    lit: HirLiteral::Int(0),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(0),
                    key: RegId::new(3),
                    val: RegId::new(4),
                },
                HirStmt::StoreVariable {
                    var_id: state_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(5),
                    var_id: state_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("msg")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(5),
                    path: RegId::new(6),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::String("!".into()),
                },
                HirStmt::StringAppend {
                    src_dst: RegId::new(5),
                    val: RegId::new(7),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(5) },
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
    .expect("local record string field should preserve semantics through store/load");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected local record string field to lower through StringAppend"
    );
}

#[test]
fn test_lower_local_record_list_field_preserves_semantics() {
    let state_var = VarId::new(213);
    let get_decl = DeclId::new(215);
    let decl_names = HashMap::from([(get_decl, "get".to_string())]);

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
                    lit: HirLiteral::String("vals".into()),
                },
                HirStmt::LoadValue {
                    dst: RegId::new(2),
                    val: Box::new(Value::list(
                        vec![
                            Value::int(11, Span::test_data()),
                            Value::int(22, Span::test_data()),
                        ],
                        Span::test_data(),
                    )),
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
                    lit: HirLiteral::Int(0),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(0),
                    key: RegId::new(3),
                    val: RegId::new(4),
                },
                HirStmt::StoreVariable {
                    var_id: state_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(5),
                    var_id: state_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("vals")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(5),
                    path: RegId::new(6),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(7)],
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
        register_count: 8,
        file_count: 0,
    };

    let result = lower_hir_to_mir_with_hints(
        &HirProgram::new(func, HashMap::new(), vec![], None),
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("local record list field should preserve semantics through store/load");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListGet { .. })),
        "expected local record list field to lower through ListGet"
    );
}

#[test]
fn test_lower_mutated_captured_record_variable_materializes_metadata_only_record_store() {
    let capture_var = VarId::new(22);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Record { capacity: 1 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(9),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(0),
                    key: RegId::new(1),
                    val: RegId::new(2),
                },
                HirStmt::StoreVariable {
                    var_id: capture_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(3),
                    var_id: capture_var,
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

    let mut capture_record = Record::new();
    capture_record.push("pid", Value::int(1, Span::test_data()));
    let hir = HirProgram::new(
        func,
        HashMap::new(),
        vec![(
            capture_var,
            Value::record(capture_record, Span::test_data()),
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
    .expect("metadata-only record builders should materialize before mutable global stores");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StoreSlot {
                    offset: 0,
                    ty: MirType::I64,
                    ..
                }
            )),
        "expected metadata-only record builder store to materialize the pid field into a stack slot"
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
        "expected reloading the captured global field after store to load the pid field"
    );
}

#[test]
fn test_lower_global_set_from_metadata_only_record_builder_infers_layout_and_preserves_string_semantics()
 {
    let global_get_decl = DeclId::new(216);
    let global_set_decl = DeclId::new(217);
    let decl_names = HashMap::from([
        (global_get_decl, "global-get".to_string()),
        (global_set_decl, "global-set".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("msg".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("hi".into()),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(1),
                    key: RegId::new(2),
                    val: RegId::new(3),
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
                    src_dst: RegId::new(1),
                    key: RegId::new(4),
                    val: RegId::new(5),
                },
                HirStmt::Call {
                    decl_id: global_set_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("msg")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(6),
                    path: RegId::new(7),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(8),
                    lit: HirLiteral::String("!".into()),
                },
                HirStmt::StringAppend {
                    src_dst: RegId::new(6),
                    val: RegId::new(8),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(6) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 9,
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
    .expect("metadata-only record builders should establish named global layout and semantics");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected global-get on metadata-inferred record string field to materialize a stack string slot"
    );
}

#[test]
fn test_lower_global_set_from_nested_metadata_record_builder_preserves_nested_string_semantics() {
    let global_get_decl = DeclId::new(218);
    let global_set_decl = DeclId::new(219);
    let decl_names = HashMap::from([
        (global_get_decl, "global-get".to_string()),
        (global_set_decl, "global-set".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("msg".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("hi".into()),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(1),
                    key: RegId::new(2),
                    val: RegId::new(3),
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
                    src_dst: RegId::new(1),
                    key: RegId::new(4),
                    val: RegId::new(5),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::String("inner".into()),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(6),
                    key: RegId::new(7),
                    val: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(8),
                    lit: HirLiteral::String("cpu".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(9),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(6),
                    key: RegId::new(8),
                    val: RegId::new(9),
                },
                HirStmt::Call {
                    decl_id: global_set_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(10),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(11),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("inner"), string_member("msg")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(10),
                    path: RegId::new(11),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(12),
                    lit: HirLiteral::String("!".into()),
                },
                HirStmt::StringAppend {
                    src_dst: RegId::new(10),
                    val: RegId::new(12),
                },
            ],
            terminator: HirTerminator::Return {
                src: RegId::new(10),
            },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 13,
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
    .expect(
        "nested metadata-only record builders should establish named global layout and semantics",
    );

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected nested metadata-inferred record string field to materialize a stack string slot"
    );
}
