use super::*;
use crate::compiler::hir::{
    HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
};
use crate::compiler::mir::{BinOpKind, COUNTER_MAP_NAME, StructField};
use crate::compiler::{EbpfProgramType, compile_mir_to_ebpf_with_hints};
use nu_protocol::ast::{CellPath, PathMember, Pattern, RangeInclusion};
use nu_protocol::casing::Casing;
use nu_protocol::{Record, RegId, Span, Value, VarId};
use std::collections::HashMap;

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
fn test_lower_mutated_captured_bool_variable_uses_data_global() {
    let capture_var = VarId::new(117);
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
        vec![(capture_var, Value::bool(true, Span::test_data()))],
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
    .expect("mutated captured bool should lower through a writable global");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].data, vec![1]);
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
                    ty: MirType::Bool,
                    ..
                }
            )),
        "expected mutable captured bool lowering to emit a bool store to the writable global"
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
fn test_lower_mutated_captured_heterogeneous_list_variable_is_rejected() {
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
                vec![
                    Value::int(1, Span::test_data()),
                    Value::string("bad", Span::test_data()),
                ],
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
    .expect_err("mutated captured heterogeneous lists should remain unsupported");

    assert!(
        err.to_string()
            .contains(
                "mutable captured globals currently only support bool and numeric scalar values, strings, fixed binary values, numeric constant lists, homogeneous fixed arrays of scalar/string/binary/record constants with fixed-layout fields, and representable constant records"
            )
    );
}

#[test]
fn test_lower_mutated_captured_fixed_record_array_store_and_project_field() {
    let capture_var = VarId::new(26);
    let get_decl = DeclId::new(904);
    let count_decl = DeclId::new(905);
    let decl_names = HashMap::from([
        (get_decl, "get".to_string()),
        (count_decl, "count".to_string()),
    ]);

    let mut initial_first = Record::new();
    initial_first.push("pid", Value::int(7, Span::test_data()));
    initial_first.push("cpu", Value::int(2, Span::test_data()));

    let mut initial_second = Record::new();
    initial_second.push("pid", Value::int(9, Span::test_data()));
    initial_second.push("cpu", Value::int(3, Span::test_data()));

    let mut new_first = Record::new();
    new_first.push("pid", Value::int(11, Span::test_data()));
    new_first.push("cpu", Value::int(4, Span::test_data()));

    let mut new_second = Record::new();
    new_second.push("pid", Value::int(13, Span::test_data()));
    new_second.push("cpu", Value::int(5, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::list(
                        vec![
                            Value::record(new_first, Span::test_data()),
                            Value::record(new_second, Span::test_data()),
                        ],
                        Span::test_data(),
                    )),
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
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(2)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("cpu")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(1),
                    path: RegId::new(3),
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
        vec![(
            capture_var,
            Value::list(
                vec![
                    Value::record(initial_first, Span::test_data()),
                    Value::record(initial_second, Span::test_data()),
                ],
                Span::test_data(),
            ),
        )],
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
    .expect("mutated captured fixed record arrays should lower through writable globals");

    let mut expected_initial = Vec::new();
    expected_initial.extend_from_slice(&7i64.to_le_bytes());
    expected_initial.extend_from_slice(&2i64.to_le_bytes());
    expected_initial.extend_from_slice(&9i64.to_le_bytes());
    expected_initial.extend_from_slice(&3i64.to_le_bytes());

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.data_globals[0].name, "__nu_capture_global_26");
    assert_eq!(result.data_globals[0].data, expected_initial);
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
                MirInst::MapUpdate {
                    map: MapRef { name, .. },
                    ..
                } if name == COUNTER_MAP_NAME
            )),
        "expected projected fixed-array record field to be usable as a scalar key"
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
                        pipeline_input: Some(RegId::new(0)),
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
                        pipeline_input: Some(RegId::new(0)),
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
                        pipeline_input: Some(RegId::new(0)),
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
fn test_lower_global_get_string_concatenates_literal_suffix() {
    let define_decl = DeclId::new(1301);
    let get_decl = DeclId::new(1302);
    let length_decl = DeclId::new(1303);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
        (length_decl, "str length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("left".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("string:8".into()),
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
                    lit: HirLiteral::String("lo".into()),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(3),
                    op: nu_protocol::ast::Operator::Math(nu_protocol::ast::Math::Add),
                    rhs: RegId::new(4),
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-get string should concatenate a literal suffix");

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
                } if bytes.starts_with(b"lo")
            )),
        "expected runtime string concat to append the literal suffix"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("runtime string concat should compile through codegen");
}

#[test]
fn test_lower_global_get_string_compares_literal_equality_and_inequality() {
    let define_decl = DeclId::new(1304);
    let get_decl = DeclId::new(1306);
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
                    lit: HirLiteral::String("left".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("string:8".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("lo".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        pipeline_input: Some(RegId::new(2)),
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
                    lit: HirLiteral::String("lo".into()),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(3),
                    op: nu_protocol::ast::Operator::Comparison(nu_protocol::ast::Comparison::Equal),
                    rhs: RegId::new(4),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::String("no".into()),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(5),
                    op: nu_protocol::ast::Operator::Comparison(
                        nu_protocol::ast::Comparison::NotEqual,
                    ),
                    rhs: RegId::new(6),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(5) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 7,
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
    .expect("global-get string should compare against literals");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { len: 2, .. })),
        "expected runtime string equality/inequality to lower through bounded StrCmp"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("runtime string equality and inequality should compile through codegen");
}

#[test]
fn test_lower_global_get_string_match_literal_pattern() {
    let define_decl = DeclId::new(1307);
    let get_decl = DeclId::new(1308);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::String("left".into()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::String("string:8".into()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String("lo".into()),
                    },
                    HirStmt::Call {
                        decl_id: define_decl,
                        src_dst: RegId::new(2),
                        args: HirCallArgs {
                            positional: vec![RegId::new(0)],
                            named: vec![(b"type".to_vec(), RegId::new(1))],
                            pipeline_input: Some(RegId::new(2)),
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
                terminator: HirTerminator::Match {
                    pattern: Box::new(Pattern::Value(Value::string("lo", Span::test_data()))),
                    src: RegId::new(3),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(10),
                }],
                terminator: HirTerminator::Return { src: RegId::new(4) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(20),
                }],
                terminator: HirTerminator::Return { src: RegId::new(5) },
            },
        ],
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
    .expect("global-get string should match against a literal pattern");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { len: 2, .. })),
        "expected runtime string match to lower through bounded StrCmp"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("runtime string match should compile through codegen");
}

#[test]
fn test_lower_global_get_string_starts_with_guards_runtime_length() {
    let define_decl = DeclId::new(1309);
    let get_decl = DeclId::new(1310);
    let starts_with_decl = DeclId::new(1311);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("left".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("string:8".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("hello".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        pipeline_input: Some(RegId::new(2)),
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
                    lit: HirLiteral::String("hello".into()),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-get string should run str starts-with with a runtime length guard");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { len: 5, .. })),
        "expected runtime starts-with to compare prefix bytes"
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
                    op: BinOpKind::Ge,
                    rhs: MirValue::Const(5),
                    ..
                }
            )),
        "expected runtime starts-with to guard against strings shorter than the prefix"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("runtime starts-with should compile through codegen");
}

#[test]
fn test_lower_global_get_string_ends_with_runtime_length() {
    let define_decl = DeclId::new(1312);
    let get_decl = DeclId::new(1313);
    let ends_with_decl = DeclId::new(1314);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
        (ends_with_decl, "str ends-with".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("left".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("string:8".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("hello".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        pipeline_input: Some(RegId::new(2)),
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
                    lit: HirLiteral::String("lo".into()),
                },
                HirStmt::Call {
                    decl_id: ends_with_decl,
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-get string should run str ends-with using runtime length");

    let comparisons = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::StrCmp { len: 2, .. }))
        .count();
    assert_eq!(
        comparisons, 7,
        "expected runtime ends-with to test each possible suffix offset for string:8"
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
        "expected runtime ends-with to include the offset for length 5"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("runtime ends-with should compile through codegen");
}

#[test]
fn test_lower_global_get_string_contains_runtime_length() {
    let define_decl = DeclId::new(1315);
    let get_decl = DeclId::new(1316);
    let contains_decl = DeclId::new(1317);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
        (contains_decl, "str contains".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("left".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("string:8".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("hello".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(2),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        pipeline_input: Some(RegId::new(2)),
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
                    lit: HirLiteral::String("ll".into()),
                },
                HirStmt::Call {
                    decl_id: contains_decl,
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-get string should run str contains using runtime length");

    let comparisons = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::StrCmp { len: 2, .. }))
        .count();
    assert_eq!(
        comparisons, 7,
        "expected runtime contains to test each possible substring offset for string:8"
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
                    op: BinOpKind::Ge,
                    rhs: MirValue::Const(4),
                    ..
                }
            )),
        "expected runtime contains to guard offset 2 by requiring length at least 4"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("runtime contains should compile through codegen");
}

fn lower_global_get_string_index_of_runtime_length(
    search_from_end: bool,
    needle: &str,
    range: Option<(Option<i64>, Option<i64>, RangeInclusion)>,
) -> Result<MirLoweringResult, CompileError> {
    let define_decl = DeclId::new(1318);
    let get_decl = DeclId::new(1319);
    let index_of_decl = DeclId::new(1320);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
        (index_of_decl, "str index-of".to_string()),
    ]);

    let mut stmts = vec![
        HirStmt::LoadLiteral {
            dst: RegId::new(0),
            lit: HirLiteral::String("left".into()),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(1),
            lit: HirLiteral::String("string:8".into()),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(2),
            lit: HirLiteral::String("hello".into()),
        },
        HirStmt::Call {
            decl_id: define_decl,
            src_dst: RegId::new(2),
            args: HirCallArgs {
                positional: vec![RegId::new(0)],
                named: vec![(b"type".to_vec(), RegId::new(1))],
                pipeline_input: Some(RegId::new(2)),
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
            lit: HirLiteral::String(needle.into()),
        },
    ];
    let mut named = Vec::new();
    let mut register_count = 6;
    if let Some((start, end, inclusion)) = range {
        let start_reg = RegId::new(6);
        let step_reg = RegId::new(7);
        let end_reg = RegId::new(8);
        let range_reg = RegId::new(9);
        register_count = 10;
        stmts.push(HirStmt::LoadLiteral {
            dst: start_reg,
            lit: start.map_or(HirLiteral::Nothing, HirLiteral::Int),
        });
        stmts.push(HirStmt::LoadLiteral {
            dst: step_reg,
            lit: HirLiteral::Int(1),
        });
        stmts.push(HirStmt::LoadLiteral {
            dst: end_reg,
            lit: end.map_or(HirLiteral::Nothing, HirLiteral::Int),
        });
        stmts.push(HirStmt::LoadLiteral {
            dst: range_reg,
            lit: HirLiteral::Range {
                start: start_reg,
                step: step_reg,
                end: end_reg,
                inclusion,
            },
        });
        named.push((b"range".to_vec(), range_reg));
    }
    stmts.push(HirStmt::Call {
        decl_id: index_of_decl,
        src_dst: RegId::new(5),
        args: HirCallArgs {
            positional: vec![RegId::new(4)],
            named,
            flags: search_from_end
                .then(|| b"end".to_vec())
                .into_iter()
                .collect(),
            pipeline_input: Some(RegId::new(3)),
            ..HirCallArgs::default()
        },
    });

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
        register_count,
        file_count: 0,
    };
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
}

#[test]
fn test_lower_global_get_string_index_of_runtime_length() {
    let result = lower_global_get_string_index_of_runtime_length(false, "l", None)
        .expect("global-get string should run str index-of using runtime length");

    let comparisons = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::StrCmp { len: 1, .. }))
        .count();
    assert_eq!(
        comparisons, 8,
        "expected runtime index-of to test each possible substring offset for string:8"
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
                    op: BinOpKind::Ge,
                    rhs: MirValue::Const(3),
                    ..
                }
            )),
        "expected runtime index-of to guard offset 2 by requiring length at least 3"
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
                    src: MirValue::Const(2),
                    ..
                }
            )),
        "expected runtime index-of to emit the first matching byte offset"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("runtime index-of should compile through codegen");
}

#[test]
fn test_lower_global_get_string_index_of_end_runtime_length() {
    let result = lower_global_get_string_index_of_runtime_length(true, "l", None)
        .expect("global-get string should run str index-of --end using runtime length");

    let comparisons = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::StrCmp { len: 1, .. }))
        .count();
    assert_eq!(
        comparisons, 8,
        "expected runtime index-of --end to test each possible substring offset for string:8"
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
                    lhs_offset: 7,
                    rhs_offset: 0,
                    len: 1,
                    ..
                }
            )),
        "expected runtime index-of --end to probe the highest bounded offset"
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
        "expected runtime index-of --end to emit the last matching byte offset"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("runtime index-of --end should compile through codegen");
}

#[test]
fn test_lower_global_get_string_index_of_range_runtime_length() {
    let result = lower_global_get_string_index_of_runtime_length(
        false,
        "l",
        Some((Some(2), Some(5), RangeInclusion::Inclusive)),
    )
    .expect("global-get string should run str index-of --range using runtime length");

    let comparisons = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::StrCmp { len: 1, .. }))
        .count();
    assert_eq!(
        comparisons, 4,
        "expected runtime index-of --range to test offsets 2 through 5 for string:8"
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
                MirInst::StrCmp {
                    lhs_offset: 1,
                    len: 1,
                    ..
                }
            )),
        "expected runtime index-of --range to skip offsets before the bounded range"
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
                    op: BinOpKind::Ge,
                    rhs: MirValue::Const(4),
                    ..
                }
            )),
        "expected runtime index-of --range to guard offset 3 by requiring length at least 4"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("runtime index-of --range should compile through codegen");
}

#[test]
fn test_lower_global_get_string_index_of_empty_range_runtime_length() {
    let result = lower_global_get_string_index_of_runtime_length(
        false,
        "",
        Some((Some(2), Some(5), RangeInclusion::Inclusive)),
    )
    .expect("global-get string should run empty str index-of --range using runtime length");

    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { .. })),
        "expected empty runtime index-of --range not to compare bytes"
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
                    op: BinOpKind::Lt,
                    rhs: MirValue::Const(2),
                    ..
                }
            )),
        "expected empty runtime index-of --range to clamp start against runtime length"
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
                    src: MirValue::Const(2),
                    ..
                }
            )),
        "expected empty runtime index-of --range to emit the static start bound"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("empty runtime index-of --range should compile through codegen");
}

#[test]
fn test_lower_global_get_string_index_of_empty_end_range_runtime_length() {
    let result = lower_global_get_string_index_of_runtime_length(
        true,
        "",
        Some((Some(2), Some(5), RangeInclusion::Inclusive)),
    )
    .expect("global-get string should run empty str index-of --end --range using runtime length");

    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { .. })),
        "expected empty runtime index-of --end --range not to compare bytes"
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
                    op: BinOpKind::Lt,
                    rhs: MirValue::Const(6),
                    ..
                }
            )),
        "expected empty runtime index-of --end --range to clamp end against runtime length"
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
                    src: MirValue::Const(6),
                    ..
                }
            )),
        "expected empty runtime index-of --end --range to emit the static end bound"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("empty runtime index-of --end --range should compile through codegen");
}

#[test]
fn test_lower_global_get_string_index_of_negative_end_range_runtime_length() {
    let result = lower_global_get_string_index_of_runtime_length(
        false,
        "l",
        Some((Some(1), Some(-2), RangeInclusion::Inclusive)),
    )
    .expect("global-get string should run str index-of with a negative end range");

    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::StrCmp {
                    lhs_offset: 0,
                    len: 1,
                    ..
                }
            )),
        "expected negative-end runtime index-of --range to preserve the static start bound"
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
                    op: BinOpKind::Ge,
                    rhs: MirValue::Const(5),
                    ..
                }
            )),
        "expected negative-end runtime index-of --range to guard offset 3 by requiring length at least 5"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("negative-end runtime index-of --range should compile through codegen");
}

#[test]
fn test_lower_global_get_string_index_of_negative_start_range_runtime_length() {
    let result = lower_global_get_string_index_of_runtime_length(
        false,
        "l",
        Some((Some(-3), None, RangeInclusion::Inclusive)),
    )
    .expect("global-get string should run str index-of with a negative start range");

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
                    op: BinOpKind::Le,
                    rhs: MirValue::Const(5),
                    ..
                }
            )),
        "expected negative-start runtime index-of --range to guard offset 2 with length <= 5"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("negative-start runtime index-of --range should compile through codegen");
}

#[test]
fn test_lower_global_get_string_index_of_empty_negative_end_range_runtime_length() {
    let result = lower_global_get_string_index_of_runtime_length(
        false,
        "",
        Some((Some(1), Some(-2), RangeInclusion::Inclusive)),
    )
    .expect("empty runtime str index-of --range should support a negative end bound");

    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { .. })),
        "expected empty negative-end runtime index-of --range not to compare bytes"
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
                    op: BinOpKind::Lt,
                    rhs: MirValue::Const(1),
                    ..
                }
            )),
        "expected empty negative-end runtime index-of --range to clamp the positive start against runtime length"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("empty negative-end runtime index-of --range should compile through codegen");
}

#[test]
fn test_lower_global_get_string_index_of_empty_negative_start_range_runtime_length() {
    let result = lower_global_get_string_index_of_runtime_length(
        false,
        "",
        Some((Some(-3), None, RangeInclusion::Inclusive)),
    )
    .expect("empty runtime str index-of --range should support a negative start bound");

    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { .. })),
        "expected empty negative-start runtime index-of --range not to compare bytes"
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
                    op: BinOpKind::Sub,
                    rhs: MirValue::Const(3),
                    ..
                }
            )),
        "expected empty negative-start runtime index-of --range to compute len - 3 when length permits"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("empty negative-start runtime index-of --range should compile through codegen");
}

#[test]
fn test_lower_global_get_string_index_of_empty_end_negative_range_runtime_length() {
    let result = lower_global_get_string_index_of_runtime_length(
        true,
        "",
        Some((Some(1), Some(-2), RangeInclusion::Inclusive)),
    )
    .expect("empty runtime str index-of --end --range should support a negative end bound");

    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { .. })),
        "expected empty negative-end runtime index-of --end --range not to compare bytes"
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
                    op: BinOpKind::Sub,
                    rhs: MirValue::Const(1),
                    ..
                }
            )),
        "expected empty negative-end runtime index-of --end --range to compute the resolved end bound"
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
                    op: BinOpKind::Gt,
                    lhs: MirValue::VReg(_),
                    rhs: MirValue::VReg(_),
                    ..
                }
            )),
        "expected empty negative-end runtime index-of --end --range to select max(start, end)"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("empty negative-end runtime index-of --end --range should compile through codegen");
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
                        pipeline_input: Some(RegId::new(0)),
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
                        pipeline_input: Some(RegId::new(4)),
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
                        pipeline_input: Some(RegId::new(4)),
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
                        pipeline_input: Some(RegId::new(0)),
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
                        pipeline_input: Some(RegId::new(0)),
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
                        pipeline_input: Some(RegId::new(2)),
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
                        pipeline_input: Some(RegId::new(0)),
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
fn test_lower_global_define_type_int_uses_named_bss_global() {
    let define_decl = DeclId::new(411);
    let get_decl = DeclId::new(412);
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
                    lit: HirLiteral::String("int".into()),
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
    .expect("global-define --type int should lower");

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
fn test_lower_global_get_before_later_typed_global_define_with_constant_upsert_uses_named_data_global()
 {
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
fn test_lower_global_define_type_bytes_with_empty_binary_initializer_uses_named_bss_global() {
    let define_decl = DeclId::new(1073);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Binary(Vec::new()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("scratch".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("bytes:8".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(0)),
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-define --type bytes:N should zero-fill an empty binary input");

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_global_scratch");
    assert_eq!(result.bss_globals[0].size, 8);
}

#[test]
fn test_lower_bytes_length_on_typed_bytes_global_uses_declared_len() {
    let define_decl = DeclId::new(9073);
    let global_get_decl = DeclId::new(9074);
    let bytes_length_decl = DeclId::new(9075);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (bytes_length_decl, "bytes length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Binary(Vec::new()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("scratch".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("bytes:8".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(0)),
                        positional: vec![RegId::new(1)],
                        named: vec![(b"type".to_vec(), RegId::new(2))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: bytes_length_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bytes length should lower on a typed bytes global");

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
                    src: MirValue::Const(8),
                    ..
                }
            )),
        "expected bytes length to use the declared bytes:N length"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed bytes global bytes length should compile through codegen");
}

#[test]
fn test_lower_bytes_length_on_typed_record_bytes_field_uses_declared_len() {
    let define_decl = DeclId::new(9076);
    let global_get_decl = DeclId::new(9077);
    let bytes_length_decl = DeclId::new(9078);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (bytes_length_decl, "bytes length".to_string()),
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
                    lit: HirLiteral::String("record{pid:int,comm:bytes:4}".into()),
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
                        members: vec![string_member("comm")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                },
                HirStmt::Call {
                    decl_id: bytes_length_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bytes length should lower on a typed record bytes field");

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
        "expected bytes length to use the declared record bytes field length"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed record bytes field bytes length should compile through codegen");
}

#[test]
fn test_lower_bytes_length_rejects_typed_u8_array_global() {
    let define_decl = DeclId::new(9079);
    let global_get_decl = DeclId::new(9080);
    let bytes_length_decl = DeclId::new(9081);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (bytes_length_decl, "bytes length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("scratch".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u8:8}".into()),
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
                HirStmt::Call {
                    decl_id: bytes_length_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("bytes length should reject fixed u8 arrays without binary semantics");

    assert!(
        err.to_string()
            .contains("bytes length requires compile-time known binary or list<binary> input"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_global_define_empty_binary_without_type_still_rejects_empty_layout() {
    let define_decl = DeclId::new(1074);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Binary(Vec::new()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("scratch".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(0)),
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("untyped empty binary globals should not infer a zero-length layout");

    assert!(
        err.to_string()
            .contains("empty binary constants do not establish a fixed byte-buffer layout")
    );
}

#[test]
fn test_lower_global_define_type_record_empty_binary_field_zero_fills_declared_bytes() {
    let define_decl = DeclId::new(1075);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

    let mut state = Record::with_capacity(2);
    state.push("pid", Value::int(7, Span::test_data()));
    state.push("comm", Value::binary(Vec::new(), Span::test_data()));

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
                    lit: HirLiteral::String("record{pid:i64,comm:bytes:4}".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(0)),
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("typed record bytes:N fields should accept empty binary initializers");

    let mut expected = Vec::new();
    expected.extend_from_slice(&7i64.to_le_bytes());
    expected.extend_from_slice(&[0u8; 4]);
    expected.extend_from_slice(&[0u8; 4]);

    assert_eq!(result.readonly_globals.len(), 0);
    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_state");
    assert_eq!(result.data_globals[0].data, expected);
}

#[test]
fn test_lower_global_define_type_bound_record_empty_binary_field_zero_fills_declared_bytes() {
    let define_decl = DeclId::new(1076);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);
    let state_var = VarId::new(221);

    let mut state = Record::with_capacity(2);
    state.push("pid", Value::int(7, Span::test_data()));
    state.push("comm", Value::binary(Vec::new(), Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::record(state, Span::test_data())),
                },
                HirStmt::StoreVariable {
                    var_id: state_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("record{pid:i64,comm:bytes:4}".into()),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(3),
                    var_id: state_var,
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        positional: vec![RegId::new(1)],
                        named: vec![(b"type".to_vec(), RegId::new(2))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::DropVariable { var_id: state_var },
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
    .expect("typed record bytes:N fields should accept bound empty binary initializers");

    let mut expected = Vec::new();
    expected.extend_from_slice(&7i64.to_le_bytes());
    expected.extend_from_slice(&[0u8; 4]);
    expected.extend_from_slice(&[0u8; 4]);

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_state");
    assert_eq!(result.data_globals[0].data, expected);
}

#[test]
fn test_lower_constant_record_empty_binary_field_without_typed_consumer_rejects_layout() {
    let mut state = Record::with_capacity(2);
    state.push("pid", Value::int(7, Span::test_data()));
    state.push("comm", Value::binary(Vec::new(), Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadValue {
                dst: RegId::new(0),
                val: Box::new(Value::record(state, Span::test_data())),
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
    .expect_err("untyped record constants with empty binary fields should reject");

    assert!(
        err.to_string()
            .contains("empty binary constants do not establish a fixed byte-buffer layout")
    );
}

#[test]
fn test_lower_global_define_type_bool_with_constant_not_initializer_uses_named_data_global() {
    let define_decl = DeclId::new(1081);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Bool(false),
                },
                HirStmt::Not {
                    src_dst: RegId::new(0),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("enabled".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("bool".into()),
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-define --type bool with constant not input should lower");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_enabled");
    assert_eq!(result.data_globals[0].data, vec![1u8]);
}

#[test]
fn test_lower_global_define_type_int_rejects_bool_initializer() {
    let define_decl = DeclId::new(1098);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Bool(true),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("int".into()),
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
    .expect_err("global-define --type int should reject bool input");

    assert!(
        err.to_string()
            .contains("global type spec 'int' initializer requires a i64-compatible constant"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_global_define_type_record_rejects_reserved_padding_field_names() {
    let define_decl = DeclId::new(1075);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

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
                    lit: HirLiteral::String("record{a:u8,__layout_pad0:u64}".into()),
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
    .expect_err("record type specs should reject internal padding field names");

    assert!(
        err.to_string().contains("reserve field names"),
        "unexpected error: {err}"
    );
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
fn test_lower_global_define_type_i64_with_constant_follow_cell_path_initializer_uses_named_data_global()
 {
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
fn test_lower_global_define_type_string_with_constant_string_append_initializer_uses_named_data_global()
 {
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
fn test_lower_global_define_type_string_with_constant_binary_concat_initializer_uses_named_data_global()
 {
    let define_decl = DeclId::new(1080);
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
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: nu_protocol::ast::Operator::Math(nu_protocol::ast::Math::Add),
                    rhs: RegId::new(1),
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
    .expect("global-define --type string:N with constant binary concat input should lower");

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
fn test_lower_global_define_type_list_int_rejects_bool_items() {
    let define_decl = DeclId::new(1099);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::list(
                        vec![Value::bool(true, Span::test_data())],
                        Span::test_data(),
                    )),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("samples".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("list:int:4".into()),
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
    .expect_err("global-define --type list:int:N should reject bool items");

    assert!(
        err.to_string()
            .contains("global type spec 'list:int:4' initializer requires a numeric constant list"),
        "unexpected error: {err}"
    );
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
fn test_lower_global_define_type_record_with_fixed_record_array_initializer_uses_named_data_global()
{
    let define_decl = DeclId::new(1094);
    let global_get_decl = DeclId::new(1095);
    let count_decl = DeclId::new(1096);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (count_decl, "count".to_string()),
    ]);

    let mut first = Record::with_capacity(2);
    first.push("pid", Value::int(7, Span::test_data()));
    first.push("cpu", Value::int(2, Span::test_data()));

    let mut second = Record::with_capacity(2);
    second.push("pid", Value::int(9, Span::test_data()));
    second.push("cpu", Value::int(3, Span::test_data()));

    let mut state = Record::with_capacity(1);
    state.push(
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
                    lit: HirLiteral::String(
                        "record{entries:array{record{pid:int,cpu:u32}:2}}".into(),
                    ),
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
                    decl_id: global_get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![
                            string_member("entries"),
                            int_member(1),
                            string_member("cpu"),
                        ],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
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
    .expect("global-define --type record{...array{record{...}:N}...} should lower");

    let mut expected = Vec::new();
    expected.extend_from_slice(&7i64.to_le_bytes());
    expected.extend_from_slice(&2u32.to_le_bytes());
    expected.extend_from_slice(&[0u8; 4]);
    expected.extend_from_slice(&9i64.to_le_bytes());
    expected.extend_from_slice(&3u32.to_le_bytes());
    expected.extend_from_slice(&[0u8; 4]);

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_state");
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
        "expected nested initialized fixed record-array global field to be usable as a scalar key"
    );
}

#[test]
fn test_lower_global_define_type_fixed_array_initializer_uses_named_data_global() {
    let define_decl = DeclId::new(1082);
    let global_get_decl = DeclId::new(1083);
    let count_decl = DeclId::new(1084);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (count_decl, "count".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::list(
                        vec![
                            Value::int(11, Span::test_data()),
                            Value::int(22, Span::test_data()),
                        ],
                        Span::test_data(),
                    )),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_slots".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("array{u32:4}".into()),
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
                    decl_id: global_get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1)],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
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
    .expect("global-define --type array{u32:N} with constant input should lower");

    let mut expected = Vec::new();
    expected.extend_from_slice(&11u32.to_le_bytes());
    expected.extend_from_slice(&22u32.to_le_bytes());
    expected.extend_from_slice(&0u32.to_le_bytes());
    expected.extend_from_slice(&0u32.to_le_bytes());

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_slots");
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
        "expected fixed-array global element to be usable as a scalar key"
    );
}

#[test]
fn test_lower_global_define_type_fixed_array_bool_initializer_uses_named_data_global() {
    let define_decl = DeclId::new(1085);
    let global_get_decl = DeclId::new(1086);
    let count_decl = DeclId::new(1087);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (count_decl, "count".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::list(
                        vec![
                            Value::bool(true, Span::test_data()),
                            Value::bool(false, Span::test_data()),
                        ],
                        Span::test_data(),
                    )),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_flags".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("array{bool:4}".into()),
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
                    decl_id: global_get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1)],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
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
    .expect("global-define --type array{bool:N} with constant input should lower");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_flags");
    assert_eq!(result.data_globals[0].data, vec![1, 0, 0, 0]);
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
                    offset: 1,
                    ty: MirType::Bool,
                    ..
                }
            )),
        "expected bool fixed-array global element projection to load a bool"
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
        "expected bool fixed-array global element to be usable as a scalar key"
    );
}

#[test]
fn test_lower_global_define_type_fixed_array_bytes_initializer_uses_named_data_global() {
    let define_decl = DeclId::new(1120);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::list(
                        vec![
                            Value::binary(vec![1, 2], Span::test_data()),
                            Value::binary(vec![3, 4, 5], Span::test_data()),
                        ],
                        Span::test_data(),
                    )),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_buffers".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("array{bytes:4:2}".into()),
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

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-define --type array{bytes:N:N} with constant input should lower");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_buffers");
    assert_eq!(result.data_globals[0].data, vec![1, 2, 0, 0, 3, 4, 5, 0]);
}

#[test]
fn test_lower_global_define_type_fixed_array_string_initializer_preserves_semantics() {
    let define_decl = DeclId::new(1121);
    let global_get_decl = DeclId::new(1122);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::list(
                        vec![
                            Value::string("aa", Span::test_data()),
                            Value::string("bb", Span::test_data()),
                        ],
                        Span::test_data(),
                    )),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("array{string:8:2}".into()),
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
                    decl_id: global_get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1)],
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
    .expect("global-define --type array{string:N:N} with constant input should lower");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_names");
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected direct fixed-array string element to materialize as a stack string"
    );
}

#[test]
fn test_lower_global_define_type_fixed_array_numeric_list_initializer_preserves_semantics() {
    let define_decl = DeclId::new(1123);
    let global_get_decl = DeclId::new(1124);
    let get_decl = DeclId::new(1125);
    let count_decl = DeclId::new(1126);
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
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::list(
                        vec![
                            Value::list(
                                vec![
                                    Value::int(11, Span::test_data()),
                                    Value::int(22, Span::test_data()),
                                ],
                                Span::test_data(),
                            ),
                            Value::list(
                                vec![
                                    Value::int(33, Span::test_data()),
                                    Value::int(44, Span::test_data()),
                                ],
                                Span::test_data(),
                            ),
                        ],
                        Span::test_data(),
                    )),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen_samples".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("array{list:int:4:2}".into()),
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
                    decl_id: global_get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1)],
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
                        ..HirCallArgs::default()
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
    .expect("global-define --type array{list:int:N:N} with constant input should lower");

    let mut expected = Vec::new();
    expected.extend_from_slice(&2u64.to_le_bytes());
    expected.extend_from_slice(&11i64.to_le_bytes());
    expected.extend_from_slice(&22i64.to_le_bytes());
    expected.extend_from_slice(&0i64.to_le_bytes());
    expected.extend_from_slice(&0i64.to_le_bytes());
    expected.extend_from_slice(&2u64.to_le_bytes());
    expected.extend_from_slice(&33i64.to_le_bytes());
    expected.extend_from_slice(&44i64.to_le_bytes());
    expected.extend_from_slice(&0i64.to_le_bytes());
    expected.extend_from_slice(&0i64.to_le_bytes());

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_samples");
    assert_eq!(result.data_globals[0].data, expected);
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListGet { .. })),
        "expected direct fixed-array numeric-list element to materialize as a stack list"
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
        "expected fixed-array numeric-list element result to be usable as a scalar key"
    );
}

#[test]
fn test_lower_global_define_type_record_fixed_array_field_supports_get() {
    let define_decl = DeclId::new(1085);
    let global_get_decl = DeclId::new(1086);
    let count_decl = DeclId::new(1087);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
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
                    lit: HirLiteral::String("record{ports:array{u16:4},pid:int}".into()),
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
                        members: vec![string_member("ports"), int_member(2)],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
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
    .expect("global-define --type record{...array{u16:N}...} should lower");

    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_global_seen_state");
    assert_eq!(result.bss_globals[0].size, 16);
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
        "expected nested fixed-array global field element to be usable as a scalar key"
    );
}

#[test]
fn test_lower_global_define_type_fixed_record_array_supports_field_projection() {
    let define_decl = DeclId::new(1088);
    let global_get_decl = DeclId::new(1089);
    let count_decl = DeclId::new(1090);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (count_decl, "count".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("seen_entries".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{record{pid:int,cpu:u32}:2}".into()),
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
                        members: vec![int_member(1), string_member("cpu")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
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
    .expect("global-define --type array{record{...}:N} should lower");

    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_global_seen_entries");
    assert_eq!(result.bss_globals[0].size, 32);
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
        "expected fixed record-array global field to be usable as a scalar key"
    );
}

#[test]
fn test_lower_global_define_type_fixed_record_array_initializer_uses_named_data_global() {
    let define_decl = DeclId::new(1091);
    let global_get_decl = DeclId::new(1092);
    let count_decl = DeclId::new(1093);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (count_decl, "count".to_string()),
    ]);

    let mut first = Record::with_capacity(2);
    first.push("pid", Value::int(7, Span::test_data()));
    first.push("cpu", Value::int(2, Span::test_data()));

    let mut second = Record::with_capacity(2);
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
                    lit: HirLiteral::String("seen_entries".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("array{record{pid:int,cpu:u32}:2}".into()),
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
                    decl_id: global_get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1), string_member("cpu")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
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
    .expect("global-define --type array{record{...}:N} with constant input should lower");

    let mut expected = Vec::new();
    expected.extend_from_slice(&7i64.to_le_bytes());
    expected.extend_from_slice(&2u32.to_le_bytes());
    expected.extend_from_slice(&[0u8; 4]);
    expected.extend_from_slice(&9i64.to_le_bytes());
    expected.extend_from_slice(&3u32.to_le_bytes());
    expected.extend_from_slice(&[0u8; 4]);

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_entries");
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
        "expected initialized fixed record-array global field to be usable as a scalar key"
    );
}

#[test]
fn test_lower_global_define_type_fixed_record_array_source_list_builder_skips_runtime_list_push() {
    let define_decl = DeclId::new(1100);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::List { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(1),
                    key: RegId::new(2),
                    val: RegId::new(3),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::String("cpu".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(2),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(1),
                    key: RegId::new(4),
                    val: RegId::new(5),
                },
                HirStmt::ListPush {
                    src_dst: RegId::new(0),
                    item: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(8),
                    lit: HirLiteral::Int(9),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(6),
                    key: RegId::new(7),
                    val: RegId::new(8),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(9),
                    lit: HirLiteral::String("cpu".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(10),
                    lit: HirLiteral::Int(3),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(6),
                    key: RegId::new(9),
                    val: RegId::new(10),
                },
                HirStmt::ListPush {
                    src_dst: RegId::new(0),
                    item: RegId::new(6),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(11),
                    lit: HirLiteral::String("seen_entries".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(12),
                    lit: HirLiteral::String("array{record{pid:int,cpu:u32}:2}".into()),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(11)],
                        named: vec![(b"type".to_vec(), RegId::new(12))],
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Drain { src: RegId::new(0) },
                HirStmt::Drop { src: RegId::new(0) },
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
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
    .expect("source list-of-record initializers should lower as typed global data");

    let mut expected = Vec::new();
    expected.extend_from_slice(&7i64.to_le_bytes());
    expected.extend_from_slice(&2u32.to_le_bytes());
    expected.extend_from_slice(&[0u8; 4]);
    expected.extend_from_slice(&9i64.to_le_bytes());
    expected.extend_from_slice(&3u32.to_le_bytes());
    expected.extend_from_slice(&[0u8; 4]);

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_entries");
    assert_eq!(result.data_globals[0].data, expected);
    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "compile-time typed global list-of-record builders must not emit runtime ListPush"
    );
}

#[test]
fn test_lower_global_set_fixed_record_array_source_list_builder_skips_runtime_list_push() {
    let global_set_decl = DeclId::new(1101);
    let global_get_decl = DeclId::new(1102);
    let count_decl = DeclId::new(1103);
    let decl_names = HashMap::from([
        (global_set_decl, "global-set".to_string()),
        (global_get_decl, "global-get".to_string()),
        (count_decl, "count".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::List { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(1),
                    key: RegId::new(2),
                    val: RegId::new(3),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::String("cpu".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(2),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(1),
                    key: RegId::new(4),
                    val: RegId::new(5),
                },
                HirStmt::ListPush {
                    src_dst: RegId::new(0),
                    item: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(8),
                    lit: HirLiteral::Int(9),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(6),
                    key: RegId::new(7),
                    val: RegId::new(8),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(9),
                    lit: HirLiteral::String("cpu".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(10),
                    lit: HirLiteral::Int(3),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(6),
                    key: RegId::new(9),
                    val: RegId::new(10),
                },
                HirStmt::ListPush {
                    src_dst: RegId::new(0),
                    item: RegId::new(6),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(11),
                    lit: HirLiteral::String("seen_entries".into()),
                },
                HirStmt::Call {
                    decl_id: global_set_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(11)],
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Drain { src: RegId::new(0) },
                HirStmt::Drop { src: RegId::new(0) },
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(12),
                    args: HirCallArgs {
                        positional: vec![RegId::new(11)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(13),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1), string_member("cpu")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(12),
                    path: RegId::new(13),
                },
                HirStmt::Call {
                    decl_id: count_decl,
                    src_dst: RegId::new(12),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return {
                src: RegId::new(12),
            },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 14,
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
    .expect("source list-of-record global-set initializer should lower as fixed global data");

    let mut expected = Vec::new();
    expected.extend_from_slice(&7i64.to_le_bytes());
    expected.extend_from_slice(&2i64.to_le_bytes());
    expected.extend_from_slice(&9i64.to_le_bytes());
    expected.extend_from_slice(&3i64.to_le_bytes());

    let global = result
        .data_globals
        .iter()
        .find(|global| global.name == "__nu_global_seen_entries")
        .expect("expected global-set source initializer to create named data global");
    assert_eq!(global.data, expected);
    assert_eq!(result.bss_globals.len(), 0);
    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "compile-time global-set list-of-record builders must not emit runtime ListPush"
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
        "expected global-set fixed record-array field to be usable as a scalar key"
    );
}

#[test]
fn test_lower_global_set_fixed_record_array_source_list_spread_skips_runtime_list_ops() {
    let global_set_decl = DeclId::new(1104);
    let global_get_decl = DeclId::new(1105);
    let count_decl = DeclId::new(1106);
    let decl_names = HashMap::from([
        (global_set_decl, "global-set".to_string()),
        (global_get_decl, "global-get".to_string()),
        (count_decl, "count".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::List { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Record { capacity: 1 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(1),
                    key: RegId::new(2),
                    val: RegId::new(3),
                },
                HirStmt::ListPush {
                    src_dst: RegId::new(0),
                    item: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::List { capacity: 1 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Record { capacity: 1 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::Int(9),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(5),
                    key: RegId::new(6),
                    val: RegId::new(7),
                },
                HirStmt::ListPush {
                    src_dst: RegId::new(4),
                    item: RegId::new(5),
                },
                HirStmt::ListSpread {
                    src_dst: RegId::new(0),
                    items: RegId::new(4),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(8),
                    lit: HirLiteral::String("seen_entries".into()),
                },
                HirStmt::Call {
                    decl_id: global_set_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(8)],
                        pipeline_input: Some(RegId::new(0)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Drain { src: RegId::new(0) },
                HirStmt::Drop { src: RegId::new(0) },
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(9),
                    args: HirCallArgs {
                        positional: vec![RegId::new(8)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(10),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1), string_member("pid")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(9),
                    path: RegId::new(10),
                },
                HirStmt::Call {
                    decl_id: count_decl,
                    src_dst: RegId::new(9),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(9) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 11,
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
    .expect("source list-spread global-set initializer should lower as fixed global data");

    let mut expected = Vec::new();
    expected.extend_from_slice(&7i64.to_le_bytes());
    expected.extend_from_slice(&9i64.to_le_bytes());

    let global = result
        .data_globals
        .iter()
        .find(|global| global.name == "__nu_global_seen_entries")
        .expect("expected global-set spread initializer to create named data global");
    assert_eq!(global.data, expected);
    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| {
                matches!(
                    inst,
                    MirInst::ListPush { .. } | MirInst::ListLen { .. } | MirInst::ListGet { .. }
                )
            }),
        "compile-time global-set list-spread builders must not emit runtime list operations"
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
        "expected global-set fixed record-array spread field to be usable as a scalar key"
    );
}

#[test]
fn test_lower_global_define_type_fixed_record_array_initializer_supports_nested_numeric_list_field()
{
    let define_decl = DeclId::new(1094);
    let global_get_decl = DeclId::new(1095);
    let count_decl = DeclId::new(1096);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (count_decl, "count".to_string()),
    ]);

    let mut first = Record::with_capacity(1);
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

    let mut second = Record::with_capacity(1);
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
                    lit: HirLiteral::String("seen_entries".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("array{record{samples:list:int:2}:2}".into()),
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
                    decl_id: global_get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1), string_member("samples"), int_member(1)],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
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
    .expect("global-define fixed record arrays should allow nested numeric-list fields");

    let mut expected = Vec::new();
    expected.extend_from_slice(&2u64.to_le_bytes());
    expected.extend_from_slice(&1i64.to_le_bytes());
    expected.extend_from_slice(&2i64.to_le_bytes());
    expected.extend_from_slice(&2u64.to_le_bytes());
    expected.extend_from_slice(&3i64.to_le_bytes());
    expected.extend_from_slice(&4i64.to_le_bytes());

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_entries");
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
        "expected initialized nested numeric-list field to be usable as a scalar key"
    );
}

#[test]
fn test_lower_global_define_type_fixed_record_array_initializer_supports_nested_numeric_list_upsert()
 {
    let define_decl = DeclId::new(1108);
    let global_get_decl = DeclId::new(1109);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
    ]);

    let mut first = Record::with_capacity(1);
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

    let mut second = Record::with_capacity(1);
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
                    lit: HirLiteral::String("seen_entries".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("array{record{samples:list:int:2}:2}".into()),
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
                    decl_id: global_get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1), string_member("samples"), int_member(1)],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(9),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                    new_value: RegId::new(5),
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
    .expect("typed fixed record array globals should allow nested numeric-list item upserts");

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
                    offset: 40,
                    ty: MirType::I64,
                    ..
                }
            )),
        "expected $entries.1.samples.1 = ... to store at the logical nested list item slot"
    );
}

#[test]
fn test_lower_global_define_type_fixed_record_array_initializer_supports_nested_string_field() {
    let define_decl = DeclId::new(1097);
    let global_get_decl = DeclId::new(1098);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
    ]);

    let mut first = Record::with_capacity(1);
    first.push("name", Value::string("aa", Span::test_data()));

    let mut second = Record::with_capacity(1);
    second.push("name", Value::string("bb", Span::test_data()));

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
                    lit: HirLiteral::String("seen_entries".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("array{record{name:string:15}:2}".into()),
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
                    decl_id: global_get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1), string_member("name")],
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
    .expect("global-define fixed record arrays should allow nested string fields");

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_seen_entries");
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected initialized nested string field to materialize as a stack string"
    );
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
fn test_lower_global_define_type_list_int_uses_named_bss_global() {
    let define_decl = DeclId::new(413);
    let get_decl = DeclId::new(414);
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
                    lit: HirLiteral::String("list:int:4".into()),
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
    .expect("global-define --type list:int:N should lower");

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
fn test_lower_global_define_type_zero_list_supports_root_appends() {
    let define_decl = DeclId::new(417);
    let get_decl = DeclId::new(418);
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
                    lit: HirLiteral::String("samples".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("list:int:2".into()),
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
                        members: vec![int_member(0)],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(11),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                    new_value: RegId::new(5),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1)],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::Int(22),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(6),
                    new_value: RegId::new(7),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(6),
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("zero-initialized typed list global should allow root appends");

    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_global_samples");
    assert_eq!(result.bss_globals[0].size, 3 * std::mem::size_of::<i64>());
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
                    offset: 8,
                    ty: MirType::I64,
                    ..
                }
            )),
        "expected first append to store list item 0"
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
                    offset: 16,
                    ty: MirType::I64,
                    ..
                }
            )),
        "expected second append to store list item 1"
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
                    val: MirValue::Const(2),
                    ty: MirType::U64,
                    ..
                }
            )),
        "expected second append to advance the root list length to 2"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListGet { .. })),
        "expected root list follow-cell-path to lower through ListGet"
    );
}

#[test]
fn test_lower_global_define_type_initialized_list_supports_root_append() {
    let define_decl = DeclId::new(419);
    let get_decl = DeclId::new(420);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::list(
                        vec![
                            Value::int(11, Span::test_data()),
                            Value::int(22, Span::test_data()),
                        ],
                        Span::test_data(),
                    )),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("samples".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("list:int:4".into()),
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
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(2)],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(33),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                    new_value: RegId::new(5),
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
    .expect("initialized typed list global should allow root append at the current length");

    let mut expected = Vec::new();
    expected.extend_from_slice(&2u64.to_le_bytes());
    expected.extend_from_slice(&11i64.to_le_bytes());
    expected.extend_from_slice(&22i64.to_le_bytes());
    expected.extend_from_slice(&0i64.to_le_bytes());
    expected.extend_from_slice(&0i64.to_le_bytes());

    assert_eq!(result.data_globals.len(), 1);
    assert_eq!(result.bss_globals.len(), 0);
    assert_eq!(result.data_globals[0].name, "__nu_global_samples");
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
                MirInst::Store {
                    offset: 24,
                    ty: MirType::I64,
                    ..
                }
            )),
        "expected append to store list item 2"
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
                    val: MirValue::Const(3),
                    ty: MirType::U64,
                    ..
                }
            )),
        "expected append to advance the root list length to 3"
    );
}

#[test]
fn test_lower_global_define_type_full_root_list_append_rejects() {
    let define_decl = DeclId::new(424);
    let get_decl = DeclId::new(425);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (get_decl, "global-get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::list(
                        vec![Value::int(11, Span::test_data())],
                        Span::test_data(),
                    )),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("samples".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("list:int:1".into()),
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
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![int_member(1)],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(22),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                    new_value: RegId::new(5),
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("full typed root numeric list append should reject");

    match err {
        CompileError::UnsupportedInstruction(message) => assert!(
            message.contains("cannot append beyond numeric list capacity 1"),
            "unexpected error: {message}"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn test_lower_global_set_persists_mutated_root_numeric_list() {
    let define_decl = DeclId::new(421);
    let get_decl = DeclId::new(422);
    let set_decl = DeclId::new(423);
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
                    lit: HirLiteral::String("samples".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("list:int:2".into()),
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
                        members: vec![int_member(0)],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(11),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                    new_value: RegId::new(5),
                },
                HirStmt::Call {
                    decl_id: set_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        pipeline_input: Some(RegId::new(3)),
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
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(6),
                    path: RegId::new(4),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(6) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 7,
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
    .expect("global-set should persist a mutated root numeric list value");

    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_global_samples");
    let global_load_count = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::LoadGlobal { symbol, .. } if symbol == "__nu_global_samples"
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
                MirInst::Store {
                    offset: 8,
                    ty: MirType::I64,
                    ..
                }
            )),
        "expected root list mutation before global-set"
    );
}

#[test]
fn test_lower_global_define_type_zero_record_list_field_supports_append() {
    let define_decl = DeclId::new(415);
    let get_decl = DeclId::new(416);
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
                    lit: HirLiteral::String("record{samples:list:int:2}".into()),
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
                        members: vec![string_member("samples"), int_member(0)],
                    })),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(11),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(3),
                    path: RegId::new(4),
                    new_value: RegId::new(5),
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
    .expect("zero-initialized typed record list field should allow append at index 0");

    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_global_seen_state");
    assert_eq!(result.bss_globals[0].size, 3 * std::mem::size_of::<i64>());
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
                    offset: 8,
                    ty: MirType::I64,
                    ..
                }
            )),
        "expected append to store the new first list item"
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
                    val: MirValue::Const(1),
                    ty: MirType::U64,
                    ..
                }
            )),
        "expected append to update the zero-initialized list length"
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
fn test_lower_global_define_type_nested_record_list_field_supports_get() {
    let define_decl = DeclId::new(126);
    let global_get_decl = DeclId::new(127);
    let get_decl = DeclId::new(128);
    let count_decl = DeclId::new(129);
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
                    lit: HirLiteral::String(
                        "record{inner:record{vals:list:i64:2,pid:i64},cpu:u32}".into(),
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
                        members: vec![string_member("inner"), string_member("vals")],
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
                        ..HirCallArgs::default()
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
    .expect("global-define --type nested record list field should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListGet { .. })),
        "expected nested typed record global list field to lower through ListGet"
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
        "expected nested typed record global list field result to be typed as a scalar key"
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
                        pipeline_input: Some(RegId::new(2)),
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
fn test_lower_global_set_rejects_live_src_dst_without_pipeline_input() {
    let set_decl = DeclId::new(95);
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("global-set must not consume a merely live src_dst value");

    assert!(
        err.to_string()
            .contains("global-set requires a value from pipeline input")
    );
}

#[test]
fn test_lower_global_define_rejects_live_src_dst_without_pipeline_input() {
    let define_decl = DeclId::new(96);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

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
                    decl_id: define_decl,
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("global-define must not consume a merely live src_dst value");

    assert!(
        err.to_string()
            .contains("global-define requires a compile-time constant value from pipeline input")
    );
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
                        pipeline_input: Some(RegId::new(0)),
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
                        pipeline_input: Some(RegId::new(2)),
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
                        pipeline_input: Some(RegId::new(1)),
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
                        pipeline_input: Some(RegId::new(6)),
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

#[test]
fn test_lower_global_set_from_nested_metadata_record_builder_preserves_nested_list_semantics() {
    let global_get_decl = DeclId::new(220);
    let global_set_decl = DeclId::new(221);
    let get_decl = DeclId::new(222);
    let count_decl = DeclId::new(223);
    let decl_names = HashMap::from([
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
                    lit: HirLiteral::String("state".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("vals".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::List { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::Int(11),
                },
                HirStmt::ListPush {
                    src_dst: RegId::new(3),
                    item: RegId::new(4),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(22),
                },
                HirStmt::ListPush {
                    src_dst: RegId::new(3),
                    item: RegId::new(5),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(1),
                    key: RegId::new(2),
                    val: RegId::new(3),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(1),
                    key: RegId::new(6),
                    val: RegId::new(7),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(8),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(9),
                    lit: HirLiteral::String("inner".into()),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(8),
                    key: RegId::new(9),
                    val: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(10),
                    lit: HirLiteral::String("cpu".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(11),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(8),
                    key: RegId::new(10),
                    val: RegId::new(11),
                },
                HirStmt::Call {
                    decl_id: global_set_decl,
                    src_dst: RegId::new(8),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        pipeline_input: Some(RegId::new(8)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(12),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(13),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("inner"), string_member("vals")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(12),
                    path: RegId::new(13),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(14),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(12),
                    args: HirCallArgs {
                        positional: vec![RegId::new(14)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: count_decl,
                    src_dst: RegId::new(12),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return {
                src: RegId::new(12),
            },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 15,
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
    .expect("nested metadata-only record builders should preserve nested list semantics");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListGet { .. })),
        "expected nested metadata-inferred record list field to lower through ListGet"
    );
}
