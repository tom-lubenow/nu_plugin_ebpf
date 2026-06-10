use super::*;
use crate::compiler::hir::{
    HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
};
use crate::compiler::mir::{BinOpKind, COUNTER_MAP_NAME, StructField, UnaryOpKind};
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
fn test_lower_bytes_starts_with_on_typed_bytes_global_compares_fixed_bytes() {
    let define_decl = DeclId::new(10_600);
    let global_get_decl = DeclId::new(10_601);
    let starts_with_decl = DeclId::new(10_602);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (starts_with_decl, "bytes starts-with".to_string()),
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
                    lit: HirLiteral::String("bytes:4".into()),
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
                    lit: HirLiteral::Binary(vec![0, 0]),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        positional: vec![RegId::new(4)],
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
    .expect("bytes starts-with should lower on a typed bytes global");

    let byte_load_offsets = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter_map(|inst| match inst {
            MirInst::Load {
                offset,
                ty: MirType::U8,
                ..
            } => Some(*offset),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        byte_load_offsets.contains(&0) && byte_load_offsets.contains(&1),
        "expected fixed binary starts-with to compare byte offsets 0 and 1, got {byte_load_offsets:?}"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed bytes global bytes starts-with should compile through codegen");
}

#[test]
fn test_lower_bytes_at_on_typed_bytes_global_copies_fixed_slice() {
    let define_decl = DeclId::new(10_617);
    let global_get_decl = DeclId::new(10_618);
    let bytes_at_decl = DeclId::new(10_619);
    let starts_with_decl = DeclId::new(10_620);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (bytes_at_decl, "bytes at".to_string()),
        (starts_with_decl, "bytes starts-with".to_string()),
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
                    lit: HirLiteral::String("bytes:4".into()),
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
                    lit: HirLiteral::Int(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Int(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::Range {
                        start: RegId::new(4),
                        step: RegId::new(5),
                        end: RegId::new(6),
                        inclusion: RangeInclusion::Inclusive,
                    },
                },
                HirStmt::Call {
                    decl_id: bytes_at_decl,
                    src_dst: RegId::new(8),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        positional: vec![RegId::new(7)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(9),
                    lit: HirLiteral::Binary(vec![0, 0]),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
                    src_dst: RegId::new(10),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(8)),
                        positional: vec![RegId::new(9)],
                        ..HirCallArgs::default()
                    },
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
    .expect("bytes at should lower on a typed bytes global");

    let byte_load_offsets = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter_map(|inst| match inst {
            MirInst::Load {
                offset,
                ty: MirType::U8,
                ..
            } => Some(*offset),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        byte_load_offsets.contains(&1) && byte_load_offsets.contains(&2),
        "expected bytes at to copy source offsets 1 and 2, got {byte_load_offsets:?}"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StoreSlot { offset: 0, .. })),
        "expected bytes at to materialize the fixed slice in a stack slot"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed bytes global bytes at should compile through codegen");
}

#[test]
fn test_lower_bytes_at_empty_slice_on_typed_bytes_global_feeds_length() {
    let define_decl = DeclId::new(10_621);
    let global_get_decl = DeclId::new(10_622);
    let bytes_at_decl = DeclId::new(10_623);
    let bytes_length_decl = DeclId::new(10_624);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (bytes_at_decl, "bytes at".to_string()),
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
                    lit: HirLiteral::String("bytes:4".into()),
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
                    lit: HirLiteral::Int(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::Range {
                        start: RegId::new(4),
                        step: RegId::new(5),
                        end: RegId::new(6),
                        inclusion: RangeInclusion::Inclusive,
                    },
                },
                HirStmt::Call {
                    decl_id: bytes_at_decl,
                    src_dst: RegId::new(8),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        positional: vec![RegId::new(7)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: bytes_length_decl,
                    src_dst: RegId::new(9),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(8)),
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(9) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 10,
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
    .expect("empty bytes at should lower on a typed bytes global");

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
        "expected empty fixed binary slice to feed bytes length as zero"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("empty typed bytes global bytes at should compile through codegen");
}

#[test]
fn test_lower_bytes_reverse_on_typed_bytes_global_copies_reversed_bytes() {
    let define_decl = DeclId::new(10_625);
    let global_get_decl = DeclId::new(10_626);
    let reverse_decl = DeclId::new(10_627);
    let starts_with_decl = DeclId::new(10_628);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (reverse_decl, "bytes reverse".to_string()),
        (starts_with_decl, "bytes starts-with".to_string()),
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
                    lit: HirLiteral::String("bytes:4".into()),
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
                    decl_id: reverse_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Binary(vec![0, 0]),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
                        positional: vec![RegId::new(5)],
                        ..HirCallArgs::default()
                    },
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
    .expect("bytes reverse should lower on a typed bytes global");

    let byte_load_offsets = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter_map(|inst| match inst {
            MirInst::Load {
                offset,
                ty: MirType::U8,
                ..
            } => Some(*offset),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        byte_load_offsets.contains(&3) && byte_load_offsets.contains(&2),
        "expected bytes reverse to read source offsets 3 and 2 first, got {byte_load_offsets:?}"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StoreSlot { offset: 0, .. })),
        "expected bytes reverse to materialize the reversed bytes in a stack slot"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed bytes global bytes reverse should compile through codegen");
}

#[test]
fn test_lower_bytes_add_on_typed_bytes_global_copies_inserted_bytes() {
    let define_decl = DeclId::new(10_629);
    let global_get_decl = DeclId::new(10_630);
    let add_decl = DeclId::new(10_631);
    let starts_with_decl = DeclId::new(10_632);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (add_decl, "bytes add".to_string()),
        (starts_with_decl, "bytes starts-with".to_string()),
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
                    lit: HirLiteral::String("bytes:4".into()),
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
                    lit: HirLiteral::Binary(vec![0xff, 0xee]),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(2),
                },
                HirStmt::Call {
                    decl_id: add_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        positional: vec![RegId::new(4)],
                        named: vec![(b"index".to_vec(), RegId::new(5))],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::Binary(vec![0, 0, 0xff]),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
                    src_dst: RegId::new(8),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(6)),
                        positional: vec![RegId::new(7)],
                        ..HirCallArgs::default()
                    },
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bytes add should lower on a typed bytes global");

    assert!(
        result.program.main.blocks.iter().any(|block| {
            block.instructions.iter().any(|inst| {
                matches!(
                    inst,
                    MirInst::StoreSlot {
                        offset: 2,
                        val: MirValue::Const(255),
                        ty: MirType::U8,
                        ..
                    }
                )
            })
        }),
        "expected bytes add to store inserted byte 0xff at output offset 2"
    );
    assert!(
        result.program.main.blocks.iter().any(|block| {
            block.instructions.iter().any(|inst| {
                matches!(
                    inst,
                    MirInst::StoreSlot {
                        offset: 3,
                        val: MirValue::Const(238),
                        ty: MirType::U8,
                        ..
                    }
                )
            })
        }),
        "expected bytes add to store inserted byte 0xee at output offset 3"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed bytes global bytes add should compile through codegen");
}

#[test]
fn test_lower_bytes_replace_all_on_typed_bytes_global_rewrites_equal_length_bytes() {
    let define_decl = DeclId::new(10_633);
    let global_get_decl = DeclId::new(10_634);
    let replace_decl = DeclId::new(10_635);
    let starts_with_decl = DeclId::new(10_636);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (replace_decl, "bytes replace".to_string()),
        (starts_with_decl, "bytes starts-with".to_string()),
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
                    lit: HirLiteral::String("bytes:4".into()),
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
                    lit: HirLiteral::Binary(vec![0]),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Binary(vec![0xff]),
                },
                HirStmt::Call {
                    decl_id: replace_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        positional: vec![RegId::new(4), RegId::new(5)],
                        flags: vec![b"all".to_vec()],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::Binary(vec![0xff, 0xff]),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
                    src_dst: RegId::new(8),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(6)),
                        positional: vec![RegId::new(7)],
                        ..HirCallArgs::default()
                    },
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bytes replace should lower on a typed bytes global");

    assert!(
        result.program.main.blocks.iter().any(|block| {
            matches!(block.terminator, MirInst::Branch { .. })
                && block.instructions.iter().any(|inst| {
                    matches!(
                        inst,
                        MirInst::Load {
                            offset: 0,
                            ty: MirType::U8,
                            ..
                        }
                    )
                })
        }),
        "expected bytes replace to branch on fixed binary byte comparisons"
    );
    assert!(
        result.program.main.blocks.iter().any(|block| {
            block.instructions.iter().any(|inst| {
                matches!(
                    inst,
                    MirInst::StoreSlot {
                        val: MirValue::Const(255),
                        ty: MirType::U8,
                        ..
                    }
                )
            })
        }),
        "expected bytes replace to store replacement byte 0xff"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed bytes global bytes replace should compile through codegen");
}

#[test]
fn test_lower_bytes_remove_on_typed_bytes_global_accepts_impossible_match() {
    let define_decl = DeclId::new(10_641);
    let global_get_decl = DeclId::new(10_642);
    let remove_decl = DeclId::new(10_643);
    let starts_with_decl = DeclId::new(10_644);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (remove_decl, "bytes remove".to_string()),
        (starts_with_decl, "bytes starts-with".to_string()),
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
                    lit: HirLiteral::String("bytes:4".into()),
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
                    lit: HirLiteral::Binary(vec![0, 0, 0, 0, 0]),
                },
                HirStmt::Call {
                    decl_id: remove_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        positional: vec![RegId::new(4)],
                        flags: vec![b"all".to_vec(), b"end".to_vec()],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Binary(vec![0, 0, 0, 0]),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        positional: vec![RegId::new(6)],
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
    .expect("bytes remove should lower typed bytes input when the pattern cannot match");

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
        "expected bytes remove no-match lowering to materialize a stack-backed binary"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed bytes global no-match bytes remove should compile through codegen");
}

#[test]
fn test_lower_bytes_remove_on_typed_bytes_global_rejects_matchable_pattern() {
    let define_decl = DeclId::new(10_645);
    let global_get_decl = DeclId::new(10_646);
    let remove_decl = DeclId::new(10_647);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (remove_decl, "bytes remove".to_string()),
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
                    lit: HirLiteral::String("bytes:4".into()),
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
                    lit: HirLiteral::Binary(vec![0]),
                },
                HirStmt::Call {
                    decl_id: remove_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        positional: vec![RegId::new(4)],
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("bytes remove should reject matchable typed bytes input");

    assert!(
        err.to_string().contains(
            "bytes remove on typed fixed-size binary input requires a pattern longer than the input length"
        ),
        "unexpected error: {err}"
    );
}

fn assert_lower_bytes_index_of_on_typed_bytes_global(
    search_from_end: bool,
    expected_first_load_offset: i32,
) {
    let define_decl = DeclId::new(if search_from_end { 10_606 } else { 10_603 });
    let global_get_decl = DeclId::new(if search_from_end { 10_607 } else { 10_604 });
    let index_of_decl = DeclId::new(if search_from_end { 10_608 } else { 10_605 });
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (index_of_decl, "bytes index-of".to_string()),
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
                    lit: HirLiteral::String("bytes:4".into()),
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
                    lit: HirLiteral::Binary(vec![0, 0]),
                },
                HirStmt::Call {
                    decl_id: index_of_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        positional: vec![RegId::new(4)],
                        flags: if search_from_end {
                            vec![b"end".to_vec()]
                        } else {
                            Vec::new()
                        },
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
    .expect("bytes index-of should lower on a typed bytes global");

    let byte_load_offsets = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter_map(|inst| match inst {
            MirInst::Load {
                offset,
                ty: MirType::U8,
                ..
            } => Some(*offset),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        byte_load_offsets.first().copied(),
        Some(expected_first_load_offset),
        "expected fixed binary index-of first byte probe offset {expected_first_load_offset}, got {byte_load_offsets:?}"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| matches!(block.terminator, MirInst::Branch { .. })),
        "expected fixed binary index-of to branch on byte comparisons"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed bytes global bytes index-of should compile through codegen");
}

#[test]
fn test_lower_bytes_index_of_on_typed_bytes_global_compares_fixed_bytes() {
    assert_lower_bytes_index_of_on_typed_bytes_global(false, 0);
}

#[test]
fn test_lower_bytes_index_of_end_on_typed_bytes_global_compares_from_last_offset() {
    assert_lower_bytes_index_of_on_typed_bytes_global(true, 2);
}

fn assert_lower_bytes_index_of_all_on_typed_bytes_global(
    search_from_end: bool,
    expected_probe_offset: i32,
) {
    let define_decl = DeclId::new(if search_from_end { 10_612 } else { 10_609 });
    let global_get_decl = DeclId::new(if search_from_end { 10_613 } else { 10_610 });
    let index_of_decl = DeclId::new(if search_from_end { 10_614 } else { 10_611 });
    let get_decl = DeclId::new(if search_from_end { 10_616 } else { 10_615 });
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (index_of_decl, "bytes index-of".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let mut flags = vec![b"all".to_vec()];
    if search_from_end {
        flags.push(b"end".to_vec());
    }

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
                    lit: HirLiteral::String("bytes:4".into()),
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
                    lit: HirLiteral::Binary(vec![0, 0]),
                },
                HirStmt::Call {
                    decl_id: index_of_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        positional: vec![RegId::new(4)],
                        flags,
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        positional: vec![RegId::new(6)],
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
    .expect("bytes index-of --all should lower on a typed bytes global");

    assert!(
        result.program.main.blocks.iter().any(|block| {
            block
                .instructions
                .iter()
                .any(|inst| matches!(inst, MirInst::ListNew { max_len: 2, .. }))
        }),
        "expected fixed binary index-of --all to allocate a two-item offset list"
    );
    assert!(
        result.program.main.blocks.iter().any(|block| {
            block
                .instructions
                .iter()
                .any(|inst| matches!(inst, MirInst::ListPush { .. }))
        }),
        "expected fixed binary index-of --all to push matching offsets"
    );

    let byte_load_offsets = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter_map(|inst| match inst {
            MirInst::Load {
                offset,
                ty: MirType::U8,
                ..
            } => Some(*offset),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        byte_load_offsets.contains(&expected_probe_offset),
        "expected fixed binary index-of --all byte probe offset {expected_probe_offset}, got {byte_load_offsets:?}"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed bytes global bytes index-of --all should compile through codegen");
}

#[test]
fn test_lower_bytes_index_of_all_on_typed_bytes_global_builds_offset_list() {
    assert_lower_bytes_index_of_all_on_typed_bytes_global(false, 0);
}

#[test]
fn test_lower_bytes_index_of_all_end_on_typed_bytes_global_builds_reverse_offset_list() {
    assert_lower_bytes_index_of_all_on_typed_bytes_global(true, 2);
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
fn test_lower_length_on_typed_bytes_global_uses_declared_len() {
    let define_decl = DeclId::new(9082);
    let global_get_decl = DeclId::new(9083);
    let length_decl = DeclId::new(9084);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (length_decl, "length".to_string()),
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
                    lit: HirLiteral::String("bytes:8".into()),
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
                    decl_id: length_decl,
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
    .expect("length should lower on a typed bytes global");

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
        "expected length to use the declared bytes:N length"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed bytes global length should compile through codegen");
}

#[test]
fn test_lower_is_empty_on_typed_bytes_global_uses_declared_len() {
    let define_decl = DeclId::new(9085);
    let global_get_decl = DeclId::new(9086);
    let is_empty_decl = DeclId::new(9087);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (is_empty_decl, "is-empty".to_string()),
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
                    lit: HirLiteral::String("bytes:8".into()),
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
                    decl_id: is_empty_decl,
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
    .expect("is-empty should lower on a typed bytes global");

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
        "expected is-empty to see bytes:8 as non-empty"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed bytes global is-empty should compile through codegen");
}

#[test]
fn test_lower_bytes_length_on_typed_bytes_array_global_materializes_lengths() {
    let define_decl = DeclId::new(9088);
    let global_get_decl = DeclId::new(9089);
    let bytes_length_decl = DeclId::new(9090);
    let get_decl = DeclId::new(9091);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (bytes_length_decl, "bytes length".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("buffers".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{bytes:4:2}".into()),
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
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5)],
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
    .expect("bytes length should lower on a typed fixed-array bytes global");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListNew { max_len: 2, .. })),
        "expected bytes length on array{{bytes:4:2}} to materialize a two-item lengths list"
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
                MirInst::ListGet {
                    idx: MirValue::Const(1),
                    ..
                }
            )),
        "expected get 1 to consume the materialized lengths list"
    );
    assert_eq!(result.readonly_globals.len(), 1);
    assert_eq!(
        result.readonly_globals[0].data,
        vec![4, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed fixed-array bytes length should compile through codegen");
}

#[test]
fn test_lower_bytes_collect_on_typed_bytes_global_array_concatenates_elements() {
    let define_decl = DeclId::new(10_637);
    let global_get_decl = DeclId::new(10_638);
    let collect_decl = DeclId::new(10_639);
    let starts_with_decl = DeclId::new(10_640);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (collect_decl, "bytes collect".to_string()),
        (starts_with_decl, "bytes starts-with".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("buffers".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{bytes:2:2}".into()),
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
                    lit: HirLiteral::Binary(vec![0xff]),
                },
                HirStmt::Call {
                    decl_id: collect_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        positional: vec![RegId::new(4)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Binary(vec![0, 0, 0xff, 0]),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        positional: vec![RegId::new(6)],
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
    .expect("bytes collect should lower on a typed fixed-array bytes global");

    let byte_load_offsets = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter_map(|inst| match inst {
            MirInst::Load {
                offset,
                ty: MirType::U8,
                ..
            } => Some(*offset),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        byte_load_offsets.contains(&0) && byte_load_offsets.contains(&2),
        "expected bytes collect to copy fixed-array item offsets 0 and 2, got {byte_load_offsets:?}"
    );
    assert!(
        result.program.main.blocks.iter().any(|block| {
            block.instructions.iter().any(|inst| {
                matches!(
                    inst,
                    MirInst::StoreSlot {
                        offset: 2,
                        val: MirValue::Const(255),
                        ty: MirType::U8,
                        ..
                    }
                )
            })
        }),
        "expected bytes collect to store separator byte at output offset 2"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed fixed-array bytes collect should compile through codegen");
}

#[test]
fn test_lower_bytes_split_on_typed_bytes_global_accepts_impossible_separator() {
    let define_decl = DeclId::new(10_648);
    let global_get_decl = DeclId::new(10_649);
    let split_decl = DeclId::new(10_650);
    let collect_decl = DeclId::new(10_651);
    let starts_with_decl = DeclId::new(10_652);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (split_decl, "bytes split".to_string()),
        (collect_decl, "bytes collect".to_string()),
        (starts_with_decl, "bytes starts-with".to_string()),
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
                    lit: HirLiteral::String("bytes:2".into()),
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
                    lit: HirLiteral::Binary(vec![0, 0, 0]),
                },
                HirStmt::Call {
                    decl_id: split_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        positional: vec![RegId::new(4)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: collect_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::Binary(vec![0, 0]),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
                    src_dst: RegId::new(8),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(6)),
                        positional: vec![RegId::new(7)],
                        ..HirCallArgs::default()
                    },
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("bytes split should lower typed bytes input when the separator cannot match");

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
        "expected bytes split no-match lowering to materialize a stack-backed fixed array"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed bytes global no-match bytes split should compile through codegen");
}

#[test]
fn test_lower_bytes_split_on_typed_bytes_global_rejects_matchable_separator() {
    let define_decl = DeclId::new(10_653);
    let global_get_decl = DeclId::new(10_654);
    let split_decl = DeclId::new(10_655);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (split_decl, "bytes split".to_string()),
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
                    lit: HirLiteral::String("bytes:2".into()),
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
                    lit: HirLiteral::Binary(vec![0]),
                },
                HirStmt::Call {
                    decl_id: split_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        positional: vec![RegId::new(4)],
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("bytes split should reject matchable typed bytes input");

    assert!(
        err.to_string().contains(
            "bytes split on typed fixed-size binary input requires a separator longer than the input length"
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_describe_on_typed_bytes_global_uses_binary_metadata() {
    let define_decl = DeclId::new(9092);
    let global_get_decl = DeclId::new(9093);
    let describe_decl = DeclId::new(9094);
    let starts_with_decl = DeclId::new(9095);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (describe_decl, "describe".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
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
                    lit: HirLiteral::String("bytes:8".into()),
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
                    decl_id: describe_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String("binary".into()),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5)],
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
    .expect("describe should lower on a typed bytes global");

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
                } if bytes.starts_with(b"binary\0")
            )),
        "expected describe to materialize binary for bytes:N globals"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed bytes global describe should compile through codegen");
}

#[test]
fn test_lower_describe_on_typed_bytes_array_global_uses_binary_list_metadata() {
    let define_decl = DeclId::new(9096);
    let global_get_decl = DeclId::new(9097);
    let describe_decl = DeclId::new(9098);
    let starts_with_decl = DeclId::new(9099);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (describe_decl, "describe".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("buffers".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{bytes:4:2}".into()),
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
                    decl_id: describe_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String("list<binary>".into()),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5)],
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
    .expect("describe should lower on a typed fixed-array bytes global");

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
                } if bytes.starts_with(b"list<binary>\0")
            )),
        "expected describe to materialize list<binary> for array{{bytes:N:M}} globals"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed fixed-array bytes describe should compile through codegen");
}

#[test]
fn test_lower_first_on_typed_bytes_array_global_projects_binary_element() {
    let define_decl = DeclId::new(9100);
    let global_get_decl = DeclId::new(9101);
    let first_decl = DeclId::new(9102);
    let bytes_length_decl = DeclId::new(9103);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (first_decl, "first".to_string()),
        (bytes_length_decl, "bytes length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("buffers".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{bytes:4:2}".into()),
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
                    decl_id: first_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: bytes_length_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
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
    .expect("first should project typed fixed-array binary elements");

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
        "expected first array{{bytes:4:2}} element to retain binary length metadata"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed fixed-array bytes first should compile through codegen");
}

#[test]
fn test_lower_last_on_typed_u32_array_global_projects_scalar_element() {
    let define_decl = DeclId::new(9104);
    let global_get_decl = DeclId::new(9105);
    let last_decl = DeclId::new(9106);
    let count_decl = DeclId::new(9107);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (last_decl, "last".to_string()),
        (count_decl, "count".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    decl_id: last_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: count_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs::default(),
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
    .expect("last should project typed fixed-array scalar elements");

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
        "expected last array{{u32:2}} to load a U32 element"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed fixed-array u32 last should compile through codegen");
}

#[test]
fn test_lower_take_on_typed_bytes_array_global_preserves_binary_slice_metadata() {
    let define_decl = DeclId::new(9108);
    let global_get_decl = DeclId::new(9109);
    let take_decl = DeclId::new(9110);
    let bytes_length_decl = DeclId::new(9111);
    let get_decl = DeclId::new(9117);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (take_decl, "take".to_string()),
        (bytes_length_decl, "bytes length".to_string()),
        (get_decl, "get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("buffers".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{bytes:4:2}".into()),
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
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: take_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        positional: vec![RegId::new(4)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: bytes_length_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(8),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(6)),
                        positional: vec![RegId::new(7)],
                        ..HirCallArgs::default()
                    },
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("take should project typed fixed-array binary slices");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListNew { max_len: 1, .. })),
        "expected bytes length on take 1 array{{bytes:4:2}} to materialize one length"
    );
    assert!(
        result
            .readonly_globals
            .iter()
            .any(|global| global.data == 4i64.to_le_bytes().to_vec()),
        "expected typed binary slice element length metadata to be preserved"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed fixed-array bytes take slice should compile through codegen");
}

#[test]
fn test_lower_last_count_on_typed_u32_array_global_offsets_slice_for_get() {
    let define_decl = DeclId::new(9112);
    let global_get_decl = DeclId::new(9113);
    let last_decl = DeclId::new(9114);
    let get_decl = DeclId::new(9115);
    let count_decl = DeclId::new(9116);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (last_decl, "last".to_string()),
        (get_decl, "get".to_string()),
        (count_decl, "count".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: last_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        positional: vec![RegId::new(4)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        positional: vec![RegId::new(6)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: count_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs::default(),
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
    .expect("last count should project typed fixed-array scalar slices");

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
                    rhs: MirValue::Const(4),
                    ..
                }
            )),
        "expected last 1 on array{{u32:2}} to offset the slice by one u32 element"
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
        "expected get 0 from last-count slice to load a U32 element"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed fixed-array u32 last-count slice should compile through codegen");
}

#[test]
fn test_lower_skip_on_typed_u32_array_global_preserves_slice_length() {
    let define_decl = DeclId::new(9118);
    let global_get_decl = DeclId::new(9119);
    let skip_decl = DeclId::new(9120);
    let length_decl = DeclId::new(9121);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (skip_decl, "skip".to_string()),
        (length_decl, "length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: skip_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        positional: vec![RegId::new(4)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
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
    .expect("skip should project typed fixed-array scalar slices");

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
                    rhs: MirValue::Const(4),
                    ..
                }
            )),
        "expected skip 1 on array{{u32:2}} to offset the slice by one u32 element"
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
        "expected length on typed fixed-array slice to use the projected slice length"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed fixed-array u32 skip slice should compile through codegen");
}

#[test]
fn test_lower_is_empty_on_typed_u32_array_global_uses_declared_len() {
    let define_decl = DeclId::new(9122);
    let global_get_decl = DeclId::new(9123);
    let is_empty_decl = DeclId::new(9124);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (is_empty_decl, "is-empty".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    decl_id: is_empty_decl,
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
    .expect("is-empty should lower on typed fixed-array scalar globals");

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
        "expected is-empty to see array{{u32:2}} as non-empty"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed fixed-array u32 is-empty should compile through codegen");
}

#[test]
fn test_lower_is_not_empty_on_typed_u32_array_global_uses_declared_len() {
    let define_decl = DeclId::new(9125);
    let global_get_decl = DeclId::new(9126);
    let is_not_empty_decl = DeclId::new(9127);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (is_not_empty_decl, "is-not-empty".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    decl_id: is_not_empty_decl,
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
    .expect("is-not-empty should lower on typed fixed-array scalar globals");

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
        "expected is-not-empty to see array{{u32:2}} as non-empty"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed fixed-array u32 is-not-empty should compile through codegen");
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
fn test_lower_constant_record_empty_binary_field_without_typed_consumer_names_field_path() {
    let mut meta = Record::with_capacity(1);
    meta.push("comm", Value::binary(Vec::new(), Span::test_data()));

    let mut state = Record::with_capacity(2);
    state.push("pid", Value::int(7, Span::test_data()));
    state.push("meta", Value::record(meta, Span::test_data()));

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
    assert!(
        err.to_string().contains("record field 'meta.comm'"),
        "expected nested record field path in diagnostic, got: {err}"
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
        err.to_string().contains(
            "global type spec 'list:int:4' initializer[0] requires a numeric constant item, found bool"
        ),
        "unexpected error: {err}"
    );
}

fn lower_global_define_type_spec_error(type_spec: &str) -> CompileError {
    let define_decl = DeclId::new(9212);
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
                    lit: HirLiteral::String(type_spec.into()),
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

    lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("global-define --type should reject malformed type specs")
}

#[test]
fn test_lower_global_define_type_nested_record_rejects_malformed_field_path() {
    let err = lower_global_define_type_spec_error("record{inner:record{bad}}");

    assert!(
        err.to_string()
            .contains("record field 'inner.bad' must use name:type syntax"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_global_define_type_nested_record_rejects_invalid_array_length_path() {
    let err = lower_global_define_type_spec_error("record{items:array{u32:x}}");

    assert!(
        err.to_string()
            .contains("record field 'items' type spec 'array{u32:x}' has an invalid array length"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_global_define_type_nested_record_rejects_unsupported_type_path() {
    let err = lower_global_define_type_spec_error("record{inner:bogus}");

    assert!(
        err.to_string()
            .contains("unsupported record field 'inner' type spec 'bogus'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_global_define_type_nested_record_rejects_duplicate_field_path() {
    let err = lower_global_define_type_spec_error("record{inner:record{pid:u32,pid:u64}}");

    assert!(
        err.to_string()
            .contains("record field 'inner.pid' is duplicated"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_global_define_type_record_candidate_rejects_unmatched_braces() {
    let err = lower_global_define_type_spec_error("record{inner:record{pid:u32");

    assert!(
        err.to_string()
            .contains("global type spec 'record{inner:record{pid:u32' has unmatched '{' braces"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_global_define_type_nested_record_rejects_unexpected_field_path() {
    let define_decl = DeclId::new(9210);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);

    let mut inner = Record::with_capacity(2);
    inner.push("pid", Value::int(7, Span::test_data()));
    inner.push("extra", Value::bool(true, Span::test_data()));

    let mut state = Record::with_capacity(1);
    state.push("inner", Value::record(inner, Span::test_data()));

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
                    lit: HirLiteral::String("record{inner:record{pid:int}}".into()),
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
    .expect_err("global-define --type record should reject nested unexpected fields");

    assert!(
        err.to_string().contains("unexpected field 'inner.extra'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_lower_global_define_type_array_rejects_bad_item_index_path() {
    let define_decl = DeclId::new(9211);
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
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
    .expect_err("global-define --type array should reject non-numeric items");

    assert!(
        err.to_string().contains(
            "global type spec 'array{u32:2}' initializer[0] requires a u32-compatible constant"
        ),
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
fn test_lower_global_define_type_string_array_get_preserves_string_semantics() {
    let define_decl = DeclId::new(10_510);
    let global_get_decl = DeclId::new(10_511);
    let get_decl = DeclId::new(10_512);
    let length_decl = DeclId::new(10_513);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (get_decl, "get".to_string()),
        (length_decl, "str length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:2}".into()),
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
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
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
    .expect("global-define --type array{string:N:N} get item should lower as a tracked string");

    assert_eq!(result.data_globals.len(), 0);
    assert_eq!(result.bss_globals.len(), 1);
    assert_eq!(result.bss_globals[0].name, "__nu_global_names");
    assert_eq!(result.bss_globals[0].size, 48);
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
        "expected fixed-array string get to materialize a tracked stack string"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed string array get consumed by str length should compile through codegen");
}

#[test]
fn test_lower_global_define_type_string_array_str_join_materializes_tracked_string() {
    let define_decl = DeclId::new(10_544);
    let global_get_decl = DeclId::new(10_545);
    let join_decl = DeclId::new(10_546);
    let length_decl = DeclId::new(10_547);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (join_decl, "str join".to_string()),
        (length_decl, "str length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:2}".into()),
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
                    lit: HirLiteral::String("-".into()),
                },
                HirStmt::Call {
                    decl_id: join_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
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
    .expect("global-define --type array{string:N:N} str join should lower as a tracked string");

    let string_slot_appends = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::StringAppend {
                    val_type: StringAppendType::StringSlot { max_len: 8, .. },
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        string_slot_appends, 2,
        "expected str join to append both fixed-array string elements"
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
                MirInst::StringAppend {
                    val_type: StringAppendType::Literal { bytes },
                    ..
                } if bytes == b"-"
            )),
        "expected str join to append the literal separator"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints)).expect(
        "typed string array str join consumed by str length should compile through codegen",
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_join_rejects_oversized_element_cap() {
    let define_decl = DeclId::new(10_548);
    let global_get_decl = DeclId::new(10_549);
    let join_decl = DeclId::new(10_550);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (join_decl, "str join".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:65:1}".into()),
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
                    decl_id: join_decl,
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
    .expect_err("str join should reject typed string elements beyond the append copy cap");

    assert!(
        err.to_string()
            .contains("supports string elements up to 64 bytes"),
        "expected oversized element-cap diagnostic, got: {err}"
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_length_materializes_numeric_list() {
    let define_decl = DeclId::new(10_551);
    let global_get_decl = DeclId::new(10_552);
    let length_decl = DeclId::new(10_553);
    let sum_decl = DeclId::new(10_554);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (length_decl, "str length".to_string()),
        (sum_decl, "math sum".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:2}".into()),
                },
                HirStmt::LoadValue {
                    dst: RegId::new(2),
                    val: Box::new(Value::list(
                        vec![
                            Value::string("aa".to_string(), Span::unknown()),
                            Value::string("bbb".to_string(), Span::unknown()),
                        ],
                        Span::unknown(),
                    )),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        pipeline_input: Some(RegId::new(2)),
                        ..HirCallArgs::default()
                    },
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
                    decl_id: length_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: sum_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
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
    .expect("global-define --type array{string:N:N} str length should lower as a numeric list");

    let pushes = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::ListPush { .. }))
        .count();
    assert_eq!(
        pushes, 2,
        "expected str length to push each fixed-array string length"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListGet { .. })),
        "expected math sum to consume the str length numeric-list result"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints)).expect(
        "typed string array str length consumed by math sum should compile through codegen",
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_length_chars_rejects_runtime_array() {
    let define_decl = DeclId::new(10_555);
    let global_get_decl = DeclId::new(10_556);
    let length_decl = DeclId::new(10_557);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (length_decl, "str length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:2}".into()),
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
                    decl_id: length_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        flags: vec![b"chars".to_vec()],
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
    .expect_err("str length --chars should remain compile-time-only for typed string arrays");

    assert!(
        err.to_string()
            .contains("str length requires compile-time known string input"),
        "expected compile-time-only length-mode diagnostic, got: {err}"
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_length_rejects_over_capacity_list() {
    let define_decl = DeclId::new(10_558);
    let global_get_decl = DeclId::new(10_559);
    let length_decl = DeclId::new(10_560);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (length_decl, "str length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:61}".into()),
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
                    decl_id: length_decl,
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
    .expect_err("str length should reject typed string arrays beyond stack list capacity");

    assert!(
        err.to_string()
            .contains("stack-backed numeric list capacity 60"),
        "expected stack-list capacity diagnostic, got: {err}"
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_starts_with_materializes_bool_list() {
    let define_decl = DeclId::new(10_561);
    let global_get_decl = DeclId::new(10_562);
    let starts_with_decl = DeclId::new(10_563);
    let sum_decl = DeclId::new(10_564);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
        (sum_decl, "math sum".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:3}".into()),
                },
                HirStmt::LoadValue {
                    dst: RegId::new(2),
                    val: Box::new(Value::list(
                        vec![
                            Value::string("aa".to_string(), Span::unknown()),
                            Value::string("ab".to_string(), Span::unknown()),
                            Value::string("ba".to_string(), Span::unknown()),
                        ],
                        Span::unknown(),
                    )),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        pipeline_input: Some(RegId::new(2)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String("a".into()),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5)],
                        pipeline_input: Some(RegId::new(4)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: sum_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(6)),
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
    .expect("global-define --type array{string:N:N} str starts-with should lower as a bool list");

    let pushes = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::ListPush { .. }))
        .count();
    assert_eq!(
        pushes, 3,
        "expected str starts-with to push each fixed-array string predicate result"
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
                    ty: MirType::U8,
                    ..
                }
            )),
        "expected str starts-with to compare the first byte of each fixed-array string"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints)).expect(
        "typed string array str starts-with consumed by math sum should compile through codegen",
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_starts_with_ignore_case_rejects_runtime_array() {
    let define_decl = DeclId::new(10_565);
    let global_get_decl = DeclId::new(10_566);
    let starts_with_decl = DeclId::new(10_567);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:2}".into()),
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
                    lit: HirLiteral::String("a".into()),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(3)),
                        flags: vec![b"ignore-case".to_vec()],
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("str starts-with --ignore-case should remain compile-time-only for typed arrays");

    assert!(
        err.to_string()
            .contains("str starts-with --ignore-case requires compile-time known string input"),
        "expected compile-time-only ignore-case diagnostic, got: {err}"
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_starts_with_rejects_over_capacity_list() {
    let define_decl = DeclId::new(10_568);
    let global_get_decl = DeclId::new(10_569);
    let starts_with_decl = DeclId::new(10_570);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:61}".into()),
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
                    lit: HirLiteral::String("a".into()),
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("str starts-with should reject typed string arrays beyond stack list capacity");

    assert!(
        err.to_string()
            .contains("stack-backed numeric list capacity 60"),
        "expected stack-list capacity diagnostic, got: {err}"
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_ends_with_materializes_bool_list() {
    let define_decl = DeclId::new(10_571);
    let global_get_decl = DeclId::new(10_572);
    let ends_with_decl = DeclId::new(10_573);
    let sum_decl = DeclId::new(10_574);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (ends_with_decl, "str ends-with".to_string()),
        (sum_decl, "math sum".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:3}".into()),
                },
                HirStmt::LoadValue {
                    dst: RegId::new(2),
                    val: Box::new(Value::list(
                        vec![
                            Value::string("aa".to_string(), Span::unknown()),
                            Value::string("ba".to_string(), Span::unknown()),
                            Value::string("bb".to_string(), Span::unknown()),
                        ],
                        Span::unknown(),
                    )),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        pipeline_input: Some(RegId::new(2)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String("a".into()),
                },
                HirStmt::Call {
                    decl_id: ends_with_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5)],
                        pipeline_input: Some(RegId::new(4)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: sum_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(6)),
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
    .expect("global-define --type array{string:N:N} str ends-with should lower as a bool list");

    let pushes = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::ListPush { .. }))
        .count();
    assert_eq!(
        pushes, 3,
        "expected str ends-with to push each fixed-array string predicate result"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { len: 1, .. })),
        "expected str ends-with to compare suffix bytes through StrCmp"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints)).expect(
        "typed string array str ends-with consumed by math sum should compile through codegen",
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_ends_with_ignore_case_rejects_runtime_array() {
    let define_decl = DeclId::new(10_575);
    let global_get_decl = DeclId::new(10_576);
    let ends_with_decl = DeclId::new(10_577);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (ends_with_decl, "str ends-with".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:2}".into()),
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
                    lit: HirLiteral::String("a".into()),
                },
                HirStmt::Call {
                    decl_id: ends_with_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(3)),
                        flags: vec![b"ignore-case".to_vec()],
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("str ends-with --ignore-case should remain compile-time-only for typed arrays");

    assert!(
        err.to_string()
            .contains("str ends-with --ignore-case requires compile-time known string input"),
        "expected compile-time-only ignore-case diagnostic, got: {err}"
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_ends_with_rejects_over_capacity_list() {
    let define_decl = DeclId::new(10_578);
    let global_get_decl = DeclId::new(10_579);
    let ends_with_decl = DeclId::new(10_580);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (ends_with_decl, "str ends-with".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:61}".into()),
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
                    lit: HirLiteral::String("a".into()),
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("str ends-with should reject typed string arrays beyond stack list capacity");

    assert!(
        err.to_string()
            .contains("stack-backed numeric list capacity 60"),
        "expected stack-list capacity diagnostic, got: {err}"
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_contains_materializes_bool_list() {
    let define_decl = DeclId::new(10_581);
    let global_get_decl = DeclId::new(10_582);
    let contains_decl = DeclId::new(10_583);
    let sum_decl = DeclId::new(10_584);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (contains_decl, "str contains".to_string()),
        (sum_decl, "math sum".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:3}".into()),
                },
                HirStmt::LoadValue {
                    dst: RegId::new(2),
                    val: Box::new(Value::list(
                        vec![
                            Value::string("aa".to_string(), Span::unknown()),
                            Value::string("bb".to_string(), Span::unknown()),
                            Value::string("ca".to_string(), Span::unknown()),
                        ],
                        Span::unknown(),
                    )),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        pipeline_input: Some(RegId::new(2)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String("a".into()),
                },
                HirStmt::Call {
                    decl_id: contains_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5)],
                        pipeline_input: Some(RegId::new(4)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: sum_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(6)),
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
    .expect("global-define --type array{string:N:N} str contains should lower as a bool list");

    let pushes = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::ListPush { .. }))
        .count();
    assert_eq!(
        pushes, 3,
        "expected str contains to push each fixed-array string predicate result"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { len: 1, .. })),
        "expected str contains to compare substring bytes through StrCmp"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints)).expect(
        "typed string array str contains consumed by math sum should compile through codegen",
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_contains_ignore_case_rejects_runtime_array() {
    let define_decl = DeclId::new(10_585);
    let global_get_decl = DeclId::new(10_586);
    let contains_decl = DeclId::new(10_587);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (contains_decl, "str contains".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:2}".into()),
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
                    lit: HirLiteral::String("a".into()),
                },
                HirStmt::Call {
                    decl_id: contains_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(3)),
                        flags: vec![b"ignore-case".to_vec()],
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("str contains --ignore-case should remain compile-time-only for typed arrays");

    assert!(
        err.to_string()
            .contains("str contains --ignore-case requires compile-time known string input"),
        "expected compile-time-only ignore-case diagnostic, got: {err}"
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_contains_rejects_over_capacity_list() {
    let define_decl = DeclId::new(10_588);
    let global_get_decl = DeclId::new(10_589);
    let contains_decl = DeclId::new(10_590);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (contains_decl, "str contains".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:61}".into()),
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
                    lit: HirLiteral::String("a".into()),
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("str contains should reject typed string arrays beyond stack list capacity");

    assert!(
        err.to_string()
            .contains("stack-backed numeric list capacity 60"),
        "expected stack-list capacity diagnostic, got: {err}"
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_index_of_materializes_numeric_list() {
    let define_decl = DeclId::new(10_591);
    let global_get_decl = DeclId::new(10_592);
    let index_of_decl = DeclId::new(10_593);
    let sum_decl = DeclId::new(10_594);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (index_of_decl, "str index-of".to_string()),
        (sum_decl, "math sum".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:3}".into()),
                },
                HirStmt::LoadValue {
                    dst: RegId::new(2),
                    val: Box::new(Value::list(
                        vec![
                            Value::string("xa".to_string(), Span::unknown()),
                            Value::string("ba".to_string(), Span::unknown()),
                            Value::string("aa".to_string(), Span::unknown()),
                        ],
                        Span::unknown(),
                    )),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        pipeline_input: Some(RegId::new(2)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String("a".into()),
                },
                HirStmt::Call {
                    decl_id: index_of_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5)],
                        pipeline_input: Some(RegId::new(4)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: sum_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(6)),
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
    .expect("global-define --type array{string:N:N} str index-of should lower as a numeric list");

    let pushes = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| matches!(inst, MirInst::ListPush { .. }))
        .count();
    assert_eq!(
        pushes, 3,
        "expected str index-of to push each fixed-array string index result"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { len: 1, .. })),
        "expected str index-of to compare substring bytes through StrCmp"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints)).expect(
        "typed string array str index-of consumed by math sum should compile through codegen",
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_index_of_grapheme_rejects_runtime_array() {
    let define_decl = DeclId::new(10_595);
    let global_get_decl = DeclId::new(10_596);
    let index_of_decl = DeclId::new(10_597);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (index_of_decl, "str index-of".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:2}".into()),
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
                    lit: HirLiteral::String("a".into()),
                },
                HirStmt::Call {
                    decl_id: index_of_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(3)),
                        flags: vec![b"grapheme-clusters".to_vec()],
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err(
        "str index-of --grapheme-clusters should remain compile-time-only for typed arrays",
    );

    assert!(
        err.to_string()
            .contains("str index-of --grapheme-clusters requires compile-time known string input"),
        "expected compile-time-only grapheme diagnostic, got: {err}"
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_index_of_rejects_over_capacity_list() {
    let define_decl = DeclId::new(10_598);
    let global_get_decl = DeclId::new(10_599);
    let index_of_decl = DeclId::new(10_600);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (index_of_decl, "str index-of".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:61}".into()),
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
                    lit: HirLiteral::String("a".into()),
                },
                HirStmt::Call {
                    decl_id: index_of_decl,
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("str index-of should reject typed string arrays beyond stack list capacity");

    assert!(
        err.to_string()
            .contains("stack-backed numeric list capacity 60"),
        "expected stack-list capacity diagnostic, got: {err}"
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_index_of_end_materializes_numeric_list() {
    let define_decl = DeclId::new(10_601);
    let global_get_decl = DeclId::new(10_602);
    let index_of_decl = DeclId::new(10_603);
    let sum_decl = DeclId::new(10_604);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (index_of_decl, "str index-of".to_string()),
        (sum_decl, "math sum".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:3}".into()),
                },
                HirStmt::LoadValue {
                    dst: RegId::new(2),
                    val: Box::new(Value::list(
                        vec![
                            Value::string("aba".to_string(), Span::unknown()),
                            Value::string("ba".to_string(), Span::unknown()),
                            Value::string("aa".to_string(), Span::unknown()),
                        ],
                        Span::unknown(),
                    )),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        pipeline_input: Some(RegId::new(2)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String("a".into()),
                },
                HirStmt::Call {
                    decl_id: index_of_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5)],
                        pipeline_input: Some(RegId::new(4)),
                        flags: vec![b"end".to_vec()],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: sum_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(6)),
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
    .expect("typed string array str index-of --end should lower as a numeric list");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "expected str index-of --end to push fixed-array string index results"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints)).expect(
        "typed string array str index-of --end consumed by math sum should compile through codegen",
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_index_of_range_materializes_numeric_list() {
    let define_decl = DeclId::new(10_605);
    let global_get_decl = DeclId::new(10_606);
    let index_of_decl = DeclId::new(10_607);
    let sum_decl = DeclId::new(10_608);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (index_of_decl, "str index-of".to_string()),
        (sum_decl, "math sum".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:3}".into()),
                },
                HirStmt::LoadValue {
                    dst: RegId::new(2),
                    val: Box::new(Value::list(
                        vec![
                            Value::string("xa".to_string(), Span::unknown()),
                            Value::string("ba".to_string(), Span::unknown()),
                            Value::string("aa".to_string(), Span::unknown()),
                        ],
                        Span::unknown(),
                    )),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        pipeline_input: Some(RegId::new(2)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String("a".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(8),
                    lit: HirLiteral::Int(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(9),
                    lit: HirLiteral::Range {
                        start: RegId::new(6),
                        step: RegId::new(7),
                        end: RegId::new(8),
                        inclusion: RangeInclusion::Inclusive,
                    },
                },
                HirStmt::Call {
                    decl_id: index_of_decl,
                    src_dst: RegId::new(10),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5)],
                        named: vec![(b"range".to_vec(), RegId::new(9))],
                        pipeline_input: Some(RegId::new(4)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: sum_decl,
                    src_dst: RegId::new(11),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(10)),
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return {
                src: RegId::new(11),
            },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 12,
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
    .expect("typed string array str index-of --range should lower as a numeric list");

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
                    lhs_offset: 1,
                    len: 1,
                    ..
                }
            )),
        "expected str index-of --range to compare inside the bounded byte range"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints)).expect(
        "typed string array str index-of --range consumed by math sum should compile through codegen",
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_substring_range_feeds_join() {
    let define_decl = DeclId::new(10_609);
    let global_get_decl = DeclId::new(10_610);
    let substring_decl = DeclId::new(10_611);
    let join_decl = DeclId::new(10_612);
    let length_decl = DeclId::new(10_613);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (substring_decl, "str substring".to_string()),
        (join_decl, "str join".to_string()),
        (length_decl, "str length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:3}".into()),
                },
                HirStmt::LoadValue {
                    dst: RegId::new(2),
                    val: Box::new(Value::list(
                        vec![
                            Value::string("abcd".to_string(), Span::unknown()),
                            Value::string("xy".to_string(), Span::unknown()),
                            Value::string("a".to_string(), Span::unknown()),
                        ],
                        Span::unknown(),
                    )),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        pipeline_input: Some(RegId::new(2)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::Int(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(8),
                    lit: HirLiteral::Range {
                        start: RegId::new(5),
                        step: RegId::new(6),
                        end: RegId::new(7),
                        inclusion: RangeInclusion::Inclusive,
                    },
                },
                HirStmt::Call {
                    decl_id: substring_decl,
                    src_dst: RegId::new(9),
                    args: HirCallArgs {
                        positional: vec![RegId::new(8)],
                        pipeline_input: Some(RegId::new(4)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(10),
                    lit: HirLiteral::String(",".into()),
                },
                HirStmt::Call {
                    decl_id: join_decl,
                    src_dst: RegId::new(11),
                    args: HirCallArgs {
                        positional: vec![RegId::new(10)],
                        pipeline_input: Some(RegId::new(9)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(12),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(11)),
                        ..HirCallArgs::default()
                    },
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
    .expect("typed string array str substring range should lower as a fixed string array");

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
                    offset: 9,
                    ty: MirType::U8,
                    ..
                }
            )),
        "expected str substring 1..2 to copy runtime string bytes from element content offset 1"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| matches!(block.terminator, MirInst::Branch { .. })),
        "expected str substring to branch on each runtime string length"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints)).expect(
        "typed string array str substring result consumed by str join should compile through codegen",
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_substring_negative_range_rejects_runtime_array() {
    let define_decl = DeclId::new(10_614);
    let global_get_decl = DeclId::new(10_615);
    let substring_decl = DeclId::new(10_616);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (substring_decl, "str substring".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:1}".into()),
                },
                HirStmt::LoadValue {
                    dst: RegId::new(2),
                    val: Box::new(Value::list(
                        vec![Value::string("abcd".to_string(), Span::unknown())],
                        Span::unknown(),
                    )),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        pipeline_input: Some(RegId::new(2)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(-2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::Int(-1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(8),
                    lit: HirLiteral::Range {
                        start: RegId::new(5),
                        step: RegId::new(6),
                        end: RegId::new(7),
                        inclusion: RangeInclusion::Inclusive,
                    },
                },
                HirStmt::Call {
                    decl_id: substring_decl,
                    src_dst: RegId::new(9),
                    args: HirCallArgs {
                        positional: vec![RegId::new(8)],
                        pipeline_input: Some(RegId::new(4)),
                        ..HirCallArgs::default()
                    },
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(9) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 10,
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
    .expect_err("runtime typed string array str substring should reject negative bounds");

    assert!(
        err.to_string()
            .contains("supports only non-negative byte range starts"),
        "expected negative range diagnostic, got: {err}"
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_replace_all_feeds_join() {
    let define_decl = DeclId::new(10_617);
    let global_get_decl = DeclId::new(10_618);
    let replace_decl = DeclId::new(10_619);
    let join_decl = DeclId::new(10_620);
    let length_decl = DeclId::new(10_621);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (replace_decl, "str replace".to_string()),
        (join_decl, "str join".to_string()),
        (length_decl, "str length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:2}".into()),
                },
                HirStmt::LoadValue {
                    dst: RegId::new(2),
                    val: Box::new(Value::list(
                        vec![
                            Value::string("aa".to_string(), Span::unknown()),
                            Value::string("aba".to_string(), Span::unknown()),
                        ],
                        Span::unknown(),
                    )),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        pipeline_input: Some(RegId::new(2)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String("a".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::String("z".into()),
                },
                HirStmt::Call {
                    decl_id: replace_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5), RegId::new(6)],
                        flags: vec![b"all".to_vec()],
                        pipeline_input: Some(RegId::new(4)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(8),
                    lit: HirLiteral::String(",".into()),
                },
                HirStmt::Call {
                    decl_id: join_decl,
                    src_dst: RegId::new(9),
                    args: HirCallArgs {
                        positional: vec![RegId::new(8)],
                        pipeline_input: Some(RegId::new(7)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(10),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(9)),
                        ..HirCallArgs::default()
                    },
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
    .expect("typed string array str replace --all should lower as a fixed string array");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StrCmp { len: 1, .. })),
        "expected str replace to compare literal bytes against each fixed string element"
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
                MirInst::StoreSlot {
                    val: MirValue::Const(122),
                    ty: MirType::U8,
                    ..
                }
            )),
        "expected str replace to store replacement byte 'z'"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints)).expect(
        "typed string array str replace result consumed by str join should compile through codegen",
    );
}

#[test]
fn test_lower_global_define_type_string_array_str_replace_rejects_variable_length_output() {
    let define_decl = DeclId::new(10_622);
    let global_get_decl = DeclId::new(10_623);
    let replace_decl = DeclId::new(10_624);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (replace_decl, "str replace".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:1}".into()),
                },
                HirStmt::LoadValue {
                    dst: RegId::new(2),
                    val: Box::new(Value::list(
                        vec![Value::string("aa".to_string(), Span::unknown())],
                        Span::unknown(),
                    )),
                },
                HirStmt::Call {
                    decl_id: define_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![(b"type".to_vec(), RegId::new(1))],
                        pipeline_input: Some(RegId::new(2)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: global_get_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String("a".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::String("zz".into()),
                },
                HirStmt::Call {
                    decl_id: replace_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5), RegId::new(6)],
                        pipeline_input: Some(RegId::new(4)),
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("typed string array str replace should reject variable-length replacement");

    assert!(
        err.to_string()
            .contains("replacement length to equal find length"),
        "expected fixed-length replacement diagnostic, got: {err}"
    );
}

#[test]
fn test_lower_global_define_type_string_array_reverse_preserves_string_semantics() {
    let define_decl = DeclId::new(10_514);
    let global_get_decl = DeclId::new(10_515);
    let reverse_decl = DeclId::new(10_516);
    let first_decl = DeclId::new(10_517);
    let length_decl = DeclId::new(10_518);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (reverse_decl, "reverse".to_string()),
        (first_decl, "first".to_string()),
        (length_decl, "str length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:2}".into()),
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
                    decl_id: reverse_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: first_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
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
    .expect("global-define --type array{string:N:N} reverse should preserve tracked strings");

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
                    slot: _,
                    offset: 0,
                    ..
                }
            )),
        "expected reverse to materialize the fixed array into a stack slot"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed string array reverse consumed by str length should compile through codegen");
}

#[test]
fn test_lower_global_define_type_u32_array_append_materializes_fixed_array() {
    let define_decl = DeclId::new(10_519);
    let global_get_decl = DeclId::new(10_520);
    let append_decl = DeclId::new(10_521);
    let last_decl = DeclId::new(10_522);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (append_decl, "append".to_string()),
        (last_decl, "last".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    lit: HirLiteral::Int(7),
                },
                HirStmt::Call {
                    decl_id: append_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: last_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
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
    .expect("global-define --type array{u32:N} append should materialize a fixed array");

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
                    offset: 8,
                    ty: MirType::U32,
                    ..
                }
            )),
        "expected append to store the inserted u32 at the new fixed-array tail"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed u32 array append consumed by last should compile through codegen");
}

#[test]
fn test_lower_global_define_type_u32_array_prepend_materializes_fixed_array() {
    let define_decl = DeclId::new(10_523);
    let global_get_decl = DeclId::new(10_524);
    let prepend_decl = DeclId::new(10_525);
    let first_decl = DeclId::new(10_526);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (prepend_decl, "prepend".to_string()),
        (first_decl, "first".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    lit: HirLiteral::Int(7),
                },
                HirStmt::Call {
                    decl_id: prepend_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: first_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
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
    .expect("global-define --type array{u32:N} prepend should materialize a fixed array");

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
                    ty: MirType::U32,
                    ..
                }
            )),
        "expected prepend to store the inserted u32 at the new fixed-array head"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed u32 array prepend consumed by first should compile through codegen");
}

#[test]
fn test_lower_global_define_type_string_array_append_preserves_string_semantics() {
    let define_decl = DeclId::new(10_527);
    let global_get_decl = DeclId::new(10_528);
    let append_decl = DeclId::new(10_529);
    let last_decl = DeclId::new(10_530);
    let length_decl = DeclId::new(10_531);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (append_decl, "append".to_string()),
        (last_decl, "last".to_string()),
        (length_decl, "str length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:2}".into()),
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
                    lit: HirLiteral::String("x".into()),
                },
                HirStmt::Call {
                    decl_id: append_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: last_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(6)),
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
    .expect("global-define --type array{string:N:N} append should preserve tracked strings");

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
                    val: MirValue::Const(0),
                    ..
                }
            )),
        "expected append to zero-fill the destination string element before copying the literal"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed string array append consumed by str length should compile through codegen");
}

#[test]
fn test_lower_global_define_type_string_array_prepend_preserves_string_semantics() {
    let define_decl = DeclId::new(10_532);
    let global_get_decl = DeclId::new(10_533);
    let prepend_decl = DeclId::new(10_534);
    let first_decl = DeclId::new(10_535);
    let length_decl = DeclId::new(10_536);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (prepend_decl, "prepend".to_string()),
        (first_decl, "first".to_string()),
        (length_decl, "str length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("names".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{string:8:2}".into()),
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
                    lit: HirLiteral::String("x".into()),
                },
                HirStmt::Call {
                    decl_id: prepend_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: first_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(6)),
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
    .expect("global-define --type array{string:N:N} prepend should preserve tracked strings");

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
                    val: MirValue::Const(0),
                    ..
                }
            )),
        "expected prepend to zero-fill the destination string element before copying the literal"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed string array prepend consumed by str length should compile through codegen");
}

#[test]
fn test_lower_global_define_type_u32_array_sort_materializes_fixed_array() {
    let define_decl = DeclId::new(10_537);
    let global_get_decl = DeclId::new(10_538);
    let sort_decl = DeclId::new(10_539);
    let length_decl = DeclId::new(10_540);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (sort_decl, "sort".to_string()),
        (length_decl, "length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    decl_id: sort_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
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
    .expect("global-define --type array{u32:N} sort should materialize a fixed array");

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
                    ..
                }
            )),
        "expected ascending fixed-array sort to swap when the left value is greater"
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
                MirInst::StoreSlot {
                    ty: MirType::U32,
                    ..
                }
            )),
        "expected fixed-array sort to rewrite u32 stack slots during compare/swap"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed u32 array sort consumed by length should compile through codegen");
}

#[test]
fn test_lower_global_define_type_u32_array_sort_reverse_uses_descending_compare() {
    let define_decl = DeclId::new(10_541);
    let global_get_decl = DeclId::new(10_542);
    let sort_decl = DeclId::new(10_543);
    let first_decl = DeclId::new(10_544);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (sort_decl, "sort".to_string()),
        (first_decl, "first".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    decl_id: sort_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        flags: vec![b"reverse".to_vec()],
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: first_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
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
    .expect("global-define --type array{u32:N} sort --reverse should materialize a fixed array");

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
        "expected reverse fixed-array sort to swap when the left value is smaller"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed u32 array sort --reverse consumed by first should compile through codegen");
}

#[test]
fn test_lower_global_define_type_u32_array_uniq_materializes_numeric_list() {
    let define_decl = DeclId::new(10_545);
    let global_get_decl = DeclId::new(10_546);
    let uniq_decl = DeclId::new(10_547);
    let length_decl = DeclId::new(10_548);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (uniq_decl, "uniq".to_string()),
        (length_decl, "length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    decl_id: uniq_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
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
    .expect("global-define --type array{u32:N} uniq should materialize a numeric list");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "expected typed fixed-array uniq to push unique items into a stack numeric list"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed u32 array uniq consumed by length should compile through codegen");
}

#[test]
fn test_lower_global_define_type_u32_array_find_materializes_numeric_list() {
    let define_decl = DeclId::new(10_573);
    let global_get_decl = DeclId::new(10_574);
    let find_decl = DeclId::new(10_575);
    let length_decl = DeclId::new(10_576);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (find_decl, "find".to_string()),
        (length_decl, "length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: find_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
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
    .expect("global-define --type array{u32:N} find should materialize a numeric list");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "expected typed fixed-array find to push matching items into a stack numeric list"
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
                    op: BinOpKind::Eq,
                    ..
                }
            )),
        "expected typed fixed-array find to compare each item with the needle"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed u32 array find consumed by length should compile through codegen");
}

#[test]
fn test_lower_global_define_type_u32_array_compact_is_passthrough() {
    let define_decl = DeclId::new(10_577);
    let global_get_decl = DeclId::new(10_578);
    let compact_decl = DeclId::new(10_579);
    let length_decl = DeclId::new(10_580);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (compact_decl, "compact".to_string()),
        (length_decl, "length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    decl_id: compact_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
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
    .expect("global-define --type array{u32:N} compact should preserve fixed-array metadata");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::Copy { .. })),
        "expected typed fixed-array compact to pass through the input pointer"
    );
    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "compact on numeric fixed arrays should not rebuild a runtime list"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed u32 array compact consumed by length should compile through codegen");
}

#[test]
fn test_lower_global_define_type_u64_array_compact_is_passthrough() {
    let define_decl = DeclId::new(10_960);
    let global_get_decl = DeclId::new(10_961);
    let compact_decl = DeclId::new(10_962);
    let length_decl = DeclId::new(10_963);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (compact_decl, "compact".to_string()),
        (length_decl, "length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u64:2}".into()),
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
                    decl_id: compact_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
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
    .expect("global-define --type array{u64:N} compact should preserve fixed-array metadata");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::Copy { .. })),
        "expected typed u64 fixed-array compact to pass through the input pointer"
    );
    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "compact on u64 fixed arrays should not rebuild a runtime list"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed u64 array compact consumed by length should compile through codegen");
}

#[test]
fn test_lower_global_define_type_bool_array_compact_is_passthrough() {
    let define_decl = DeclId::new(10_970);
    let global_get_decl = DeclId::new(10_971);
    let compact_decl = DeclId::new(10_972);
    let length_decl = DeclId::new(10_973);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (compact_decl, "compact".to_string()),
        (length_decl, "length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("flags".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{bool:2}".into()),
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
                    decl_id: compact_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
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
    .expect("global-define --type array{bool:N} compact should preserve fixed-array metadata");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::Copy { .. })),
        "expected typed bool fixed-array compact to pass through the input pointer"
    );
    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "compact on bool fixed arrays should not rebuild a runtime list"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed bool array compact consumed by length should compile through codegen");
}

fn make_global_define_type_array_compact_length_program(
    type_spec: &str,
    global_name: &str,
    base_decl: usize,
    compact_flags: Vec<Vec<u8>>,
) -> (HirProgram, HashMap<DeclId, String>) {
    let define_decl = DeclId::new(base_decl);
    let global_get_decl = DeclId::new(base_decl + 1);
    let compact_decl = DeclId::new(base_decl + 2);
    let length_decl = DeclId::new(base_decl + 3);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (compact_decl, "compact".to_string()),
        (length_decl, "length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String(global_name.into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(type_spec.into()),
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
                    decl_id: compact_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        flags: compact_flags,
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
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

    (
        HirProgram::new(func, HashMap::new(), vec![], None),
        decl_names,
    )
}

#[test]
fn test_lower_global_define_type_string_array_compact_is_passthrough() {
    let (hir, decl_names) = make_global_define_type_array_compact_length_program(
        "array{string:8:2}",
        "names",
        10_980,
        Vec::new(),
    );

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("default compact on fixed string arrays should preserve fixed-array metadata");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::Copy { .. })),
        "expected typed string fixed-array compact to pass through the input pointer"
    );
    assert!(
        !result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "default compact on string fixed arrays should not rebuild a runtime list"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed string array compact consumed by length should compile through codegen");
}

#[test]
fn test_lower_global_define_type_string_array_compact_empty_rejects() {
    let (hir, decl_names) = make_global_define_type_array_compact_length_program(
        "array{string:8:2}",
        "names",
        10_990,
        vec![b"empty".to_vec()],
    );

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("compact --empty on fixed string arrays should remain unsupported");

    assert!(
        err.to_string().contains(
            "compact --empty on typed fixed arrays currently supports only numeric or bool elements"
        ),
        "expected targeted compact --empty fixed-array diagnostic, got: {err}"
    );
}

#[test]
fn test_lower_global_define_type_u32_array_where_materializes_numeric_list() {
    let define_decl = DeclId::new(10_581);
    let global_get_decl = DeclId::new(10_582);
    let where_decl = DeclId::new(10_583);
    let length_decl = DeclId::new(10_584);
    let closure_block_id = nu_protocol::BlockId::new(1);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (where_decl, "where".to_string()),
        (length_decl, "length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    lit: HirLiteral::Closure(closure_block_id),
                },
                HirStmt::Call {
                    decl_id: where_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
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
                    lit: HirLiteral::Int(0),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: nu_protocol::ast::Operator::Comparison(nu_protocol::ast::Comparison::Equal),
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
    let hir = HirProgram::new(
        func,
        HashMap::from([(closure_block_id, closure)]),
        vec![],
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
    .expect("global-define --type array{u32:N} where should materialize a numeric list");
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
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "expected typed fixed-array where to push matching items into a stack numeric list"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::Load {
                offset: 0,
                ty: MirType::U32,
                ..
            }
        )),
        "expected typed fixed-array where to load the first u32 item"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Eq,
                ..
            }
        )),
        "expected typed fixed-array where to run the predicate per item"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed u32 array where consumed by length should compile through codegen");
}

#[test]
fn test_lower_global_define_type_u32_array_each_materializes_numeric_list() {
    let define_decl = DeclId::new(10_585);
    let global_get_decl = DeclId::new(10_586);
    let each_decl = DeclId::new(10_587);
    let first_decl = DeclId::new(10_588);
    let closure_block_id = nu_protocol::BlockId::new(1);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (each_decl, "each".to_string()),
        (first_decl, "first".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    lit: HirLiteral::Closure(closure_block_id),
                },
                HirStmt::Call {
                    decl_id: each_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: first_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
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
                    lit: HirLiteral::Int(1),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: nu_protocol::ast::Operator::Math(nu_protocol::ast::Math::Add),
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
    let hir = HirProgram::new(
        func,
        HashMap::from([(closure_block_id, closure)]),
        vec![],
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
    .expect("global-define --type array{u32:N} each should materialize a numeric list");
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
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "expected typed fixed-array each to push transformed items into a stack numeric list"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::Load {
                offset: 0,
                ty: MirType::U32,
                ..
            }
        )),
        "expected typed fixed-array each to load the first u32 item"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Add,
                ..
            }
        )),
        "expected typed fixed-array each to transform each item"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed u32 array each consumed by first should compile through codegen");
}

#[test]
fn test_lower_global_define_type_u32_array_uniq_first_uses_non_empty_min_len() {
    let define_decl = DeclId::new(10_549);
    let global_get_decl = DeclId::new(10_550);
    let uniq_decl = DeclId::new(10_551);
    let first_decl = DeclId::new(10_552);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (uniq_decl, "uniq".to_string()),
        (first_decl, "first".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    decl_id: uniq_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: first_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
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
    .expect("global-define --type array{u32:N} uniq | first should lower");

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
        "expected first to read index 0 from the non-empty uniq result"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed u32 array uniq consumed by first should compile through codegen");
}

#[test]
fn test_lower_global_define_type_u32_array_uniq_last_uses_non_empty_min_len() {
    let define_decl = DeclId::new(10_553);
    let global_get_decl = DeclId::new(10_554);
    let uniq_decl = DeclId::new(10_555);
    let last_decl = DeclId::new(10_556);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (uniq_decl, "uniq".to_string()),
        (last_decl, "last".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    decl_id: uniq_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: last_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
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
    .expect("global-define --type array{u32:N} uniq | last should lower");

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
                    idx: MirValue::VReg(_),
                    ..
                }
            )),
        "expected last to read the runtime final index from the non-empty uniq result"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed u32 array uniq consumed by last should compile through codegen");
}

#[test]
fn test_lower_global_define_type_u32_array_uniq_math_reducers_use_non_empty_min_len() {
    for (define_decl, global_get_decl, uniq_decl, reducer_decl, reducer_name, expected_op) in [
        (
            DeclId::new(10_557),
            DeclId::new(10_558),
            DeclId::new(10_559),
            DeclId::new(10_560),
            "math min",
            BinOpKind::Lt,
        ),
        (
            DeclId::new(10_561),
            DeclId::new(10_562),
            DeclId::new(10_563),
            DeclId::new(10_564),
            "math max",
            BinOpKind::Gt,
        ),
        (
            DeclId::new(10_565),
            DeclId::new(10_566),
            DeclId::new(10_567),
            DeclId::new(10_568),
            "math sum",
            BinOpKind::Add,
        ),
        (
            DeclId::new(10_569),
            DeclId::new(10_570),
            DeclId::new(10_571),
            DeclId::new(10_572),
            "math product",
            BinOpKind::Mul,
        ),
    ] {
        let decl_names = HashMap::from([
            (define_decl, "global-define".to_string()),
            (global_get_decl, "global-get".to_string()),
            (uniq_decl, "uniq".to_string()),
            (reducer_decl, reducer_name.to_string()),
        ]);

        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::String("ports".into()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::String("array{u32:2}".into()),
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
                        decl_id: uniq_decl,
                        src_dst: RegId::new(4),
                        args: HirCallArgs {
                            pipeline_input: Some(RegId::new(3)),
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::Call {
                        decl_id: reducer_decl,
                        src_dst: RegId::new(5),
                        args: HirCallArgs {
                            pipeline_input: Some(RegId::new(4)),
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
        .unwrap_or_else(|err| {
            panic!("global-define --type array{{u32:N}} uniq | {reducer_name} should lower: {err}")
        });
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
                    idx: MirValue::Const(0),
                    ..
                }
            )),
            "expected {reducer_name} to initialize from the first uniq item"
        );
        assert!(
            instructions.iter().any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op,
                    ..
                } if *op == expected_op
            )),
            "expected {reducer_name} to lower with {expected_op:?}"
        );
        compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
            .unwrap_or_else(|err| {
                panic!("typed u32 array uniq consumed by {reducer_name} should compile: {err}")
            });
    }
}

#[test]
fn test_lower_global_define_type_u32_array_math_reducers() {
    for (define_decl, global_get_decl, reducer_decl, reducer_name, expected_op) in [
        (
            DeclId::new(10_900),
            DeclId::new(10_901),
            DeclId::new(10_902),
            "math min",
            BinOpKind::Lt,
        ),
        (
            DeclId::new(10_903),
            DeclId::new(10_904),
            DeclId::new(10_905),
            "math max",
            BinOpKind::Gt,
        ),
        (
            DeclId::new(10_906),
            DeclId::new(10_907),
            DeclId::new(10_908),
            "math sum",
            BinOpKind::Add,
        ),
        (
            DeclId::new(10_909),
            DeclId::new(10_910),
            DeclId::new(10_911),
            "math product",
            BinOpKind::Mul,
        ),
    ] {
        let decl_names = HashMap::from([
            (define_decl, "global-define".to_string()),
            (global_get_decl, "global-get".to_string()),
            (reducer_decl, reducer_name.to_string()),
        ]);

        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::String("ports".into()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::String("array{u32:2}".into()),
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
                        decl_id: reducer_decl,
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
        .unwrap_or_else(|err| {
            panic!("global-define --type array{{u32:N}} | {reducer_name} should lower: {err}")
        });
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
                MirInst::Load {
                    offset: 0,
                    ty: MirType::U32,
                    ..
                }
            )),
            "expected {reducer_name} to read typed fixed-array u32 elements"
        );
        assert!(
            instructions.iter().any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op,
                    ..
                } if *op == expected_op
            )),
            "expected {reducer_name} to lower with {expected_op:?}"
        );
        compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
            .unwrap_or_else(|err| {
                panic!("typed u32 array consumed by {reducer_name} should compile: {err}")
            });
    }
}

#[test]
fn test_lower_global_define_type_i32_array_math_abs_materializes_numeric_list() {
    let define_decl = DeclId::new(10_912);
    let global_get_decl = DeclId::new(10_913);
    let abs_decl = DeclId::new(10_914);
    let sum_decl = DeclId::new(10_915);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (abs_decl, "math abs".to_string()),
        (sum_decl, "math sum".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{i32:2}".into()),
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
                    decl_id: abs_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: sum_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
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
    .expect("global-define --type array{i32:N} | math abs should materialize a numeric list");
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
            MirInst::Load {
                offset: 0,
                ty: MirType::I32,
                ..
            }
        )),
        "expected math abs to read typed fixed-array i32 elements"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::UnaryOp {
                op: UnaryOpKind::Neg,
                ..
            }
        )),
        "expected math abs on signed fixed arrays to emit a negation path"
    );
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "expected math abs to materialize a stack numeric list"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed i32 array math abs consumed by math sum should compile");
}

#[test]
fn test_lower_global_define_type_i32_array_math_median_materializes_sorted_numeric_list() {
    let define_decl = DeclId::new(10_916);
    let global_get_decl = DeclId::new(10_917);
    let median_decl = DeclId::new(10_918);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (median_decl, "math median".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{i32:3}".into()),
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
                    decl_id: median_decl,
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
    .expect("global-define --type array{i32:N} | math median should lower");
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
            MirInst::Load {
                offset: 0,
                ty: MirType::I32,
                ..
            }
        )),
        "expected math median to read typed fixed-array i32 elements"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Gt,
                ..
            }
        )),
        "expected math median to sort the fixed-array values"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::ListGet {
                idx: MirValue::Const(1),
                ..
            }
        )),
        "expected math median to read the sorted middle item"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed i32 array math median should compile");
}

#[test]
fn test_lower_global_define_type_i32_array_math_mode_materializes_numeric_list() {
    let define_decl = DeclId::new(10_919);
    let global_get_decl = DeclId::new(10_920);
    let mode_decl = DeclId::new(10_921);
    let length_decl = DeclId::new(10_922);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (mode_decl, "math mode".to_string()),
        (length_decl, "length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{i32:3}".into()),
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
                    decl_id: mode_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
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
    .expect("global-define --type array{i32:N} | math mode should lower");
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
            MirInst::Load {
                offset: 0,
                ty: MirType::I32,
                ..
            }
        )),
        "expected math mode to read typed fixed-array i32 elements"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Gt,
                ..
            }
        )),
        "expected math mode to sort fixed-array values and track max counts"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::Eq,
                ..
            }
        )),
        "expected math mode to count values and select modes"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed i32 array math mode consumed by length should compile");
}

#[test]
fn test_lower_global_define_type_u32_array_math_integer_identity_materializes_numeric_list() {
    for (offset, command_name) in [(0, "math ceil"), (1, "math floor"), (2, "math round")] {
        let define_decl = DeclId::new(10_947 + offset);
        let global_get_decl = DeclId::new(10_950 + offset);
        let math_decl = DeclId::new(10_953 + offset);
        let length_decl = DeclId::new(10_956 + offset);
        let decl_names = HashMap::from([
            (define_decl, "global-define".to_string()),
            (global_get_decl, "global-get".to_string()),
            (math_decl, command_name.to_string()),
            (length_decl, "length".to_string()),
        ]);

        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::String("ports".into()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::String("array{u32:2}".into()),
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
                        decl_id: math_decl,
                        src_dst: RegId::new(4),
                        args: HirCallArgs {
                            pipeline_input: Some(RegId::new(3)),
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::Call {
                        decl_id: length_decl,
                        src_dst: RegId::new(5),
                        args: HirCallArgs {
                            pipeline_input: Some(RegId::new(4)),
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
        .unwrap_or_else(|err| {
            panic!("global-define --type array{{u32:N}} | {command_name} should lower: {err}")
        });
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
                MirInst::Load {
                    offset: 0,
                    ty: MirType::U32,
                    ..
                }
            )),
            "expected {command_name} to read typed fixed-array u32 elements"
        );
        assert!(
            instructions
                .iter()
                .any(|inst| matches!(inst, MirInst::ListPush { .. })),
            "expected {command_name} to materialize a stack numeric list"
        );
        compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
            .unwrap_or_else(|err| {
                panic!("typed u32 array {command_name} consumed by length should compile: {err}")
            });
    }
}

#[test]
fn test_lower_global_define_type_u32_array_bits_and_materializes_numeric_list() {
    let define_decl = DeclId::new(10_923);
    let global_get_decl = DeclId::new(10_924);
    let bits_decl = DeclId::new(10_925);
    let length_decl = DeclId::new(10_926);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (bits_decl, "bits and".to_string()),
        (length_decl, "length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: bits_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
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
    .expect("global-define --type array{u32:N} | bits and should lower");
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
            MirInst::Load {
                offset: 0,
                ty: MirType::U32,
                ..
            }
        )),
        "expected bits and to read typed fixed-array u32 elements"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::And,
                ..
            }
        )),
        "expected bits and to transform fixed-array values"
    );
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "expected bits and to materialize a stack numeric list"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed u32 array bits and consumed by length should compile");
}

#[test]
fn test_lower_global_define_type_u32_array_bits_not_materializes_numeric_list() {
    let define_decl = DeclId::new(10_927);
    let global_get_decl = DeclId::new(10_928);
    let bits_decl = DeclId::new(10_929);
    let length_decl = DeclId::new(10_930);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (bits_decl, "bits not".to_string()),
        (length_decl, "length".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("ports".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("array{u32:2}".into()),
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
                    lit: HirLiteral::Int(4),
                },
                HirStmt::Call {
                    decl_id: bits_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        named: vec![(b"number-bytes".to_vec(), RegId::new(4))],
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
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
    .expect("global-define --type array{u32:N} | bits not should lower");
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
            MirInst::Load {
                offset: 0,
                ty: MirType::U32,
                ..
            }
        )),
        "expected bits not to read typed fixed-array u32 elements"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::UnaryOp {
                op: UnaryOpKind::BitNot,
                ..
            }
        )),
        "expected bits not to transform fixed-array values"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::BinOp {
                op: BinOpKind::And,
                ..
            }
        )),
        "expected bits not --number-bytes to apply the byte-width mask"
    );
    assert!(
        instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "expected bits not to materialize a stack numeric list"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed u32 array bits not consumed by length should compile");
}

#[test]
fn test_lower_global_define_type_u32_array_bits_shift_materializes_numeric_list() {
    for (offset, command_name, expected_op) in [
        (0, "bits shl", BinOpKind::Shl),
        (1, "bits shr", BinOpKind::Shr),
    ] {
        let define_decl = DeclId::new(10_931 + offset);
        let global_get_decl = DeclId::new(10_933 + offset);
        let bits_decl = DeclId::new(10_935 + offset);
        let length_decl = DeclId::new(10_937 + offset);
        let decl_names = HashMap::from([
            (define_decl, "global-define".to_string()),
            (global_get_decl, "global-get".to_string()),
            (bits_decl, command_name.to_string()),
            (length_decl, "length".to_string()),
        ]);

        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::String("ports".into()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::String("array{u32:2}".into()),
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
                        lit: HirLiteral::Int(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(5),
                        lit: HirLiteral::Int(4),
                    },
                    HirStmt::Call {
                        decl_id: bits_decl,
                        src_dst: RegId::new(6),
                        args: HirCallArgs {
                            positional: vec![RegId::new(4)],
                            named: vec![(b"number-bytes".to_vec(), RegId::new(5))],
                            pipeline_input: Some(RegId::new(3)),
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::Call {
                        decl_id: length_decl,
                        src_dst: RegId::new(7),
                        args: HirCallArgs {
                            pipeline_input: Some(RegId::new(6)),
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
        .unwrap_or_else(|err| {
            panic!("global-define --type array{{u32:N}} | {command_name} should lower: {err}")
        });
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
                MirInst::Load {
                    offset: 0,
                    ty: MirType::U32,
                    ..
                }
            )),
            "expected {command_name} to read typed fixed-array u32 elements"
        );
        assert!(
            instructions.iter().any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op,
                    ..
                } if *op == expected_op
            )),
            "expected {command_name} to transform fixed-array values"
        );
        assert!(
            instructions.iter().any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::And,
                    ..
                }
            )),
            "expected {command_name} --number-bytes to apply the byte-width mask"
        );
        assert!(
            instructions
                .iter()
                .any(|inst| matches!(inst, MirInst::ListPush { .. })),
            "expected {command_name} to materialize a stack numeric list"
        );
        compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
            .unwrap_or_else(|err| {
                panic!("typed u32 array {command_name} consumed by length should compile: {err}")
            });
    }
}

#[test]
fn test_lower_global_define_type_u32_array_bits_rotate_materializes_numeric_list() {
    for (offset, command_name) in [(0, "bits rol"), (1, "bits ror")] {
        let define_decl = DeclId::new(10_939 + offset);
        let global_get_decl = DeclId::new(10_941 + offset);
        let bits_decl = DeclId::new(10_943 + offset);
        let length_decl = DeclId::new(10_945 + offset);
        let decl_names = HashMap::from([
            (define_decl, "global-define".to_string()),
            (global_get_decl, "global-get".to_string()),
            (bits_decl, command_name.to_string()),
            (length_decl, "length".to_string()),
        ]);

        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::String("ports".into()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::String("array{u32:2}".into()),
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
                        lit: HirLiteral::Int(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(5),
                        lit: HirLiteral::Int(4),
                    },
                    HirStmt::Call {
                        decl_id: bits_decl,
                        src_dst: RegId::new(6),
                        args: HirCallArgs {
                            positional: vec![RegId::new(4)],
                            named: vec![(b"number-bytes".to_vec(), RegId::new(5))],
                            pipeline_input: Some(RegId::new(3)),
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::Call {
                        decl_id: length_decl,
                        src_dst: RegId::new(7),
                        args: HirCallArgs {
                            pipeline_input: Some(RegId::new(6)),
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
        .unwrap_or_else(|err| {
            panic!("global-define --type array{{u32:N}} | {command_name} should lower: {err}")
        });
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
                MirInst::Load {
                    offset: 0,
                    ty: MirType::U32,
                    ..
                }
            )),
            "expected {command_name} to read typed fixed-array u32 elements"
        );
        for expected_op in [BinOpKind::Shl, BinOpKind::Shr, BinOpKind::Or] {
            assert!(
                instructions.iter().any(|inst| matches!(
                    inst,
                    MirInst::BinOp {
                        op,
                        ..
                    } if *op == expected_op
                )),
                "expected {command_name} to emit {expected_op:?}"
            );
        }
        assert!(
            instructions.iter().any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::And,
                    ..
                }
            )),
            "expected {command_name} --number-bytes to apply the byte-width mask"
        );
        assert!(
            instructions
                .iter()
                .any(|inst| matches!(inst, MirInst::ListPush { .. })),
            "expected {command_name} to materialize a stack numeric list"
        );
        compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
            .unwrap_or_else(|err| {
                panic!("typed u32 array {command_name} consumed by length should compile: {err}")
            });
    }
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
fn test_lower_global_define_type_record_supports_command_get_field() {
    let define_decl = DeclId::new(10_290);
    let global_get_decl = DeclId::new(10_291);
    let get_decl = DeclId::new(10_292);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (get_decl, "get".to_string()),
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
                    decl_id: global_get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::String("pid".into()),
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("global-define --type record{...} command get field should lower");

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
        "expected command get to load the pid field at offset 0"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed record command get should compile through codegen");
}

#[test]
fn test_lower_global_define_type_record_select_reject_supports_scalar_fields() {
    for (case_idx, (cmd_name, field_names)) in
        [("select", vec!["pid", "uid"]), ("reject", vec!["comm"])]
            .into_iter()
            .enumerate()
    {
        let base_decl = 10_350 + case_idx * 10;
        let define_decl = DeclId::new(base_decl);
        let global_get_decl = DeclId::new(base_decl + 1);
        let transform_decl = DeclId::new(base_decl + 2);
        let get_decl = DeclId::new(base_decl + 3);
        let decl_names = HashMap::from([
            (define_decl, "global-define".to_string()),
            (global_get_decl, "global-get".to_string()),
            (transform_decl, cmd_name.to_string()),
            (get_decl, "get".to_string()),
        ]);

        let mut stmts = vec![
            HirStmt::LoadLiteral {
                dst: RegId::new(0),
                lit: HirLiteral::String("seen_state".into()),
            },
            HirStmt::LoadLiteral {
                dst: RegId::new(1),
                lit: HirLiteral::String("record{pid:i64,uid:u32,comm:string:8}".into()),
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
        ];

        let mut next_reg = 4;
        let mut transform_args = Vec::new();
        for field_name in field_names {
            let reg = RegId::new(next_reg);
            next_reg += 1;
            stmts.push(HirStmt::LoadLiteral {
                dst: reg,
                lit: HirLiteral::String(field_name.into()),
            });
            transform_args.push(reg);
        }

        let transform_reg = RegId::new(next_reg);
        next_reg += 1;
        stmts.push(HirStmt::Call {
            decl_id: transform_decl,
            src_dst: transform_reg,
            args: HirCallArgs {
                positional: transform_args,
                pipeline_input: Some(RegId::new(3)),
                ..HirCallArgs::default()
            },
        });

        let uid_field_reg = RegId::new(next_reg);
        next_reg += 1;
        stmts.push(HirStmt::LoadLiteral {
            dst: uid_field_reg,
            lit: HirLiteral::String("uid".into()),
        });

        let uid_result_reg = RegId::new(next_reg);
        next_reg += 1;
        stmts.push(HirStmt::Call {
            decl_id: get_decl,
            src_dst: uid_result_reg,
            args: HirCallArgs {
                positional: vec![uid_field_reg],
                pipeline_input: Some(transform_reg),
                ..HirCallArgs::default()
            },
        });

        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts,
                terminator: HirTerminator::Return {
                    src: uid_result_reg,
                },
            }],
            entry: HirBlockId(0),
            spans: Vec::new(),
            ast: Vec::new(),
            comments: Vec::new(),
            register_count: next_reg,
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
        .unwrap_or_else(|err| {
            panic!("global-define --type record{{...}} | {cmd_name} should lower: {err:?}")
        });

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
                        ty: MirType::U32,
                        ..
                    }
                )),
            "expected typed record {cmd_name} output to preserve uid scalar projection"
        );
        compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
            .unwrap_or_else(|err| {
                panic!("typed record {cmd_name} output should compile through codegen: {err:?}")
            });
    }
}

#[test]
fn test_lower_global_define_type_record_reject_all_fields_marks_empty_record() {
    let define_decl = DeclId::new(10_365);
    let global_get_decl = DeclId::new(10_366);
    let reject_decl = DeclId::new(10_367);
    let is_empty_decl = DeclId::new(10_368);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (reject_decl, "reject".to_string()),
        (is_empty_decl, "is-empty".to_string()),
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
                    decl_id: global_get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String("uid".into()),
                },
                HirStmt::Call {
                    decl_id: reject_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4), RegId::new(5)],
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: is_empty_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(6)),
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
    .expect("typed record reject all fields should produce an empty metadata record");
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
        "expected is-empty after rejecting all typed record fields to fold to true"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed record reject-all is-empty result should compile through codegen");
}

#[test]
fn test_lower_global_define_type_record_metadata_reject_all_fields_marks_empty_record() {
    let define_decl = DeclId::new(10_360);
    let global_get_decl = DeclId::new(10_361);
    let select_decl = DeclId::new(10_362);
    let reject_decl = DeclId::new(10_363);
    let is_empty_decl = DeclId::new(10_364);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (select_decl, "select".to_string()),
        (reject_decl, "reject".to_string()),
        (is_empty_decl, "is-empty".to_string()),
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
                    decl_id: global_get_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::Call {
                    decl_id: select_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4)],
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::Call {
                    decl_id: reject_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        positional: vec![RegId::new(6)],
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: is_empty_decl,
                    src_dst: RegId::new(8),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(7)),
                        ..HirCallArgs::default()
                    },
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("metadata-backed record reject all fields should preserve empty record shape");
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
        "expected is-empty after metadata-backed reject-all to fold to true"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("metadata-backed reject-all is-empty result should compile through codegen");
}

#[test]
fn test_lower_global_define_type_record_rename_supports_scalar_fields() {
    for (case_idx, use_column_mapping) in [false, true].into_iter().enumerate() {
        let base_decl = 10_370 + case_idx * 10;
        let define_decl = DeclId::new(base_decl);
        let global_get_decl = DeclId::new(base_decl + 1);
        let rename_decl = DeclId::new(base_decl + 2);
        let get_decl = DeclId::new(base_decl + 3);
        let decl_names = HashMap::from([
            (define_decl, "global-define".to_string()),
            (global_get_decl, "global-get".to_string()),
            (rename_decl, "rename".to_string()),
            (get_decl, "get".to_string()),
        ]);

        let mut stmts = vec![
            HirStmt::LoadLiteral {
                dst: RegId::new(0),
                lit: HirLiteral::String("seen_state".into()),
            },
            HirStmt::LoadLiteral {
                dst: RegId::new(1),
                lit: HirLiteral::String("record{pid:i64,uid:u32,cpu:u32}".into()),
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
        ];

        let rename_reg = if use_column_mapping {
            let mut mapping = Record::new();
            mapping.push("uid", Value::string("user", Span::test_data()));
            stmts.push(HirStmt::LoadValue {
                dst: RegId::new(4),
                val: Box::new(Value::record(mapping, Span::test_data())),
            });
            stmts.push(HirStmt::Call {
                decl_id: rename_decl,
                src_dst: RegId::new(5),
                args: HirCallArgs {
                    named: vec![(b"column".to_vec(), RegId::new(4))],
                    pipeline_input: Some(RegId::new(3)),
                    ..HirCallArgs::default()
                },
            });
            RegId::new(5)
        } else {
            for (idx, name) in ["tid", "user", "core"].into_iter().enumerate() {
                stmts.push(HirStmt::LoadLiteral {
                    dst: RegId::new(4 + idx as u32),
                    lit: HirLiteral::String(name.into()),
                });
            }
            stmts.push(HirStmt::Call {
                decl_id: rename_decl,
                src_dst: RegId::new(7),
                args: HirCallArgs {
                    positional: vec![RegId::new(4), RegId::new(5), RegId::new(6)],
                    pipeline_input: Some(RegId::new(3)),
                    ..HirCallArgs::default()
                },
            });
            RegId::new(7)
        };

        let user_field_reg = RegId::new(8);
        let user_result_reg = RegId::new(9);
        stmts.push(HirStmt::LoadLiteral {
            dst: user_field_reg,
            lit: HirLiteral::String("user".into()),
        });
        stmts.push(HirStmt::Call {
            decl_id: get_decl,
            src_dst: user_result_reg,
            args: HirCallArgs {
                positional: vec![user_field_reg],
                pipeline_input: Some(rename_reg),
                ..HirCallArgs::default()
            },
        });

        let func = HirFunction {
            blocks: vec![HirBlock {
                id: HirBlockId(0),
                stmts,
                terminator: HirTerminator::Return {
                    src: user_result_reg,
                },
            }],
            entry: HirBlockId(0),
            spans: Vec::new(),
            ast: Vec::new(),
            comments: Vec::new(),
            register_count: 10,
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
        .unwrap_or_else(|err| {
            panic!("global-define --type record{{...}} | rename should lower: {err:?}")
        });

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
                        ty: MirType::U32,
                        ..
                    }
                )),
            "expected typed record rename output to preserve uid scalar projection"
        );
        compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
            .unwrap_or_else(|err| {
                panic!("typed record rename output should compile through codegen: {err:?}")
            });
    }
}

#[test]
fn test_lower_global_define_type_record_values_supports_scalar_fields() {
    let define_decl = DeclId::new(10_390);
    let global_get_decl = DeclId::new(10_391);
    let values_decl = DeclId::new(10_392);
    let get_decl = DeclId::new(10_393);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (values_decl, "values".to_string()),
        (get_decl, "get".to_string()),
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
                    lit: HirLiteral::String("record{pid:i64,uid:u32,cpu:u32}".into()),
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
                    decl_id: values_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::Call {
                    decl_id: get_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5)],
                        pipeline_input: Some(RegId::new(4)),
                        ..HirCallArgs::default()
                    },
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
    .unwrap_or_else(|err| {
        panic!("global-define --type record{{...}} | values should lower: {err:?}")
    });
    let instructions = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .collect::<Vec<_>>();

    assert_eq!(
        instructions
            .iter()
            .filter(|inst| matches!(inst, MirInst::ListPush { .. }))
            .count(),
        3,
        "expected values to materialize each scalar typed record field"
    );
    assert!(
        instructions.iter().any(|inst| matches!(
            inst,
            MirInst::Load {
                offset: 8,
                ty: MirType::U32,
                ..
            }
        )),
        "expected values output to preserve uid scalar projection"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints)).unwrap_or_else(
        |err| panic!("typed record values output should compile through codegen: {err:?}"),
    );
}

#[test]
fn test_lower_global_define_type_record_insert_update_upsert_supports_scalar_fields() {
    for (case_idx, (cmd_name, replacement_field, get_field, expected_offset)) in [
        ("insert", "tid", "uid", 8),
        ("update", "uid", "cpu", 12),
        ("upsert", "uid", "cpu", 12),
    ]
    .into_iter()
    .enumerate()
    {
        let base_decl = 10_400 + case_idx * 10;
        let define_decl = DeclId::new(base_decl);
        let global_get_decl = DeclId::new(base_decl + 1);
        let record_cmd_decl = DeclId::new(base_decl + 2);
        let get_decl = DeclId::new(base_decl + 3);
        let decl_names = HashMap::from([
            (define_decl, "global-define".to_string()),
            (global_get_decl, "global-get".to_string()),
            (record_cmd_decl, cmd_name.to_string()),
            (get_decl, "get".to_string()),
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
                        lit: HirLiteral::String("record{pid:i64,uid:u32,cpu:u32}".into()),
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
                        lit: HirLiteral::String(replacement_field.into()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(5),
                        lit: HirLiteral::Int(7),
                    },
                    HirStmt::Call {
                        decl_id: record_cmd_decl,
                        src_dst: RegId::new(6),
                        args: HirCallArgs {
                            positional: vec![RegId::new(4), RegId::new(5)],
                            pipeline_input: Some(RegId::new(3)),
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(7),
                        lit: HirLiteral::String(get_field.into()),
                    },
                    HirStmt::Call {
                        decl_id: get_decl,
                        src_dst: RegId::new(8),
                        args: HirCallArgs {
                            positional: vec![RegId::new(7)],
                            pipeline_input: Some(RegId::new(6)),
                            ..HirCallArgs::default()
                        },
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
        let hir = HirProgram::new(func, HashMap::new(), vec![], None);

        let result = lower_hir_to_mir_with_hints(
            &hir,
            None,
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|err| {
            panic!("global-define --type record{{...}} | {cmd_name} should lower: {err:?}")
        });

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
                        offset,
                        ty: MirType::U32,
                        ..
                    } if *offset == expected_offset
                )),
            "expected {cmd_name} output to preserve typed field '{get_field}'"
        );
        compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
            .unwrap_or_else(|err| {
                panic!("typed record {cmd_name} output should compile through codegen: {err:?}")
            });
    }
}

#[test]
fn test_lower_global_define_type_record_default_supports_scalar_fields() {
    for (case_idx, (default_field, get_field, expected_offset)) in
        [("tid", "tid", None), ("uid", "uid", Some(8))]
            .into_iter()
            .enumerate()
    {
        let base_decl = 10_430 + case_idx * 10;
        let define_decl = DeclId::new(base_decl);
        let global_get_decl = DeclId::new(base_decl + 1);
        let default_decl = DeclId::new(base_decl + 2);
        let get_decl = DeclId::new(base_decl + 3);
        let decl_names = HashMap::from([
            (define_decl, "global-define".to_string()),
            (global_get_decl, "global-get".to_string()),
            (default_decl, "default".to_string()),
            (get_decl, "get".to_string()),
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
                        lit: HirLiteral::String("record{pid:i64,uid:u32,cpu:u32}".into()),
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
                        lit: HirLiteral::Int(7),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(5),
                        lit: HirLiteral::String(default_field.into()),
                    },
                    HirStmt::Call {
                        decl_id: default_decl,
                        src_dst: RegId::new(6),
                        args: HirCallArgs {
                            positional: vec![RegId::new(4), RegId::new(5)],
                            pipeline_input: Some(RegId::new(3)),
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(7),
                        lit: HirLiteral::String(get_field.into()),
                    },
                    HirStmt::Call {
                        decl_id: get_decl,
                        src_dst: RegId::new(8),
                        args: HirCallArgs {
                            positional: vec![RegId::new(7)],
                            pipeline_input: Some(RegId::new(6)),
                            ..HirCallArgs::default()
                        },
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
        let hir = HirProgram::new(func, HashMap::new(), vec![], None);

        let result = lower_hir_to_mir_with_hints(
            &hir,
            None,
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_or_else(|err| {
            panic!("global-define --type record{{...}} | default should lower: {err:?}")
        });

        if let Some(expected_offset) = expected_offset {
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
                            offset,
                            ty: MirType::U32,
                            ..
                        } if *offset == expected_offset
                    )),
                "expected default on existing typed field '{get_field}' to preserve the typed projection"
            );
        }
        compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
            .unwrap_or_else(|err| {
                panic!("typed record default output should compile through codegen: {err:?}")
            });
    }
}

#[test]
fn test_lower_global_define_type_record_merge_supports_scalar_fields() {
    for (case_idx, (merge_field, get_field, expected_offset)) in
        [("tid", "uid", 8), ("uid", "cpu", 12)]
            .into_iter()
            .enumerate()
    {
        let base_decl = 10_450 + case_idx * 10;
        let define_decl = DeclId::new(base_decl);
        let global_get_decl = DeclId::new(base_decl + 1);
        let merge_decl = DeclId::new(base_decl + 2);
        let get_decl = DeclId::new(base_decl + 3);
        let decl_names = HashMap::from([
            (define_decl, "global-define".to_string()),
            (global_get_decl, "global-get".to_string()),
            (merge_decl, "merge".to_string()),
            (get_decl, "get".to_string()),
        ]);

        let mut merge_record = Record::new();
        merge_record.push(merge_field, Value::int(7, Span::test_data()));

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
                        lit: HirLiteral::String("record{pid:i64,uid:u32,cpu:u32}".into()),
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
                    HirStmt::LoadValue {
                        dst: RegId::new(4),
                        val: Box::new(Value::record(merge_record, Span::test_data())),
                    },
                    HirStmt::Call {
                        decl_id: merge_decl,
                        src_dst: RegId::new(5),
                        args: HirCallArgs {
                            positional: vec![RegId::new(4)],
                            pipeline_input: Some(RegId::new(3)),
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(6),
                        lit: HirLiteral::String(get_field.into()),
                    },
                    HirStmt::Call {
                        decl_id: get_decl,
                        src_dst: RegId::new(7),
                        args: HirCallArgs {
                            positional: vec![RegId::new(6)],
                            pipeline_input: Some(RegId::new(5)),
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
        .unwrap_or_else(|err| {
            panic!("global-define --type record{{...}} | merge should lower: {err:?}")
        });

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
                        offset,
                        ty: MirType::U32,
                        ..
                    } if *offset == expected_offset
                )),
            "expected merge output to preserve typed field '{get_field}'"
        );
        compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
            .unwrap_or_else(|err| {
                panic!("typed record merge output should compile through codegen: {err:?}")
            });
    }
}

#[test]
fn test_lower_global_define_type_record_values_shape_consumers_use_field_count() {
    for (case_idx, (consumer_name, expected_const)) in
        [("length", 2), ("is-empty", 0), ("is-not-empty", 1)]
            .into_iter()
            .enumerate()
    {
        let base_decl = 10_300 + case_idx * 10;
        let define_decl = DeclId::new(base_decl);
        let global_get_decl = DeclId::new(base_decl + 1);
        let values_decl = DeclId::new(base_decl + 2);
        let consumer_decl = DeclId::new(base_decl + 3);
        let decl_names = HashMap::from([
            (define_decl, "global-define".to_string()),
            (global_get_decl, "global-get".to_string()),
            (values_decl, "values".to_string()),
            (consumer_decl, consumer_name.to_string()),
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
                        lit: HirLiteral::String("record{pid:i64,comm:string:8}".into()),
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
                        decl_id: values_decl,
                        src_dst: RegId::new(4),
                        args: HirCallArgs {
                            pipeline_input: Some(RegId::new(3)),
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::Call {
                        decl_id: consumer_decl,
                        src_dst: RegId::new(5),
                        args: HirCallArgs {
                            pipeline_input: Some(RegId::new(4)),
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
        .unwrap_or_else(|err| {
            panic!("values | {consumer_name} should lower from typed record field count: {err:?}")
        });
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
                    src: MirValue::Const(value),
                    ..
                } if *value == expected_const
            )),
            "expected values | {consumer_name} to fold to {expected_const}"
        );
        assert!(
            !instructions.iter().any(|inst| matches!(
                inst,
                MirInst::ListNew { .. } | MirInst::ListPush { .. } | MirInst::ListGet { .. }
            )),
            "shape-only values | {consumer_name} should not materialize runtime list operations"
        );

        compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
            .unwrap_or_else(|err| {
                panic!("values | {consumer_name} should compile through codegen: {err:?}")
            });
    }
}

#[test]
fn test_lower_global_define_type_record_shape_consumers_use_field_count() {
    for (case_idx, (consumer_name, expected_const)) in
        [("length", 2), ("is-empty", 0), ("is-not-empty", 1)]
            .into_iter()
            .enumerate()
    {
        let base_decl = 10_550 + case_idx * 10;
        let define_decl = DeclId::new(base_decl);
        let global_get_decl = DeclId::new(base_decl + 1);
        let consumer_decl = DeclId::new(base_decl + 2);
        let decl_names = HashMap::from([
            (define_decl, "global-define".to_string()),
            (global_get_decl, "global-get".to_string()),
            (consumer_decl, consumer_name.to_string()),
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
                        decl_id: global_get_decl,
                        src_dst: RegId::new(3),
                        args: HirCallArgs {
                            positional: vec![RegId::new(0)],
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::Call {
                        decl_id: consumer_decl,
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
        .unwrap_or_else(|err| {
            panic!("typed record | {consumer_name} should lower from field count: {err:?}")
        });
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
                    src: MirValue::Const(value),
                    ..
                } if *value == expected_const
            )),
            "expected typed record | {consumer_name} to fold to {expected_const}"
        );
        assert!(
            !instructions.iter().any(|inst| matches!(
                inst,
                MirInst::ListNew { .. } | MirInst::ListPush { .. } | MirInst::ListGet { .. }
            )),
            "typed record | {consumer_name} should not materialize runtime list operations"
        );

        compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
            .unwrap_or_else(|err| {
                panic!("typed record | {consumer_name} should compile through codegen: {err:?}")
            });
    }
}

#[test]
fn test_lower_global_define_type_record_describe_uses_declared_fields() {
    let define_decl = DeclId::new(10_580);
    let global_get_decl = DeclId::new(10_581);
    let describe_decl = DeclId::new(10_582);
    let starts_with_decl = DeclId::new(10_583);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (describe_decl, "describe".to_string()),
        (starts_with_decl, "str starts-with".to_string()),
    ]);

    let expected = "record<pid: int, comm: string, active: bool>";
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
                    lit: HirLiteral::String("record{pid:int,comm:string:8,active:bool}".into()),
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
                    decl_id: describe_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String(expected.into()),
                },
                HirStmt::Call {
                    decl_id: starts_with_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5)],
                        pipeline_input: Some(RegId::new(4)),
                        ..HirCallArgs::default()
                    },
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
    .expect("typed record describe should lower from declared field layout");

    let expected_bytes = format!("{expected}\0");
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
                } if bytes.starts_with(expected_bytes.as_bytes())
            )),
        "expected describe to materialize the full typed record field layout"
    );
    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("typed record describe should compile through codegen");
}

#[test]
fn test_lower_global_define_type_aggregate_describe_uses_declared_layout() {
    for (case_idx, (type_spec, expected)) in [
        ("array{u32:4}", "list<int>"),
        (
            "array{record{pid:int,active:bool}:2}",
            "list<record<pid: int, active: bool>>",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let base_decl = 10_590 + case_idx * 10;
        let define_decl = DeclId::new(base_decl);
        let global_get_decl = DeclId::new(base_decl + 1);
        let describe_decl = DeclId::new(base_decl + 2);
        let starts_with_decl = DeclId::new(base_decl + 3);
        let decl_names = HashMap::from([
            (define_decl, "global-define".to_string()),
            (global_get_decl, "global-get".to_string()),
            (describe_decl, "describe".to_string()),
            (starts_with_decl, "str starts-with".to_string()),
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
                        lit: HirLiteral::String(type_spec.into()),
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
                        decl_id: describe_decl,
                        src_dst: RegId::new(4),
                        args: HirCallArgs {
                            pipeline_input: Some(RegId::new(3)),
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(5),
                        lit: HirLiteral::String(expected.into()),
                    },
                    HirStmt::Call {
                        decl_id: starts_with_decl,
                        src_dst: RegId::new(6),
                        args: HirCallArgs {
                            positional: vec![RegId::new(5)],
                            pipeline_input: Some(RegId::new(4)),
                            ..HirCallArgs::default()
                        },
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
        .unwrap_or_else(|err| {
            panic!("typed aggregate describe should lower from '{type_spec}': {err:?}")
        });

        let expected_bytes = format!("{expected}\0");
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
                    } if bytes.starts_with(expected_bytes.as_bytes())
                )),
            "expected describe of '{type_spec}' to materialize '{expected}'"
        );
        compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
            .unwrap_or_else(|err| {
                panic!("typed aggregate describe for '{type_spec}' should compile: {err:?}")
            });
    }
}

#[test]
fn test_lower_global_define_type_record_columns_uses_typed_field_names() {
    let define_decl = DeclId::new(10_330);
    let global_get_decl = DeclId::new(10_331);
    let columns_decl = DeclId::new(10_332);
    let length_decl = DeclId::new(10_333);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (columns_decl, "columns".to_string()),
        (length_decl, "length".to_string()),
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
                    lit: HirLiteral::String("record{pid:i64,comm:string:8}".into()),
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
                    decl_id: columns_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: length_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
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
    .expect("columns | length should lower from typed record field names");

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
                src: MirValue::Const(2),
                ..
            }
        )),
        "expected columns | length to fold to the typed record field count"
    );
    assert!(
        !instructions.iter().any(|inst| matches!(
            inst,
            MirInst::ListNew { .. } | MirInst::ListPush { .. } | MirInst::ListGet { .. }
        )),
        "metadata-only columns | length should not materialize runtime list operations"
    );

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("columns | length should compile through codegen");
}

#[test]
fn test_lower_global_define_type_record_values_first_does_not_use_shape_placeholder() {
    let define_decl = DeclId::new(10_340);
    let global_get_decl = DeclId::new(10_341);
    let values_decl = DeclId::new(10_342);
    let first_decl = DeclId::new(10_343);
    let is_empty_decl = DeclId::new(10_344);
    let decl_names = HashMap::from([
        (define_decl, "global-define".to_string()),
        (global_get_decl, "global-get".to_string()),
        (values_decl, "values".to_string()),
        (first_decl, "first".to_string()),
        (is_empty_decl, "is-empty".to_string()),
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
                    lit: HirLiteral::String("record{pid:i64,comm:string:8}".into()),
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
                    decl_id: values_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(3)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: first_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(4)),
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::Call {
                    decl_id: is_empty_decl,
                    src_dst: RegId::new(6),
                    args: HirCallArgs {
                        pipeline_input: Some(RegId::new(5)),
                        ..HirCallArgs::default()
                    },
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("values | first must not use field-count-only placeholder values");

    assert!(
        format!("{err:?}")
            .contains("values on typed record input currently supports only scalar output fields"),
        "expected values | first to reject non-scalar typed record fields without shape-only lowering, got {err:?}"
    );
    assert!(
        format!("{err:?}").contains("comm"),
        "expected values | first rejection to name the non-scalar field, got {err:?}"
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
