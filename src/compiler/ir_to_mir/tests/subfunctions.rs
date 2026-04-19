use super::*;
use crate::compiler::hir::{AnnotatedMutGlobal, HirBlock};
use crate::compiler::ir_to_mir::tests::helpers::string_member;
use crate::compiler::{
    compile_mir_to_ebpf_with_hints, compile_mir_to_ebpf_with_hints_and_globals,
    passes::optimize_with_ssa_hints,
};

#[test]
fn test_user_function_call_lowers_to_subfn() {
    use nu_protocol::ir::{Instruction, IrBlock, Literal};
    use nu_protocol::{DeclId, RegId, VarId};
    use std::sync::Arc;

    let user_ir = IrBlock {
        instructions: vec![
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(10),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec![],
        register_count: 1,
        file_count: 0,
    };

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(7),
            },
            Instruction::PushPositional { src: RegId::new(0) },
            Instruction::Call {
                decl_id: DeclId::new(1),
                src_dst: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(1) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec![],
        register_count: 2,
        file_count: 0,
    };

    let user_func = HirFunction::from_ir_block(user_ir).unwrap();
    let hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        None,
    );

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), user_func);

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &HashMap::new(),
        None,
        &user_functions,
        &HashMap::new(),
    )
    .unwrap();

    assert_eq!(result.program.subfunctions.len(), 1);
    assert_eq!(result.program.subfunctions[0].param_count, 1);

    let mut saw_call = false;
    for block in &result.program.main.blocks {
        for inst in &block.instructions {
            if let MirInst::CallSubfn { args, .. } = inst {
                saw_call = true;
                assert_eq!(args.len(), 1);
            }
        }
    }
    assert!(saw_call, "Expected CallSubfn in main function");
}

#[test]
fn test_user_function_allows_unused_params_with_signature() {
    use nu_protocol::ir::{Instruction, IrBlock, Literal};
    use nu_protocol::{DeclId, RegId, VarId};
    use std::sync::Arc;

    let user_ir = IrBlock {
        instructions: vec![
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(10),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec![],
        register_count: 1,
        file_count: 0,
    };

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(7),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(9),
            },
            Instruction::PushPositional { src: RegId::new(0) },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::Call {
                decl_id: DeclId::new(1),
                src_dst: RegId::new(2),
            },
            Instruction::Return { src: RegId::new(2) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec![],
        register_count: 3,
        file_count: 0,
    };

    let user_func = HirFunction::from_ir_block(user_ir).unwrap();
    let hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        None,
    );

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), user_func);

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![
                UserParam {
                    name: Some("a".into()),
                    kind: UserParamKind::Positional,
                    optional: false,
                },
                UserParam {
                    name: Some("b".into()),
                    kind: UserParamKind::Positional,
                    optional: false,
                },
            ],
        },
    );

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &HashMap::new(),
        None,
        &user_functions,
        &signatures,
    )
    .unwrap();

    assert_eq!(result.program.subfunctions.len(), 1);
    assert_eq!(result.program.subfunctions[0].param_count, 2);
}

#[test]
fn test_user_function_named_flag_signature() {
    use nu_protocol::ir::{DataSlice, Instruction, IrBlock};
    use nu_protocol::{DeclId, RegId, VarId};
    use std::sync::Arc;

    let user_ir = IrBlock {
        instructions: vec![
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(10),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec![],
        register_count: 1,
        file_count: 0,
    };

    let data: Arc<[u8]> = Arc::from(b"verbose".as_slice());
    let main_ir = IrBlock {
        instructions: vec![
            Instruction::PushFlag {
                name: DataSlice { start: 0, len: 7 },
            },
            Instruction::Call {
                decl_id: DeclId::new(1),
                src_dst: RegId::new(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data,
        ast: vec![],
        comments: vec![],
        register_count: 1,
        file_count: 0,
    };

    let user_func = HirFunction::from_ir_block(user_ir).unwrap();
    let hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        None,
    );

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), user_func);

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![UserParam {
                name: Some("verbose".into()),
                kind: UserParamKind::Switch,
                optional: true,
            }],
        },
    );

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &HashMap::new(),
        None,
        &user_functions,
        &signatures,
    )
    .unwrap();

    assert_eq!(result.program.subfunctions.len(), 1);
    assert_eq!(result.program.subfunctions[0].param_count, 1);
}

#[test]
fn test_user_function_metadata_only_record_args_respecialize_by_layout() {
    use nu_protocol::{DeclId, RegId, VarId};

    let param_var = VarId::new(10);
    let user_func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: param_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(nu_protocol::ast::CellPath {
                        members: vec![string_member("msg")],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
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

    let main_func = HirFunction {
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
                HirStmt::Call {
                    decl_id: DeclId::new(1),
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..Default::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::Record { capacity: 1 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::String("msg".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(8),
                    lit: HirLiteral::String("bye".into()),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(6),
                    key: RegId::new(7),
                    val: RegId::new(8),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(9),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(10),
                    lit: HirLiteral::String("inner".into()),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(9),
                    key: RegId::new(10),
                    val: RegId::new(6),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(11),
                    lit: HirLiteral::String("cpu".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(12),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(9),
                    key: RegId::new(11),
                    val: RegId::new(12),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(1),
                    src_dst: RegId::new(13),
                    args: HirCallArgs {
                        positional: vec![RegId::new(9)],
                        ..Default::default()
                    },
                },
            ],
            terminator: HirTerminator::Return {
                src: RegId::new(13),
            },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 14,
        file_count: 0,
    };

    let hir_program = HirProgram::new(main_func, HashMap::new(), vec![], None);

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), user_func);

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![UserParam {
                name: Some("state".into()),
                kind: UserParamKind::Positional,
                optional: false,
            }],
        },
    );

    let err = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &HashMap::new(),
        None,
        &user_functions,
        &signatures,
    )
    .expect_err(
        "distinct metadata-only record layouts should trigger a fresh subfunction specialization",
    );

    assert!(
        err.to_string()
            .contains("typed field path 'msg' has no field 'msg'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_user_function_mutating_annotated_global_param_writes_through_global() {
    use nu_protocol::ast::{Math, Operator};
    use nu_protocol::{DeclId, RegId, Span, Type, Value, VarId};

    let global_var = VarId::new(250);
    let param_var = VarId::new(10);
    let user_func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: param_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Math(Math::Add),
                    rhs: RegId::new(1),
                },
                HirStmt::StoreVariable {
                    var_id: param_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: param_var,
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

    let main_func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: global_var,
                },
                HirStmt::Call {
                    decl_id: DeclId::new(1),
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..Default::default()
                    },
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: global_var,
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

    let mut hir_program = HirProgram::new(main_func, HashMap::new(), vec![], None);
    hir_program.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Int,
        initial_value: Value::int(7, Span::test_data()),
    }];

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), user_func);

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![
                UserParam {
                    name: None,
                    kind: UserParamKind::Input,
                    optional: false,
                },
                UserParam {
                    name: Some("state".into()),
                    kind: UserParamKind::Positional,
                    optional: false,
                },
            ],
        },
    );

    let result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &HashMap::new(),
        None,
        &user_functions,
        &signatures,
    )
    .expect("annotated global user-function mutation should lower");

    let subfn = &result.program.subfunctions[0];
    assert!(
        subfn
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadGlobal { symbol, .. } if symbol == "__nu_local_global_250"
            )),
        "expected user-function param loads to read through the annotated global backing"
    );
    assert!(
        subfn
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::Store { .. })),
        "expected user-function param mutation to emit a write through the backing global"
    );
}

#[test]
fn test_user_function_mutating_annotated_global_param_compiles() {
    use nu_protocol::ast::{Math, Operator};
    use nu_protocol::{DeclId, RegId, Span, Type, Value, VarId};

    let global_var = VarId::new(250);
    let param_var = VarId::new(10);
    let user_func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: param_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Math(Math::Add),
                    rhs: RegId::new(1),
                },
                HirStmt::StoreVariable {
                    var_id: param_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: param_var,
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

    let main_func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: global_var,
                },
                HirStmt::Call {
                    decl_id: DeclId::new(1),
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..Default::default()
                    },
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: global_var,
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

    let mut hir_program = HirProgram::new(main_func, HashMap::new(), vec![], None);
    hir_program.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Int,
        initial_value: Value::int(7, Span::test_data()),
    }];

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), user_func);

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![UserParam {
                name: Some("state".into()),
                kind: UserParamKind::Positional,
                optional: false,
            }],
        },
    );

    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(1), "bump".to_string());
    let hir_types = crate::compiler::hir_type_infer::infer_hir_types_with_decls(
        &hir_program,
        &decl_names,
        &user_functions,
    )
    .expect("view-ir style program should infer HIR types");

    let probe_ctx = ProbeContext::new(crate::compiler::EbpfProgramType::Kprobe, "ksys_read");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &user_functions,
        &signatures,
    )
    .expect("annotated global user-function mutation should lower");

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    for ((subfn, hints), stack_slots) in result
        .program
        .subfunctions
        .iter_mut()
        .zip(result.type_hints.subfunctions.iter_mut())
        .zip(result.type_hints.subfunction_stack_slots.iter())
    {
        optimize_with_ssa_hints(
            subfn,
            None,
            hints,
            stack_slots,
            &result.type_hints.generic_map_value_types,
        );
    }

    compile_mir_to_ebpf_with_hints_and_globals(
        &result.program,
        Some(&probe_ctx),
        Some(&result.type_hints),
        result.readonly_globals,
        result.data_globals,
        result.bss_globals,
    )
    .expect("annotated global user-function mutation should compile");
}

#[test]
fn test_shadowed_user_function_mutating_annotated_global_param_compiles() {
    use nu_protocol::{DeclId, RegId, Span, Type, Value, VarId};

    let global_var = VarId::new(250);
    let param_var = VarId::new(81);
    let local_var = VarId::new(82);
    let user_func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: param_var,
                },
                HirStmt::StoreVariable {
                    var_id: local_var,
                    src: RegId::new(0),
                },
                HirStmt::Drain { src: RegId::new(0) },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: local_var,
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
                HirStmt::Span {
                    src_dst: RegId::new(0),
                },
                HirStmt::StoreVariable {
                    var_id: local_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Nothing,
                },
                HirStmt::Drain { src: RegId::new(0) },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: local_var,
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

    let main_func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: global_var,
                },
                HirStmt::Call {
                    decl_id: DeclId::new(1),
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..Default::default()
                    },
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: global_var,
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

    let mut hir_program = HirProgram::new(main_func, HashMap::new(), vec![], None);
    hir_program.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Int,
        initial_value: Value::int(0, Span::test_data()),
    }];

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), user_func);

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![UserParam {
                name: Some("state".into()),
                kind: UserParamKind::Positional,
                optional: false,
            }],
        },
    );

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &HashMap::new(),
        None,
        &user_functions,
        &signatures,
    )
    .expect("shadowed annotated global user-function mutation should lower");

    optimize_with_ssa_hints(
        &mut result.program.main,
        None,
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    for ((subfn, hints), stack_slots) in result
        .program
        .subfunctions
        .iter_mut()
        .zip(result.type_hints.subfunctions.iter_mut())
        .zip(result.type_hints.subfunction_stack_slots.iter())
    {
        optimize_with_ssa_hints(
            subfn,
            None,
            hints,
            stack_slots,
            &result.type_hints.generic_map_value_types,
        );
    }

    compile_mir_to_ebpf_with_hints_and_globals(
        &result.program,
        None,
        Some(&result.type_hints),
        result.readonly_globals,
        result.data_globals,
        result.bss_globals,
    )
    .expect("shadowed annotated global user-function mutation should compile");
}

#[test]
fn test_shadowed_user_function_mutating_annotated_record_global_param_compiles() {
    use nu_protocol::ast::{Math, Operator, PathMember};
    use nu_protocol::casing::Casing;
    use nu_protocol::{DeclId, Record, RegId, Span, Type, Value, VarId};

    let global_var = VarId::new(250);
    let param_var = VarId::new(81);
    let local_var = VarId::new(82);
    let user_func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: param_var,
                },
                HirStmt::StoreVariable {
                    var_id: local_var,
                    src: RegId::new(0),
                },
                HirStmt::Drain { src: RegId::new(0) },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: local_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![PathMember::test_string(
                            "pid".to_string(),
                            false,
                            Casing::Sensitive,
                        )],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Math(Math::Add),
                    rhs: RegId::new(1),
                },
                HirStmt::Span {
                    src_dst: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(1),
                    var_id: local_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![PathMember::test_string(
                            "pid".to_string(),
                            false,
                            Casing::Sensitive,
                        )],
                    })),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(1),
                    path: RegId::new(2),
                    new_value: RegId::new(0),
                },
                HirStmt::StoreVariable {
                    var_id: local_var,
                    src: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Nothing,
                },
                HirStmt::Drain { src: RegId::new(0) },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: local_var,
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

    let main_func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: global_var,
                },
                HirStmt::Call {
                    decl_id: DeclId::new(1),
                    src_dst: RegId::new(1),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        ..Default::default()
                    },
                },
                HirStmt::StoreVariable {
                    var_id: global_var,
                    src: RegId::new(1),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: global_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![PathMember::test_string(
                            "pid".to_string(),
                            false,
                            Casing::Sensitive,
                        )],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(2),
                    path: RegId::new(3),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(2) },
        }],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };

    let mut initial = Record::new();
    initial.push("pid", Value::int(0, Span::test_data()));
    initial.push("ok", Value::bool(false, Span::test_data()));

    let mut hir_program = HirProgram::new(main_func, HashMap::new(), vec![], None);
    hir_program.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Record(Box::new([
            ("pid".to_string(), Type::Int),
            ("ok".to_string(), Type::Bool),
        ])),
        initial_value: Value::record(initial, Span::test_data()),
    }];

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), user_func);

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![UserParam {
                name: Some("state".into()),
                kind: UserParamKind::Positional,
                optional: false,
            }],
        },
    );

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &HashMap::new(),
        None,
        &user_functions,
        &signatures,
    )
    .expect("shadowed annotated record global user-function mutation should lower");

    optimize_with_ssa_hints(
        &mut result.program.main,
        None,
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    for ((subfn, hints), stack_slots) in result
        .program
        .subfunctions
        .iter_mut()
        .zip(result.type_hints.subfunctions.iter_mut())
        .zip(result.type_hints.subfunction_stack_slots.iter())
    {
        optimize_with_ssa_hints(
            subfn,
            None,
            hints,
            stack_slots,
            &result.type_hints.generic_map_value_types,
        );
    }

    compile_mir_to_ebpf_with_hints_and_globals(
        &result.program,
        None,
        Some(&result.type_hints),
        result.readonly_globals,
        result.data_globals,
        result.bss_globals,
    )
    .expect("shadowed annotated record global user-function mutation should compile");
}

#[test]
fn test_user_function_returned_annotated_record_can_flow_through_local() {
    use nu_protocol::ast::{Math, Operator, PathMember};
    use nu_protocol::casing::Casing;
    use nu_protocol::{DeclId, Record, RegId, Span, Type, Value, VarId};

    let global_var = VarId::new(250);
    let param_var = VarId::new(81);
    let local_var = VarId::new(82);
    let next_var = VarId::new(83);
    let user_func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: param_var,
                },
                HirStmt::StoreVariable {
                    var_id: local_var,
                    src: RegId::new(0),
                },
                HirStmt::Drain { src: RegId::new(0) },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: local_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![PathMember::test_string(
                            "pid".to_string(),
                            false,
                            Casing::Sensitive,
                        )],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(0),
                    op: Operator::Math(Math::Add),
                    rhs: RegId::new(1),
                },
                HirStmt::Span {
                    src_dst: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(1),
                    var_id: local_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![PathMember::test_string(
                            "pid".to_string(),
                            false,
                            Casing::Sensitive,
                        )],
                    })),
                },
                HirStmt::UpsertCellPath {
                    src_dst: RegId::new(1),
                    path: RegId::new(2),
                    new_value: RegId::new(0),
                },
                HirStmt::StoreVariable {
                    var_id: local_var,
                    src: RegId::new(1),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Nothing,
                },
                HirStmt::Drain { src: RegId::new(0) },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: local_var,
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

    let main_func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(1),
                    var_id: global_var,
                },
                HirStmt::Call {
                    decl_id: DeclId::new(1),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..Default::default()
                    },
                },
                HirStmt::StoreVariable {
                    var_id: next_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: next_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![PathMember::test_string(
                            "pid".to_string(),
                            false,
                            Casing::Sensitive,
                        )],
                    })),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
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

    let mut initial = Record::new();
    initial.push("pid", Value::int(0, Span::test_data()));
    initial.push("ok", Value::bool(false, Span::test_data()));

    let mut hir_program = HirProgram::new(main_func, HashMap::new(), vec![], None);
    hir_program.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: global_var,
        declared_type: Type::Record(Box::new([
            ("pid".to_string(), Type::Int),
            ("ok".to_string(), Type::Bool),
        ])),
        initial_value: Value::record(initial, Span::test_data()),
    }];

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), user_func);

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![UserParam {
                name: Some("state".into()),
                kind: UserParamKind::Positional,
                optional: false,
            }],
        },
    );

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &HashMap::new(),
        None,
        &user_functions,
        &signatures,
    )
    .expect("returned annotated record through local should lower");

    optimize_with_ssa_hints(
        &mut result.program.main,
        None,
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    for ((subfn, hints), stack_slots) in result
        .program
        .subfunctions
        .iter_mut()
        .zip(result.type_hints.subfunctions.iter_mut())
        .zip(result.type_hints.subfunction_stack_slots.iter())
    {
        optimize_with_ssa_hints(
            subfn,
            None,
            hints,
            stack_slots,
            &result.type_hints.generic_map_value_types,
        );
    }

    compile_mir_to_ebpf_with_hints_and_globals(
        &result.program,
        None,
        Some(&result.type_hints),
        result.readonly_globals,
        result.data_globals,
        result.bss_globals,
    )
    .expect("returned annotated record through local should compile");
}

#[test]
fn test_user_function_returned_metadata_only_record_preserves_string_semantics() {
    use nu_protocol::{DeclId, RegId, VarId};

    let param_var = VarId::new(81);
    let user_func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(3),
                    var_id: param_var,
                },
                HirStmt::Drain { src: RegId::new(3) },
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

    let main_func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(1),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..Default::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("msg")],
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
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0),
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

    let hir_program = HirProgram::new(main_func, HashMap::new(), vec![], None);

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), user_func);

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![UserParam {
                name: Some("seed".into()),
                kind: UserParamKind::Positional,
                optional: false,
            }],
        },
    );

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &HashMap::new(),
        None,
        &user_functions,
        &signatures,
    )
    .expect("metadata-only record return should keep enough information for caller projection");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected caller to keep returned metadata-only record string field semantics"
    );

    optimize_with_ssa_hints(
        &mut result.program.main,
        None,
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    for ((subfn, hints), stack_slots) in result
        .program
        .subfunctions
        .iter_mut()
        .zip(result.type_hints.subfunctions.iter_mut())
        .zip(result.type_hints.subfunction_stack_slots.iter())
    {
        optimize_with_ssa_hints(
            subfn,
            None,
            hints,
            stack_slots,
            &result.type_hints.generic_map_value_types,
        );
    }

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("metadata-only record return should compile after caller projection");
}

#[test]
fn test_multiblock_user_function_returned_metadata_only_record_preserves_string_semantics() {
    use nu_protocol::{DeclId, RegId, VarId};

    let param_var = VarId::new(81);
    let user_func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(3),
                        var_id: param_var,
                    },
                    HirStmt::Drain { src: RegId::new(3) },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::Bool(true),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(4),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
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
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(2),
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
                        lit: HirLiteral::String("bye".into()),
                    },
                    HirStmt::RecordInsert {
                        src_dst: RegId::new(0),
                        key: RegId::new(1),
                        val: RegId::new(2),
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
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 5,
        file_count: 0,
    };

    let main_func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::Int(0),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(1),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        ..Default::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::CellPath(Box::new(CellPath {
                        members: vec![string_member("msg")],
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
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::Int(0),
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

    let hir_program = HirProgram::new(main_func, HashMap::new(), vec![], None);

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), user_func);

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![UserParam {
                name: Some("seed".into()),
                kind: UserParamKind::Positional,
                optional: false,
            }],
        },
    );

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &HashMap::new(),
        None,
        &user_functions,
        &signatures,
    )
    .expect("multiblock metadata-only record return should lower");

    assert!(
        result.program.subfunctions.is_empty(),
        "record-returning multiblock user function should inline instead of lowering as a subfunction"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected caller to keep returned record string field semantics after multiblock inline"
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .all(|inst| !matches!(inst, MirInst::CallSubfn { .. })),
        "record-returning multiblock user function should not emit a BPF subfunction call"
    );

    optimize_with_ssa_hints(
        &mut result.program.main,
        None,
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );

    compile_mir_to_ebpf_with_hints(&result.program, None, Some(&result.type_hints))
        .expect("multiblock metadata-only record return should compile after caller projection");
}

#[test]
fn test_view_ir_style_user_function_returned_annotated_record_can_flow_through_local() {
    use nu_protocol::ast::{CellPath, Math, Operator, PathMember};
    use nu_protocol::casing::Casing;
    use nu_protocol::ir::{Instruction, IrBlock, Literal, RedirectMode};
    use nu_protocol::{DeclId, Record, RegId, Span, Type, Value, VarId};
    use std::sync::Arc;

    let user_ir = IrBlock {
        instructions: vec![
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(80),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(81),
                src: RegId::new(0),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(81),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::CellPath(Box::new(CellPath {
                    members: vec![PathMember::test_string(
                        "pid".to_string(),
                        false,
                        Casing::Sensitive,
                    )],
                })),
            },
            Instruction::FollowCellPath {
                src_dst: RegId::new(0),
                path: RegId::new(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(1),
            },
            Instruction::BinaryOp {
                lhs_dst: RegId::new(0),
                op: Operator::Math(Math::Add),
                rhs: RegId::new(1),
            },
            Instruction::Span {
                src_dst: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(1),
                var_id: VarId::new(81),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::CellPath(Box::new(CellPath {
                    members: vec![PathMember::test_string(
                        "pid".to_string(),
                        false,
                        Casing::Sensitive,
                    )],
                })),
            },
            Instruction::UpsertCellPath {
                src_dst: RegId::new(1),
                path: RegId::new(2),
                new_value: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(81),
                src: RegId::new(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Nothing,
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(81),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec!["".into(); 17],
        register_count: 3,
        file_count: 0,
    };

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadVariable {
                dst: RegId::new(1),
                var_id: VarId::new(84),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::RedirectOut {
                mode: RedirectMode::Value,
            },
            Instruction::Call {
                decl_id: DeclId::new(1),
                src_dst: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(85),
                src: RegId::new(0),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(85),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::CellPath(Box::new(CellPath {
                    members: vec![PathMember::test_string(
                        "pid".to_string(),
                        false,
                        Casing::Sensitive,
                    )],
                })),
            },
            Instruction::FollowCellPath {
                src_dst: RegId::new(0),
                path: RegId::new(1),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec!["".into(); 12],
        register_count: 3,
        file_count: 0,
    };

    let mut initial = Record::new();
    initial.push("pid", Value::int(0, Span::test_data()));
    initial.push("ok", Value::bool(false, Span::test_data()));

    let mut hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        None,
    );
    hir_program.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: VarId::new(84),
        declared_type: Type::Record(Box::new([
            ("pid".to_string(), Type::Int),
            ("ok".to_string(), Type::Bool),
        ])),
        initial_value: Value::record(initial, Span::test_data()),
    }];

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), HirFunction::from_ir_block(user_ir).unwrap());

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![UserParam {
                name: Some("state".into()),
                kind: UserParamKind::Positional,
                optional: false,
            }],
        },
    );

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        None,
        &HashMap::new(),
        None,
        &user_functions,
        &signatures,
    )
    .expect("view-ir style returned annotated record through local should lower");

    optimize_with_ssa_hints(
        &mut result.program.main,
        None,
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    for ((subfn, hints), stack_slots) in result
        .program
        .subfunctions
        .iter_mut()
        .zip(result.type_hints.subfunctions.iter_mut())
        .zip(result.type_hints.subfunction_stack_slots.iter())
    {
        optimize_with_ssa_hints(
            subfn,
            None,
            hints,
            stack_slots,
            &result.type_hints.generic_map_value_types,
        );
    }

    compile_mir_to_ebpf_with_hints_and_globals(
        &result.program,
        None,
        Some(&result.type_hints),
        result.readonly_globals,
        result.data_globals,
        result.bss_globals,
    )
    .expect("view-ir style returned annotated record through local should compile");
}

#[test]
fn test_view_ir_style_user_function_returned_annotated_string_record_can_flow_through_local() {
    use nu_protocol::ast::{CellPath, PathMember};
    use nu_protocol::casing::Casing;
    use nu_protocol::ir::{DataSlice, Instruction, IrBlock, Literal, RedirectMode};
    use nu_protocol::{DeclId, Record, RegId, Span, Type, Value, VarId};
    use std::sync::Arc;

    let user_data: Arc<[u8]> = Arc::from(b"msgok".to_vec());
    let user_ir = IrBlock {
        instructions: vec![
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(80),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(81),
                src: RegId::new(0),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::String(DataSlice { start: 3, len: 2 }),
            },
            Instruction::LoadVariable {
                dst: RegId::new(1),
                var_id: VarId::new(81),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::CellPath(Box::new(CellPath {
                    members: vec![PathMember::test_string(
                        "msg".to_string(),
                        false,
                        Casing::Sensitive,
                    )],
                })),
            },
            Instruction::UpsertCellPath {
                src_dst: RegId::new(1),
                path: RegId::new(2),
                new_value: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(81),
                src: RegId::new(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Nothing,
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(81),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: user_data,
        ast: vec![],
        comments: vec!["".into(); 12],
        register_count: 3,
        file_count: 0,
    };

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadVariable {
                dst: RegId::new(1),
                var_id: VarId::new(84),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::RedirectOut {
                mode: RedirectMode::Value,
            },
            Instruction::Call {
                decl_id: DeclId::new(1),
                src_dst: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(85),
                src: RegId::new(0),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(85),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::CellPath(Box::new(CellPath {
                    members: vec![PathMember::test_string(
                        "msg".to_string(),
                        false,
                        Casing::Sensitive,
                    )],
                })),
            },
            Instruction::FollowCellPath {
                src_dst: RegId::new(0),
                path: RegId::new(1),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec!["".into(); 12],
        register_count: 3,
        file_count: 0,
    };

    let mut initial = Record::new();
    initial.push("msg", Value::string("hi", Span::test_data()));

    let mut hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        None,
    );
    hir_program.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: VarId::new(84),
        declared_type: Type::Record(Box::new([("msg".to_string(), Type::String)])),
        initial_value: Value::record(initial, Span::test_data()),
    }];

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), HirFunction::from_ir_block(user_ir).unwrap());

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![
                UserParam {
                    name: None,
                    kind: UserParamKind::Input,
                    optional: false,
                },
                UserParam {
                    name: Some("state".into()),
                    kind: UserParamKind::Positional,
                    optional: false,
                },
            ],
        },
    );

    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(1), "bump".to_string());
    let hir_types = crate::compiler::hir_type_infer::infer_hir_types_with_decls(
        &hir_program,
        &decl_names,
        &user_functions,
    )
    .expect("view-ir style string-record program should infer HIR types");
    let probe_ctx = ProbeContext::new(crate::compiler::EbpfProgramType::Kprobe, "ksys_read");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &user_functions,
        &signatures,
    )
    .expect("view-ir style returned annotated string record through local should lower");

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    for ((subfn, hints), stack_slots) in result
        .program
        .subfunctions
        .iter_mut()
        .zip(result.type_hints.subfunctions.iter_mut())
        .zip(result.type_hints.subfunction_stack_slots.iter())
    {
        optimize_with_ssa_hints(
            subfn,
            None,
            hints,
            stack_slots,
            &result.type_hints.generic_map_value_types,
        );
    }

    compile_mir_to_ebpf_with_hints_and_globals(
        &result.program,
        Some(&probe_ctx),
        Some(&result.type_hints),
        result.readonly_globals,
        result.data_globals,
        result.bss_globals,
    )
    .expect("view-ir style returned annotated string record through local should compile");
}

#[test]
fn test_view_ir_style_user_function_returned_annotated_list_record_can_flow_through_local() {
    use nu_protocol::ast::{CellPath, PathMember};
    use nu_protocol::casing::Casing;
    use nu_protocol::ir::{Instruction, IrBlock, Literal, RedirectMode};
    use nu_protocol::{DeclId, Record, RegId, Span, Type, Value, VarId};
    use std::sync::Arc;

    let user_ir = IrBlock {
        instructions: vec![
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(80),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(81),
                src: RegId::new(0),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::List { capacity: 2 },
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(33),
            },
            Instruction::ListPush {
                src_dst: RegId::new(0),
                item: RegId::new(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(44),
            },
            Instruction::ListPush {
                src_dst: RegId::new(0),
                item: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(1),
                var_id: VarId::new(81),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::CellPath(Box::new(CellPath {
                    members: vec![PathMember::test_string(
                        "vals".to_string(),
                        false,
                        Casing::Sensitive,
                    )],
                })),
            },
            Instruction::UpsertCellPath {
                src_dst: RegId::new(1),
                path: RegId::new(2),
                new_value: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(81),
                src: RegId::new(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Nothing,
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(81),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec!["".into(); 16],
        register_count: 3,
        file_count: 0,
    };

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadVariable {
                dst: RegId::new(1),
                var_id: VarId::new(84),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::RedirectOut {
                mode: RedirectMode::Value,
            },
            Instruction::Call {
                decl_id: DeclId::new(1),
                src_dst: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(85),
                src: RegId::new(0),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(85),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::CellPath(Box::new(CellPath {
                    members: vec![PathMember::test_string(
                        "vals".to_string(),
                        false,
                        Casing::Sensitive,
                    )],
                })),
            },
            Instruction::FollowCellPath {
                src_dst: RegId::new(0),
                path: RegId::new(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(1),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::RedirectOut {
                mode: RedirectMode::Value,
            },
            Instruction::Call {
                decl_id: DeclId::new(2),
                src_dst: RegId::new(0),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec!["".into(); 16],
        register_count: 2,
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

    let mut hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        None,
    );
    hir_program.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: VarId::new(84),
        declared_type: Type::Record(Box::new([(
            "vals".to_string(),
            Type::List(Box::new(Type::Int)),
        )])),
        initial_value: Value::record(initial, Span::test_data()),
    }];

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), HirFunction::from_ir_block(user_ir).unwrap());

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![
                UserParam {
                    name: None,
                    kind: UserParamKind::Input,
                    optional: false,
                },
                UserParam {
                    name: Some("state".into()),
                    kind: UserParamKind::Positional,
                    optional: false,
                },
            ],
        },
    );
    signatures.insert(
        DeclId::new(2),
        UserFunctionSig {
            params: vec![
                UserParam {
                    name: None,
                    kind: UserParamKind::Input,
                    optional: false,
                },
                UserParam {
                    name: Some("index".into()),
                    kind: UserParamKind::Positional,
                    optional: false,
                },
            ],
        },
    );

    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(1), "bump".to_string());
    decl_names.insert(DeclId::new(2), "get".to_string());
    let hir_types = crate::compiler::hir_type_infer::infer_hir_types_with_decls(
        &hir_program,
        &decl_names,
        &user_functions,
    )
    .expect("view-ir style list-record program should infer HIR types");
    let probe_ctx = ProbeContext::new(crate::compiler::EbpfProgramType::Kprobe, "ksys_read");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &user_functions,
        &signatures,
    )
    .expect("view-ir style returned annotated list record through local should lower");

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    for ((subfn, hints), stack_slots) in result
        .program
        .subfunctions
        .iter_mut()
        .zip(result.type_hints.subfunctions.iter_mut())
        .zip(result.type_hints.subfunction_stack_slots.iter())
    {
        optimize_with_ssa_hints(
            subfn,
            None,
            hints,
            stack_slots,
            &result.type_hints.generic_map_value_types,
        );
    }

    compile_mir_to_ebpf_with_hints_and_globals(
        &result.program,
        Some(&probe_ctx),
        Some(&result.type_hints),
        result.readonly_globals,
        result.data_globals,
        result.bss_globals,
    )
    .expect("view-ir style returned annotated list record through local should compile");
}

#[test]
fn test_view_ir_style_user_function_returned_nested_annotated_list_record_can_flow_through_local() {
    use nu_protocol::ast::{CellPath, PathMember};
    use nu_protocol::casing::Casing;
    use nu_protocol::ir::{Instruction, IrBlock, Literal, RedirectMode};
    use nu_protocol::{DeclId, Record, RegId, Span, Type, Value, VarId};
    use std::sync::Arc;

    let user_ir = IrBlock {
        instructions: vec![
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(80),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(81),
                src: RegId::new(0),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::List { capacity: 2 },
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(33),
            },
            Instruction::ListPush {
                src_dst: RegId::new(0),
                item: RegId::new(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(44),
            },
            Instruction::ListPush {
                src_dst: RegId::new(0),
                item: RegId::new(1),
            },
            Instruction::LoadVariable {
                dst: RegId::new(1),
                var_id: VarId::new(81),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::CellPath(Box::new(CellPath {
                    members: vec![
                        PathMember::test_string("nested".to_string(), false, Casing::Sensitive),
                        PathMember::test_string("vals".to_string(), false, Casing::Sensitive),
                    ],
                })),
            },
            Instruction::UpsertCellPath {
                src_dst: RegId::new(1),
                path: RegId::new(2),
                new_value: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(81),
                src: RegId::new(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Nothing,
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(81),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec!["".into(); 16],
        register_count: 3,
        file_count: 0,
    };

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadVariable {
                dst: RegId::new(1),
                var_id: VarId::new(84),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::RedirectOut {
                mode: RedirectMode::Value,
            },
            Instruction::Call {
                decl_id: DeclId::new(1),
                src_dst: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: VarId::new(85),
                src: RegId::new(0),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: VarId::new(85),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::CellPath(Box::new(CellPath {
                    members: vec![
                        PathMember::test_string("nested".to_string(), false, Casing::Sensitive),
                        PathMember::test_string("vals".to_string(), false, Casing::Sensitive),
                    ],
                })),
            },
            Instruction::FollowCellPath {
                src_dst: RegId::new(0),
                path: RegId::new(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(1),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::RedirectOut {
                mode: RedirectMode::Value,
            },
            Instruction::Call {
                decl_id: DeclId::new(2),
                src_dst: RegId::new(0),
            },
            Instruction::Drain { src: RegId::new(0) },
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::Int(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec!["".into(); 16],
        register_count: 2,
        file_count: 0,
    };

    let mut nested = Record::new();
    nested.push(
        "vals",
        Value::list(
            vec![
                Value::int(11, Span::test_data()),
                Value::int(22, Span::test_data()),
            ],
            Span::test_data(),
        ),
    );
    let mut initial = Record::new();
    initial.push("nested", Value::record(nested, Span::test_data()));

    let mut hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        None,
    );
    hir_program.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: VarId::new(84),
        declared_type: Type::Record(Box::new([(
            "nested".to_string(),
            Type::Record(Box::new([(
                "vals".to_string(),
                Type::List(Box::new(Type::Int)),
            )])),
        )])),
        initial_value: Value::record(initial, Span::test_data()),
    }];

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), HirFunction::from_ir_block(user_ir).unwrap());

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![UserParam {
                name: Some("state".into()),
                kind: UserParamKind::Positional,
                optional: false,
            }],
        },
    );
    signatures.insert(
        DeclId::new(2),
        UserFunctionSig {
            params: vec![
                UserParam {
                    name: None,
                    kind: UserParamKind::Input,
                    optional: false,
                },
                UserParam {
                    name: Some("index".into()),
                    kind: UserParamKind::Positional,
                    optional: false,
                },
            ],
        },
    );

    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(1), "bump".to_string());
    decl_names.insert(DeclId::new(2), "get".to_string());
    let hir_types = crate::compiler::hir_type_infer::infer_hir_types_with_decls(
        &hir_program,
        &decl_names,
        &user_functions,
    )
    .expect("view-ir style nested list-record program should infer HIR types");
    let probe_ctx = ProbeContext::new(crate::compiler::EbpfProgramType::Kprobe, "ksys_read");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &user_functions,
        &signatures,
    )
    .expect("view-ir style returned nested annotated list record through local should lower");

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );
    for ((subfn, hints), stack_slots) in result
        .program
        .subfunctions
        .iter_mut()
        .zip(result.type_hints.subfunctions.iter_mut())
        .zip(result.type_hints.subfunction_stack_slots.iter())
    {
        optimize_with_ssa_hints(
            subfn,
            None,
            hints,
            stack_slots,
            &result.type_hints.generic_map_value_types,
        );
    }

    compile_mir_to_ebpf_with_hints_and_globals(
        &result.program,
        Some(&probe_ctx),
        Some(&result.type_hints),
        result.readonly_globals,
        result.data_globals,
        result.bss_globals,
    )
    .expect("view-ir style returned nested annotated list record through local should compile");
}

#[test]
fn test_view_ir_style_user_function_constant_string_return_can_flow_through_local() {
    use nu_protocol::ir::{Instruction, IrBlock, Literal, RedirectMode};
    use nu_protocol::{DeclId, RegId};
    use std::sync::Arc;

    let user_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::String(nu_protocol::ir::DataSlice { start: 0, len: 2 }),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from(b"ok".as_slice()),
        ast: vec![],
        comments: vec!["".into(); 2],
        register_count: 1,
        file_count: 0,
    };

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::String(nu_protocol::ir::DataSlice { start: 0, len: 2 }),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::RedirectOut {
                mode: RedirectMode::Value,
            },
            Instruction::Call {
                decl_id: DeclId::new(1),
                src_dst: RegId::new(0),
            },
            Instruction::RedirectOut {
                mode: RedirectMode::Caller,
            },
            Instruction::RedirectErr {
                mode: RedirectMode::Caller,
            },
            Instruction::Call {
                decl_id: DeclId::new(2),
                src_dst: RegId::new(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from(b"hi".as_slice()),
        ast: vec![],
        comments: vec!["".into(); 8],
        register_count: 2,
        file_count: 0,
    };

    let hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        None,
    );

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), HirFunction::from_ir_block(user_ir).unwrap());

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![
                UserParam {
                    name: None,
                    kind: UserParamKind::Input,
                    optional: false,
                },
                UserParam {
                    name: Some("msg".into()),
                    kind: UserParamKind::Positional,
                    optional: false,
                },
            ],
        },
    );

    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(1), "bump".to_string());
    decl_names.insert(DeclId::new(2), "count".to_string());
    let hir_types = crate::compiler::hir_type_infer::infer_hir_types_with_decls(
        &hir_program,
        &decl_names,
        &user_functions,
    )
    .expect("view-ir style constant string program should infer HIR types");
    let probe_ctx = ProbeContext::new(crate::compiler::EbpfProgramType::Kprobe, "ksys_read");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &user_functions,
        &signatures,
    )
    .expect("view-ir style constant string return through local should lower");

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );

    compile_mir_to_ebpf_with_hints_and_globals(
        &result.program,
        Some(&probe_ctx),
        Some(&result.type_hints),
        result.readonly_globals,
        result.data_globals,
        result.bss_globals,
    )
    .expect("view-ir style constant string return through local should compile");
}

#[test]
fn test_view_ir_style_user_function_constant_list_return_can_flow_through_local() {
    use nu_protocol::ir::{Instruction, IrBlock, Literal, RedirectMode};
    use nu_protocol::{DeclId, RegId};
    use std::sync::Arc;

    let user_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(0),
                lit: Literal::List { capacity: 2 },
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(33),
            },
            Instruction::ListPush {
                src_dst: RegId::new(0),
                item: RegId::new(1),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::Int(44),
            },
            Instruction::ListPush {
                src_dst: RegId::new(0),
                item: RegId::new(1),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec!["".into(); 6],
        register_count: 2,
        file_count: 0,
    };

    let main_ir = IrBlock {
        instructions: vec![
            Instruction::LoadLiteral {
                dst: RegId::new(1),
                lit: Literal::List { capacity: 2 },
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::Int(11),
            },
            Instruction::ListPush {
                src_dst: RegId::new(1),
                item: RegId::new(2),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::Int(22),
            },
            Instruction::ListPush {
                src_dst: RegId::new(1),
                item: RegId::new(2),
            },
            Instruction::PushPositional { src: RegId::new(1) },
            Instruction::RedirectOut {
                mode: RedirectMode::Value,
            },
            Instruction::Call {
                decl_id: DeclId::new(1),
                src_dst: RegId::new(0),
            },
            Instruction::StoreVariable {
                var_id: nu_protocol::VarId::new(40),
                src: RegId::new(0),
            },
            Instruction::LoadVariable {
                dst: RegId::new(0),
                var_id: nu_protocol::VarId::new(40),
            },
            Instruction::LoadLiteral {
                dst: RegId::new(2),
                lit: Literal::CellPath(Box::new(nu_protocol::ast::CellPath {
                    members: vec![nu_protocol::ast::PathMember::Int {
                        val: 1,
                        span: nu_protocol::Span::test_data(),
                        optional: false,
                    }],
                })),
            },
            Instruction::FollowCellPath {
                src_dst: RegId::new(0),
                path: RegId::new(2),
            },
            Instruction::RedirectOut {
                mode: RedirectMode::Caller,
            },
            Instruction::RedirectErr {
                mode: RedirectMode::Caller,
            },
            Instruction::Call {
                decl_id: DeclId::new(2),
                src_dst: RegId::new(0),
            },
            Instruction::Return { src: RegId::new(0) },
        ],
        spans: vec![],
        data: Arc::from([]),
        ast: vec![],
        comments: vec!["".into(); 15],
        register_count: 3,
        file_count: 0,
    };

    let hir_program = HirProgram::new(
        HirFunction::from_ir_block(main_ir).unwrap(),
        HashMap::new(),
        vec![],
        None,
    );

    let mut user_functions = HashMap::new();
    user_functions.insert(DeclId::new(1), HirFunction::from_ir_block(user_ir).unwrap());

    let mut signatures = HashMap::new();
    signatures.insert(
        DeclId::new(1),
        UserFunctionSig {
            params: vec![
                UserParam {
                    name: None,
                    kind: UserParamKind::Input,
                    optional: false,
                },
                UserParam {
                    name: Some("vals".into()),
                    kind: UserParamKind::Positional,
                    optional: false,
                },
            ],
        },
    );

    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(1), "bump".to_string());
    decl_names.insert(DeclId::new(2), "count".to_string());
    let hir_types = crate::compiler::hir_type_infer::infer_hir_types_with_decls(
        &hir_program,
        &decl_names,
        &user_functions,
    )
    .expect("view-ir style constant list program should infer HIR types");
    let probe_ctx = ProbeContext::new(crate::compiler::EbpfProgramType::Kprobe, "ksys_read");

    let mut result = lower_hir_to_mir_with_hints(
        &hir_program,
        Some(&probe_ctx),
        &decl_names,
        Some(&hir_types),
        &user_functions,
        &signatures,
    )
    .expect("view-ir style constant list return through local should lower");

    optimize_with_ssa_hints(
        &mut result.program.main,
        Some(&probe_ctx),
        &mut result.type_hints.main,
        &result.type_hints.main_stack_slots,
        &result.type_hints.generic_map_value_types,
    );

    compile_mir_to_ebpf_with_hints_and_globals(
        &result.program,
        Some(&probe_ctx),
        Some(&result.type_hints),
        result.readonly_globals,
        result.data_globals,
        result.bss_globals,
    )
    .expect("view-ir style constant list return through local should compile");
}
