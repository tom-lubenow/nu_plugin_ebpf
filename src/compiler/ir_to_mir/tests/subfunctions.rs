use super::*;
use crate::compiler::hir::{AnnotatedMutGlobal, HirBlock};

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
            params: vec![UserParam {
                name: Some("state".into()),
                kind: UserParamKind::Positional,
                optional: false,
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
