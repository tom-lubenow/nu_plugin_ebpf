use super::*;
use crate::compiler::hir::{
    HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
};
use nu_protocol::ast::{Comparison, Operator};
use nu_protocol::{Record, RegId, VarId};
use nu_protocol::{Span, Value};

#[test]
fn test_let_generalization_allows_distinct_instantiations() {
    let mut func = HirFunction {
        blocks: Vec::new(),
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 4,
        file_count: 0,
    };

    let mut block = HirBlock {
        id: HirBlockId(0),
        stmts: Vec::new(),
        terminator: HirTerminator::Return { src: RegId::new(0) },
    };

    // Store unconstrained register into a variable => generalized.
    block.stmts.push(HirStmt::StoreVariable {
        var_id: VarId::new(0),
        src: RegId::new(0),
    });

    // First instantiation: constrain to bool via Not.
    block.stmts.push(HirStmt::LoadVariable {
        dst: RegId::new(1),
        var_id: VarId::new(0),
    });
    block.stmts.push(HirStmt::Not {
        src_dst: RegId::new(1),
    });

    // Second instantiation: constrain to a pointer via move from a string literal.
    block.stmts.push(HirStmt::LoadVariable {
        dst: RegId::new(2),
        var_id: VarId::new(0),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(3),
        lit: HirLiteral::String("hi".into()),
    });
    block.stmts.push(HirStmt::Move {
        dst: RegId::new(2),
        src: RegId::new(3),
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::new();
    infer_hir(&program, &decl_names).expect("expected polymorphic let to type-check");
}

#[test]
fn test_conflicting_constraints_without_let() {
    let mut func = HirFunction {
        blocks: Vec::new(),
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 2,
        file_count: 0,
    };

    let mut block = HirBlock {
        id: HirBlockId(0),
        stmts: Vec::new(),
        terminator: HirTerminator::Return { src: RegId::new(0) },
    };

    // Constrain RegId(0) to a pointer and then to bool without let-generalization.
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::String("oops".into()),
    });
    block.stmts.push(HirStmt::Not {
        src_dst: RegId::new(0),
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::new();
    assert!(infer_hir(&program, &decl_names).is_err());
}

#[test]
fn test_list_push_requires_list_ptr() {
    let mut func = HirFunction {
        blocks: Vec::new(),
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 2,
        file_count: 0,
    };

    let mut block = HirBlock {
        id: HirBlockId(0),
        stmts: Vec::new(),
        terminator: HirTerminator::Return { src: RegId::new(0) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::Int(0),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::Int(1),
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::new();
    assert!(infer_hir(&program, &decl_names).is_err());
}

#[test]
fn test_record_insert_requires_string_key() {
    let mut func = HirFunction {
        blocks: Vec::new(),
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 3,
        file_count: 0,
    };

    let mut block = HirBlock {
        id: HirBlockId(0),
        stmts: Vec::new(),
        terminator: HirTerminator::Return { src: RegId::new(0) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::Record { capacity: 0 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::Int(0),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(2),
        lit: HirLiteral::Int(1),
    });
    block.stmts.push(HirStmt::RecordInsert {
        src_dst: RegId::new(0),
        key: RegId::new(1),
        val: RegId::new(2),
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::new();
    assert!(infer_hir(&program, &decl_names).is_err());
}

#[test]
fn test_pointer_null_comparison_is_permissive() {
    let mut func = HirFunction {
        blocks: Vec::new(),
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 2,
        file_count: 0,
    };

    let mut block = HirBlock {
        id: HirBlockId(0),
        stmts: Vec::new(),
        terminator: HirTerminator::Return { src: RegId::new(0) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::String("ptr".into()),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::Int(0),
    });
    block.stmts.push(HirStmt::BinaryOp {
        lhs_dst: RegId::new(0),
        op: Operator::Comparison(Comparison::NotEqual),
        rhs: RegId::new(1),
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::new();
    infer_hir(&program, &decl_names).expect("pointer null checks should remain permissive");
}

#[test]
fn test_string_append_requires_string_dst() {
    let mut func = HirFunction {
        blocks: Vec::new(),
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 2,
        file_count: 0,
    };

    let mut block = HirBlock {
        id: HirBlockId(0),
        stmts: Vec::new(),
        terminator: HirTerminator::Return { src: RegId::new(0) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::Int(0),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::String("hi".into()),
    });
    block.stmts.push(HirStmt::StringAppend {
        src_dst: RegId::new(0),
        val: RegId::new(1),
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::new();
    assert!(infer_hir(&program, &decl_names).is_err());
}

#[test]
fn test_capture_seeded_into_hm_environment() {
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

    let program = HirProgram::new(
        func,
        HashMap::new(),
        vec![(capture_var, Value::string("hi", Span::test_data()))],
        None,
    );
    let decl_names = HashMap::new();
    let inferred = infer_hir_types(&program, &decl_names).expect("captured string should infer");

    assert_eq!(
        inferred.main.get(&RegId::new(0)),
        Some(&stack_string_ptr_type())
    );
}

#[test]
fn test_load_value_string_infers_stack_string_ptr() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadValue {
                dst: RegId::new(0),
                val: Box::new(Value::string("pinned_map", Span::test_data())),
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

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::new();
    let inferred = infer_hir_types(&program, &decl_names).expect("string load value should infer");

    assert_eq!(
        inferred.main.get(&RegId::new(0)),
        Some(&stack_string_ptr_type())
    );
}

#[test]
fn test_load_value_record_infers_stack_record_ptr() {
    let mut rec = Record::new();
    rec.push("pid", Value::int(42, Span::test_data()));

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

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::new();
    let inferred = infer_hir_types(&program, &decl_names).expect("record load value should infer");

    assert_eq!(
        inferred.main.get(&RegId::new(0)),
        Some(&stack_record_ptr_type())
    );
}

#[test]
fn test_load_value_numeric_list_infers_stack_list_ptr() {
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

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::new();
    let inferred =
        infer_hir_types(&program, &decl_names).expect("numeric list load value should infer");

    assert_eq!(
        inferred.main.get(&RegId::new(0)),
        Some(&stack_list_ptr_type())
    );
}

#[test]
fn test_capture_record_seeded_into_hm_environment() {
    let capture_var = VarId::new(12);
    let mut rec = Record::new();
    rec.push("pid", Value::int(42, Span::test_data()));

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

    let program = HirProgram::new(
        func,
        HashMap::new(),
        vec![(capture_var, Value::record(rec, Span::test_data()))],
        None,
    );
    let decl_names = HashMap::new();
    let inferred = infer_hir_types(&program, &decl_names).expect("captured record should infer");

    assert_eq!(
        inferred.main.get(&RegId::new(0)),
        Some(&stack_record_ptr_type())
    );
}

#[test]
fn test_capture_numeric_list_seeded_into_hm_environment() {
    let capture_var = VarId::new(14);

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

    let program = HirProgram::new(
        func,
        HashMap::new(),
        vec![(
            capture_var,
            Value::list(
                vec![
                    Value::int(1, Span::test_data()),
                    Value::filesize(2, Span::test_data()),
                ],
                Span::test_data(),
            ),
        )],
        None,
    );
    let decl_names = HashMap::new();
    let inferred =
        infer_hir_types(&program, &decl_names).expect("captured numeric list should infer");

    assert_eq!(
        inferred.main.get(&RegId::new(0)),
        Some(&stack_list_ptr_type())
    );
}
