use super::*;
use crate::compiler::hir::{
    HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
};
use nu_protocol::RegId;

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
