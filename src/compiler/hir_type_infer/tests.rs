use super::*;
use crate::compiler::hir::{
    AnnotatedMutGlobal, HirBlock, HirBlockId, HirCallArgs, HirFunction, HirLiteral, HirProgram,
    HirStmt, HirTerminator,
};
use nu_protocol::ast::{CellPath, Comparison, Math, Operator, PathMember};
use nu_protocol::casing::Casing;
use nu_protocol::{DeclId, Record, RegId, Span, Type, Value, VarId};

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
fn test_list_push_record_item_reports_fixed_layout_hint() {
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
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::Record { capacity: 1 },
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::new();
    let errors = infer_hir(&program, &decl_names)
        .expect_err("record runtime list items should be rejected with a targeted hint");
    let rendered = errors[0].to_string();

    assert!(
        rendered.contains("runtime list literals currently support numeric scalar items only"),
        "unexpected error: {rendered}"
    );
    assert!(
        rendered.contains("leading typed `mut` global")
            && rendered.contains("global-define --type array{...}")
            && rendered.contains("layout-establishing `global-set` initializer"),
        "expected fixed-layout recovery hint, got: {rendered}"
    );
}

#[test]
fn test_list_push_binary_item_allowed_for_bytes_collect() {
    let collect_decl = DeclId::new(49);
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
        terminator: HirTerminator::Return { src: RegId::new(2) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::Binary(vec![0x11]),
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: collect_decl,
        src_dst: RegId::new(2),
        args: HirCallArgs {
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([(collect_decl, "bytes collect".to_string())]);
    infer_hir(&program, &decl_names)
        .expect("bytes collect should allow compile-time binary list builders");
}

#[test]
fn test_list_push_binary_item_allowed_for_sort() {
    let sort_decl = DeclId::new(69);
    let collect_decl = DeclId::new(70);
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
        terminator: HirTerminator::Return { src: RegId::new(3) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::Binary(vec![0x03]),
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: sort_decl,
        src_dst: RegId::new(2),
        args: HirCallArgs {
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });
    block.stmts.push(HirStmt::Call {
        decl_id: collect_decl,
        src_dst: RegId::new(3),
        args: HirCallArgs {
            pipeline_input: Some(RegId::new(2)),
            ..HirCallArgs::default()
        },
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([
        (sort_decl, "sort".to_string()),
        (collect_decl, "bytes collect".to_string()),
    ]);
    infer_hir(&program, &decl_names).expect("sort should allow compile-time binary list builders");
}

fn assert_list_push_binary_item_allowed_for_item_command(decl_id: DeclId, decl_name: &str) {
    let collect_decl = DeclId::new(decl_id.get() + 100);
    let mut func = HirFunction {
        blocks: Vec::new(),
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 5,
        file_count: 0,
    };

    let mut block = HirBlock {
        id: HirBlockId(0),
        stmts: Vec::new(),
        terminator: HirTerminator::Return { src: RegId::new(4) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::Binary(vec![0x01]),
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(2),
        lit: HirLiteral::Binary(vec![0x02]),
    });
    block.stmts.push(HirStmt::Call {
        decl_id,
        src_dst: RegId::new(3),
        args: HirCallArgs {
            positional: vec![RegId::new(2)],
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });
    block.stmts.push(HirStmt::Call {
        decl_id: collect_decl,
        src_dst: RegId::new(4),
        args: HirCallArgs {
            pipeline_input: Some(RegId::new(3)),
            ..HirCallArgs::default()
        },
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([
        (decl_id, decl_name.to_string()),
        (collect_decl, "bytes collect".to_string()),
    ]);
    infer_hir(&program, &decl_names)
        .unwrap_or_else(|_| panic!("{decl_name} should allow compile-time binary lists"));
}

fn assert_list_push_binary_item_allowed_for_list_transform(
    decl_id: DeclId,
    decl_name: &str,
    positional: Vec<HirLiteral>,
    flags: Vec<Vec<u8>>,
) {
    let collect_decl = DeclId::new(decl_id.get() + 100);
    let positional_count =
        u32::try_from(positional.len()).expect("test positional count fits in u32");
    let transform_reg = RegId::new(2 + positional_count);
    let collect_reg = RegId::new(transform_reg.get() + 1);
    let mut func = HirFunction {
        blocks: Vec::new(),
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: collect_reg.get() + 1,
        file_count: 0,
    };

    let mut block = HirBlock {
        id: HirBlockId(0),
        stmts: Vec::new(),
        terminator: HirTerminator::Return { src: collect_reg },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::Binary(vec![0x01]),
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    let mut positional_regs = Vec::new();
    for (index, lit) in positional.into_iter().enumerate() {
        let reg = RegId::new(u32::try_from(index).expect("test index fits in u32") + 2);
        block.stmts.push(HirStmt::LoadLiteral { dst: reg, lit });
        positional_regs.push(reg);
    }
    block.stmts.push(HirStmt::Call {
        decl_id,
        src_dst: transform_reg,
        args: HirCallArgs {
            positional: positional_regs,
            flags,
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });
    block.stmts.push(HirStmt::Call {
        decl_id: collect_decl,
        src_dst: collect_reg,
        args: HirCallArgs {
            pipeline_input: Some(transform_reg),
            ..HirCallArgs::default()
        },
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([
        (decl_id, decl_name.to_string()),
        (collect_decl, "bytes collect".to_string()),
    ]);
    infer_hir(&program, &decl_names)
        .unwrap_or_else(|_| panic!("{decl_name} should allow compile-time binary lists"));
}

fn assert_list_push_binary_item_allowed_for_item_access(
    decl_id: DeclId,
    decl_name: &str,
    index: Option<i64>,
) {
    let starts_with_decl = DeclId::new(decl_id.get() + 100);
    let index_reg = index.map(|_| RegId::new(2));
    let access_reg = RegId::new(2 + u32::from(index_reg.is_some()));
    let pattern_reg = RegId::new(access_reg.get() + 1);
    let starts_with_reg = RegId::new(access_reg.get() + 2);
    let mut func = HirFunction {
        blocks: Vec::new(),
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: starts_with_reg.get() + 1,
        file_count: 0,
    };

    let mut block = HirBlock {
        id: HirBlockId(0),
        stmts: Vec::new(),
        terminator: HirTerminator::Return {
            src: starts_with_reg,
        },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::Binary(vec![0x01]),
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    if let Some(raw_index) = index {
        block.stmts.push(HirStmt::LoadLiteral {
            dst: index_reg.expect("index register exists"),
            lit: HirLiteral::Int(raw_index),
        });
    }
    block.stmts.push(HirStmt::Call {
        decl_id,
        src_dst: access_reg,
        args: HirCallArgs {
            positional: index_reg.into_iter().collect(),
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: pattern_reg,
        lit: HirLiteral::Binary(vec![0x01]),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: starts_with_decl,
        src_dst: starts_with_reg,
        args: HirCallArgs {
            positional: vec![pattern_reg],
            pipeline_input: Some(access_reg),
            ..HirCallArgs::default()
        },
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([
        (decl_id, decl_name.to_string()),
        (starts_with_decl, "bytes starts-with".to_string()),
    ]);
    infer_hir(&program, &decl_names)
        .unwrap_or_else(|_| panic!("{decl_name} should allow compile-time binary lists"));
}

#[test]
fn test_list_push_binary_item_allowed_for_append() {
    assert_list_push_binary_item_allowed_for_item_command(DeclId::new(71), "append");
}

#[test]
fn test_list_push_binary_item_allowed_for_prepend() {
    assert_list_push_binary_item_allowed_for_item_command(DeclId::new(72), "prepend");
}

#[test]
fn test_list_push_binary_item_allowed_for_list_transforms() {
    let scenarios = [
        ("take", 73, Some(HirLiteral::Int(1)), Vec::new()),
        ("skip", 74, Some(HirLiteral::Int(0)), Vec::new()),
        ("drop", 75, Some(HirLiteral::Int(0)), Vec::new()),
        ("first", 76, Some(HirLiteral::Int(1)), Vec::new()),
        ("last", 77, Some(HirLiteral::Int(1)), Vec::new()),
        ("reverse", 78, None, Vec::new()),
        ("uniq", 79, None, Vec::new()),
        ("compact", 80, None, vec![b"empty".to_vec()]),
    ];

    for (decl_name, decl_id, positional, flags) in scenarios {
        assert_list_push_binary_item_allowed_for_list_transform(
            DeclId::new(decl_id),
            decl_name,
            positional.into_iter().collect(),
            flags,
        );
    }
}

#[test]
fn test_list_push_binary_item_allowed_for_find() {
    assert_list_push_binary_item_allowed_for_list_transform(
        DeclId::new(81),
        "find",
        vec![HirLiteral::Binary(vec![0x01])],
        Vec::new(),
    );
}

#[test]
fn test_list_push_binary_item_allowed_for_item_access() {
    let scenarios = [
        ("first", 82, None),
        ("last", 83, None),
        ("get", 84, Some(0)),
    ];

    for (decl_name, decl_id, index) in scenarios {
        assert_list_push_binary_item_allowed_for_item_access(
            DeclId::new(decl_id),
            decl_name,
            index,
        );
    }
}

#[test]
fn test_list_push_string_item_allowed_for_str_join() {
    let join_decl = DeclId::new(50);
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
        terminator: HirTerminator::Return { src: RegId::new(2) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::String(b"ab".to_vec()),
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: join_decl,
        src_dst: RegId::new(2),
        args: HirCallArgs {
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([(join_decl, "str join".to_string())]);
    infer_hir(&program, &decl_names).expect("str join should allow compile-time string lists");
}

fn assert_list_push_string_item_allowed_for_pipeline_command(decl_id: DeclId, decl_name: &str) {
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
        terminator: HirTerminator::Return { src: RegId::new(2) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::String(b"ab".to_vec()),
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    block.stmts.push(HirStmt::Call {
        decl_id,
        src_dst: RegId::new(2),
        args: HirCallArgs {
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([(decl_id, decl_name.to_string())]);
    infer_hir(&program, &decl_names)
        .unwrap_or_else(|_| panic!("{decl_name} should allow compile-time string lists"));
}

fn assert_list_push_string_item_allowed_for_pipeline_command_with_int_arg(
    decl_id: DeclId,
    decl_name: &str,
) {
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
        terminator: HirTerminator::Return { src: RegId::new(2) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::String(b"ab".to_vec()),
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(3),
        lit: HirLiteral::Int(1),
    });
    block.stmts.push(HirStmt::Call {
        decl_id,
        src_dst: RegId::new(2),
        args: HirCallArgs {
            positional: vec![RegId::new(3)],
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([(decl_id, decl_name.to_string())]);
    infer_hir(&program, &decl_names)
        .unwrap_or_else(|_| panic!("{decl_name} should allow compile-time string lists"));
}

fn assert_list_push_string_item_allowed_for_pipeline_command_with_string_arg(
    decl_id: DeclId,
    decl_name: &str,
) {
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
        terminator: HirTerminator::Return { src: RegId::new(2) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::String(b"ab".to_vec()),
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(3),
        lit: HirLiteral::String(b"cd".to_vec()),
    });
    block.stmts.push(HirStmt::Call {
        decl_id,
        src_dst: RegId::new(2),
        args: HirCallArgs {
            positional: vec![RegId::new(3)],
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([(decl_id, decl_name.to_string())]);
    infer_hir(&program, &decl_names)
        .unwrap_or_else(|_| panic!("{decl_name} should allow compile-time string lists"));
}

#[test]
fn test_list_push_string_item_allowed_for_length() {
    assert_list_push_string_item_allowed_for_pipeline_command(DeclId::new(51), "length");
}

#[test]
fn test_list_push_string_item_allowed_for_is_empty() {
    assert_list_push_string_item_allowed_for_pipeline_command(DeclId::new(52), "is-empty");
}

#[test]
fn test_list_push_string_item_allowed_for_is_not_empty() {
    assert_list_push_string_item_allowed_for_pipeline_command(DeclId::new(53), "is-not-empty");
}

#[test]
fn test_list_push_string_item_allowed_for_first() {
    assert_list_push_string_item_allowed_for_pipeline_command(DeclId::new(54), "first");
}

#[test]
fn test_list_push_string_item_allowed_for_last() {
    assert_list_push_string_item_allowed_for_pipeline_command(DeclId::new(55), "last");
}

#[test]
fn test_list_push_string_item_allowed_for_get() {
    let get_decl = DeclId::new(56);
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
        terminator: HirTerminator::Return { src: RegId::new(2) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::String(b"ab".to_vec()),
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(3),
        lit: HirLiteral::Int(0),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: get_decl,
        src_dst: RegId::new(2),
        args: HirCallArgs {
            positional: vec![RegId::new(3)],
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([(get_decl, "get".to_string())]);
    infer_hir(&program, &decl_names).expect("get should allow compile-time string lists");
}

#[test]
fn test_list_push_string_item_allowed_for_take() {
    assert_list_push_string_item_allowed_for_pipeline_command_with_int_arg(DeclId::new(57), "take");
}

#[test]
fn test_list_push_string_item_allowed_for_skip() {
    assert_list_push_string_item_allowed_for_pipeline_command_with_int_arg(DeclId::new(58), "skip");
}

#[test]
fn test_list_push_string_item_allowed_for_drop() {
    assert_list_push_string_item_allowed_for_pipeline_command_with_int_arg(DeclId::new(59), "drop");
}

#[test]
fn test_list_push_string_item_allowed_for_first_count() {
    assert_list_push_string_item_allowed_for_pipeline_command_with_int_arg(
        DeclId::new(60),
        "first",
    );
}

#[test]
fn test_list_push_string_item_allowed_for_last_count() {
    assert_list_push_string_item_allowed_for_pipeline_command_with_int_arg(DeclId::new(61), "last");
}

#[test]
fn test_list_push_string_item_allowed_for_reverse() {
    assert_list_push_string_item_allowed_for_pipeline_command(DeclId::new(62), "reverse");
}

#[test]
fn test_list_push_string_item_allowed_for_append() {
    assert_list_push_string_item_allowed_for_pipeline_command_with_string_arg(
        DeclId::new(63),
        "append",
    );
}

#[test]
fn test_list_push_string_item_allowed_for_prepend() {
    assert_list_push_string_item_allowed_for_pipeline_command_with_string_arg(
        DeclId::new(64),
        "prepend",
    );
}

#[test]
fn test_list_push_string_item_allowed_for_uniq() {
    assert_list_push_string_item_allowed_for_pipeline_command(DeclId::new(65), "uniq");
}

#[test]
fn test_list_push_string_item_allowed_for_sort() {
    assert_list_push_string_item_allowed_for_pipeline_command(DeclId::new(68), "sort");
}

#[test]
fn test_list_push_string_item_allowed_for_find() {
    assert_list_push_string_item_allowed_for_pipeline_command_with_string_arg(
        DeclId::new(66),
        "find",
    );
}

#[test]
fn test_list_push_string_item_allowed_for_compact() {
    assert_list_push_string_item_allowed_for_pipeline_command(DeclId::new(67), "compact");
}

#[test]
fn test_list_push_record_item_allowed_for_typed_global_array_initializer() {
    let define_decl = DeclId::new(42);
    let mut func = HirFunction {
        blocks: Vec::new(),
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 5,
        file_count: 0,
    };

    let mut block = HirBlock {
        id: HirBlockId(0),
        stmts: Vec::new(),
        terminator: HirTerminator::Return { src: RegId::new(4) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::Record { capacity: 1 },
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(2),
        lit: HirLiteral::String("entries".into()),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(3),
        lit: HirLiteral::String("array{record{pid:int}:1}".into()),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: define_decl,
        src_dst: RegId::new(4),
        args: HirCallArgs {
            positional: vec![RegId::new(2)],
            named: vec![(b"type".to_vec(), RegId::new(3))],
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });
    block.stmts.push(HirStmt::Drain { src: RegId::new(0) });
    block.stmts.push(HirStmt::Drop { src: RegId::new(0) });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::Int(0),
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([(define_decl, "global-define".to_string())]);
    infer_hir(&program, &decl_names)
        .expect("record list items should be allowed for compile-time typed global arrays");
}

#[test]
fn test_list_push_record_item_allowed_for_global_set_initializer() {
    let set_decl = DeclId::new(43);
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
        terminator: HirTerminator::Return { src: RegId::new(3) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::Record { capacity: 1 },
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(2),
        lit: HirLiteral::String("entries".into()),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: set_decl,
        src_dst: RegId::new(3),
        args: HirCallArgs {
            positional: vec![RegId::new(2)],
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });
    block.stmts.push(HirStmt::Drain { src: RegId::new(0) });
    block.stmts.push(HirStmt::Drop { src: RegId::new(0) });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::Int(0),
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([(set_decl, "global-set".to_string())]);
    infer_hir(&program, &decl_names)
        .expect("record list items should be allowed for compile-time global-set arrays");
}

#[test]
fn test_list_push_record_item_allowed_through_bound_list_spread_global_set_initializer() {
    let set_decl = DeclId::new(44);
    let tail_var = VarId::new(7);
    let mut func = HirFunction {
        blocks: Vec::new(),
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 7,
        file_count: 0,
    };

    let mut block = HirBlock {
        id: HirBlockId(0),
        stmts: Vec::new(),
        terminator: HirTerminator::Return { src: RegId::new(6) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::Record { capacity: 1 },
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    block.stmts.push(HirStmt::StoreVariable {
        var_id: tail_var,
        src: RegId::new(0),
    });
    block.stmts.push(HirStmt::Drain { src: RegId::new(0) });
    block.stmts.push(HirStmt::Drop { src: RegId::new(0) });
    block.stmts.push(HirStmt::LoadVariable {
        dst: RegId::new(2),
        var_id: tail_var,
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(3),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(4),
        lit: HirLiteral::Record { capacity: 1 },
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(3),
        item: RegId::new(4),
    });
    block.stmts.push(HirStmt::ListSpread {
        src_dst: RegId::new(2),
        items: RegId::new(3),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(5),
        lit: HirLiteral::String("entries".into()),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: set_decl,
        src_dst: RegId::new(6),
        args: HirCallArgs {
            positional: vec![RegId::new(5)],
            pipeline_input: Some(RegId::new(2)),
            ..HirCallArgs::default()
        },
    });
    block.stmts.push(HirStmt::Drain { src: RegId::new(2) });
    block.stmts.push(HirStmt::Drop { src: RegId::new(2) });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(2),
        lit: HirLiteral::Int(0),
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([(set_decl, "global-set".to_string())]);
    infer_hir(&program, &decl_names).expect(
        "record list items should be allowed through bound list-spread global-set initializers",
    );
}

#[test]
fn test_list_push_record_item_allowed_for_map_put_value_initializer() {
    let map_put_decl = DeclId::new(45);
    let mut func = HirFunction {
        blocks: Vec::new(),
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 5,
        file_count: 0,
    };

    let mut block = HirBlock {
        id: HirBlockId(0),
        stmts: Vec::new(),
        terminator: HirTerminator::Return { src: RegId::new(0) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::Record { capacity: 1 },
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(2),
        lit: HirLiteral::String("entries_by_pid".into()),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(3),
        lit: HirLiteral::Int(7),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_put_decl,
        src_dst: RegId::new(4),
        args: HirCallArgs {
            positional: vec![RegId::new(2), RegId::new(3)],
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });
    block.stmts.push(HirStmt::Drain { src: RegId::new(0) });
    block.stmts.push(HirStmt::Drop { src: RegId::new(0) });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::Int(0),
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([(map_put_decl, "map-put".to_string())]);
    infer_hir(&program, &decl_names)
        .expect("record list items should be allowed for fixed-layout map-put values");
}

#[test]
fn test_list_push_record_item_allowed_for_map_put_key_initializer() {
    let map_put_decl = DeclId::new(47);
    let mut func = HirFunction {
        blocks: Vec::new(),
        entry: HirBlockId(0),
        spans: Vec::new(),
        ast: Vec::new(),
        comments: Vec::new(),
        register_count: 5,
        file_count: 0,
    };

    let mut block = HirBlock {
        id: HirBlockId(0),
        stmts: Vec::new(),
        terminator: HirTerminator::Return { src: RegId::new(3) },
    };

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::Record { capacity: 1 },
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(2),
        lit: HirLiteral::String("entry_batches".into()),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(3),
        lit: HirLiteral::Int(42),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_put_decl,
        src_dst: RegId::new(3),
        args: HirCallArgs {
            positional: vec![RegId::new(2), RegId::new(0)],
            pipeline_input: Some(RegId::new(3)),
            ..HirCallArgs::default()
        },
    });
    block.stmts.push(HirStmt::Drain { src: RegId::new(0) });
    block.stmts.push(HirStmt::Drop { src: RegId::new(0) });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([(map_put_decl, "map-put".to_string())]);
    infer_hir(&program, &decl_names)
        .expect("record list items should be allowed for fixed-layout map-put keys");
}

#[test]
fn test_list_push_record_item_allowed_for_piped_map_get_key_initializer() {
    let map_get_decl = DeclId::new(48);
    let entry_var = VarId::new(77);
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

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::Record { capacity: 1 },
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(2),
        lit: HirLiteral::String("entry_batches".into()),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(3),
        lit: HirLiteral::String("hash".into()),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_get_decl,
        src_dst: RegId::new(0),
        args: HirCallArgs {
            positional: vec![RegId::new(2)],
            named: vec![(b"kind".to_vec(), RegId::new(3))],
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });
    block.stmts.push(HirStmt::StoreVariable {
        var_id: entry_var,
        src: RegId::new(0),
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([(map_get_decl, "map-get".to_string())]);
    infer_hir(&program, &decl_names)
        .expect("record list items should be allowed for piped fixed-layout map-get keys");
}

#[test]
fn test_list_push_record_item_allowed_for_map_push_value_initializer() {
    let map_push_decl = DeclId::new(46);
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

    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::List { capacity: 1 },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(1),
        lit: HirLiteral::Record { capacity: 1 },
    });
    block.stmts.push(HirStmt::ListPush {
        src_dst: RegId::new(0),
        item: RegId::new(1),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(2),
        lit: HirLiteral::String("entry_batches".into()),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_push_decl,
        src_dst: RegId::new(3),
        args: HirCallArgs {
            positional: vec![RegId::new(2)],
            pipeline_input: Some(RegId::new(0)),
            ..HirCallArgs::default()
        },
    });
    block.stmts.push(HirStmt::Drain { src: RegId::new(0) });
    block.stmts.push(HirStmt::Drop { src: RegId::new(0) });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(0),
        lit: HirLiteral::Int(0),
    });

    func.blocks.push(block);

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::from([(map_push_decl, "map-push".to_string())]);
    infer_hir(&program, &decl_names)
        .expect("record list items should be allowed for fixed-layout map-push values");
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
fn test_ctx_param_is_seeded_as_pointer_for_helper_call() {
    let ctx_var = VarId::new(80);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("bpf_msg_cork_bytes".into()),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(2),
                    var_id: ctx_var,
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(8),
                },
                HirStmt::Call {
                    decl_id: DeclId::new(42),
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1), RegId::new(2), RegId::new(3)],
                        ..Default::default()
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

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), Some(ctx_var));
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "helper-call".to_string());

    infer_hir(&program, &decl_names).expect("ctx param should type-check as a helper pointer arg");
}

#[test]
fn test_random_int_infers_integer() {
    let decl_id = DeclId::new(42);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::Call {
                decl_id,
                src_dst: RegId::new(0),
                args: HirCallArgs::default(),
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
    let mut decl_names = HashMap::new();
    decl_names.insert(decl_id, "random int".to_string());

    let inferred = infer_hir_types(&program, &decl_names).expect("random int should infer");
    assert_eq!(inferred.main.get(&RegId::new(0)), Some(&HMType::I64));
}

#[test]
fn test_record_spread_requires_record_source() {
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
                    lit: HirLiteral::Int(7),
                },
                HirStmt::RecordSpread {
                    src_dst: RegId::new(0),
                    items: RegId::new(1),
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
fn test_string_binary_add_allows_stack_string_operands() {
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
                    op: Operator::Math(Math::Add),
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

    let program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    let decl_names = HashMap::new();
    let inferred = infer_hir_types(&program, &decl_names)
        .expect("string + string should infer as stack string concat");

    assert_eq!(
        inferred.main.get(&RegId::new(0)),
        Some(&stack_string_ptr_type())
    );
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
fn test_captured_binary_infers_readonly_map_ptr() {
    let capture_var = VarId::new(8);
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
        vec![(capture_var, Value::binary(vec![1, 2, 3], Span::test_data()))],
        None,
    );
    let decl_names = HashMap::new();
    let inferred = infer_hir_types(&program, &decl_names).expect("captured binary should infer");

    assert_eq!(
        inferred.main.get(&RegId::new(0)),
        Some(&readonly_binary_ptr_type())
    );
}

#[test]
fn test_load_literal_binary_infers_readonly_map_ptr() {
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![HirStmt::LoadLiteral {
                dst: RegId::new(0),
                lit: HirLiteral::Binary(vec![1, 2, 3]),
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
    let inferred = infer_hir_types(&program, &decl_names).expect("binary literal should infer");

    assert_eq!(
        inferred.main.get(&RegId::new(0)),
        Some(&readonly_binary_ptr_type())
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

#[test]
fn test_annotated_record_global_field_math_infers_from_declared_type() {
    let state_var = VarId::new(21);

    let mut init = Record::new();
    init.push("ok", Value::bool(false, Span::test_data()));
    init.push("pid", Value::int(7, Span::test_data()));
    let mut declared_init = Record::new();
    declared_init.push("ok", Value::bool(false, Span::test_data()));
    declared_init.push("pid", Value::int(7, Span::test_data()));

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadValue {
                    dst: RegId::new(0),
                    val: Box::new(Value::record(init, Span::test_data())),
                },
                HirStmt::StoreVariable {
                    var_id: state_var,
                    src: RegId::new(0),
                },
                HirStmt::LoadVariable {
                    dst: RegId::new(1),
                    var_id: state_var,
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
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(1),
                    path: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(1),
                },
                HirStmt::BinaryOp {
                    lhs_dst: RegId::new(1),
                    op: Operator::Math(Math::Add),
                    rhs: RegId::new(3),
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

    let mut program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    program.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: state_var,
        declared_type: Type::Record(Box::new([
            ("pid".to_string(), Type::Int),
            ("ok".to_string(), Type::Bool),
        ])),
        initial_value: Value::record(declared_init, Span::test_data()),
    }];

    let decl_names = HashMap::new();
    let inferred =
        infer_hir_types(&program, &decl_names).expect("annotated record field math should infer");

    assert_eq!(inferred.main.get(&RegId::new(1)), Some(&HMType::I64));
}

#[test]
fn test_infer_annotated_duration_math_uses_i64_type() {
    let state_var = VarId::new(43);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadVariable {
                    dst: RegId::new(0),
                    var_id: state_var,
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

    let mut program = HirProgram::new(func, HashMap::new(), Vec::new(), None);
    program.annotated_mut_globals = vec![AnnotatedMutGlobal {
        var_id: state_var,
        declared_type: Type::Duration,
        initial_value: Value::duration(1234, Span::test_data()),
    }];

    let decl_names = HashMap::new();
    let inferred =
        infer_hir_types(&program, &decl_names).expect("annotated duration math should infer");

    assert_eq!(inferred.main.get(&RegId::new(0)), Some(&HMType::I64));
}
