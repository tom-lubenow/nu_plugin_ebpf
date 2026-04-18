use super::helpers::*;
use super::*;
use crate::compiler::BpfHelper;
use crate::compiler::EbpfProgramType;
use crate::compiler::hir::{
    HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
};
use crate::compiler::mir::{AddressSpace, BYTES_COUNTER_MAP_NAME, StructField};
use nu_protocol::ast::{CellPath, Comparison, Operator};
use nu_protocol::{DeclId, Record, RegId, Span, Value, VarId};
use std::collections::HashMap;

fn path_struct_schema(map_name: &str, kind: MapKind) -> HashMap<MapRef, MirType> {
    HashMap::from([(
        MapRef {
            name: map_name.to_string(),
            kind,
        },
        MirType::Struct {
            name: Some("path".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "mnt".to_string(),
                    ty: MirType::U64,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "dentry".to_string(),
                    ty: MirType::Ptr {
                        pointee: Box::new(MirType::Struct {
                            name: Some("dentry".to_string()),
                            kernel_btf_type_id: None,
                            fields: vec![StructField {
                                name: "d_flags".to_string(),
                                ty: MirType::U32,
                                offset: 0,
                                synthetic: false,
                                bitfield: None,
                            }],
                        }),
                        address_space: AddressSpace::Kernel,
                    },
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        },
    )])
}

#[test]
fn test_lower_map_get_preserves_prior_typed_struct_schema() {
    let hir =
        make_map_put_get_projection_program(DeclId::new(42), DeclId::new(43), DeclId::new(44));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-put".to_string());
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "count".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("typed map put/get projection should lower");

    assert!(result.type_hints.main.values().any(|ty| matches!(
        ty,
        MirType::Ptr {
            pointee,
            address_space: AddressSpace::Map,
        } if matches!(
            pointee.as_ref(),
            MirType::Struct { name, fields, .. }
                if name.as_deref() == Some("path")
                    && fields.len() == 2
                    && fields[0].name == "mnt"
                    && fields[0].offset == 0
                    && fields[1].name == "dentry"
                    && fields[1].offset == 8
        )
    )));

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| matches!(block.terminator, MirInst::Branch { .. })),
        "expected null-check branch around typed map-get result"
    );
}

#[test]
fn test_lower_map_put_get_record_string_field_preserves_semantics() {
    let capture_var = VarId::new(320);
    let lookup_var = VarId::new(321);
    let map_put_decl = DeclId::new(209);
    let map_get_decl = DeclId::new(210);
    let decl_names = HashMap::from([
        (map_put_decl, "map-put".to_string()),
        (map_get_decl, "map-get".to_string()),
    ]);

    let mut record = Record::new();
    record.push("msg", Value::string("hi", Span::test_data()));
    record.push("pid", Value::int(0, Span::test_data()));

    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: capture_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::String("typed_state".into()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::String("hash".into()),
                    },
                    HirStmt::Call {
                        decl_id: map_put_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(1), RegId::new(2)],
                            named: vec![(b"kind".to_vec(), RegId::new(3))],
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(1), RegId::new(2)],
                            named: vec![(b"kind".to_vec(), RegId::new(3))],
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(4),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: lookup_var,
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
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                }],
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
    .expect("map-put/map-get record string field should preserve semantics");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected map-get on record string field to materialize a stack string slot"
    );
}

#[test]
fn test_lower_map_put_get_metadata_only_record_builder_preserves_string_semantics() {
    let lookup_var = VarId::new(324);
    let map_put_decl = DeclId::new(214);
    let map_get_decl = DeclId::new(215);
    let decl_names = HashMap::from([
        (map_put_decl, "map-put".to_string()),
        (map_get_decl, "map-get".to_string()),
    ]);

    let func = HirFunction {
        blocks: vec![
            HirBlock {
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
                        lit: HirLiteral::String("typed_state".into()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(6),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(7),
                        lit: HirLiteral::String("hash".into()),
                    },
                    HirStmt::Call {
                        decl_id: map_put_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(5), RegId::new(6)],
                            named: vec![(b"kind".to_vec(), RegId::new(7))],
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(5), RegId::new(6)],
                            named: vec![(b"kind".to_vec(), RegId::new(7))],
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(8),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(8),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: lookup_var,
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
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                }],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
        ],
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
    .expect("map-put/map-get metadata-only record builder should preserve semantics");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected map-get on metadata-only record builder field to materialize a stack string slot"
    );
}

#[test]
fn test_lower_map_put_get_record_list_field_preserves_semantics() {
    let capture_var = VarId::new(322);
    let lookup_var = VarId::new(323);
    let map_put_decl = DeclId::new(211);
    let map_get_decl = DeclId::new(212);
    let get_decl = DeclId::new(213);
    let decl_names = HashMap::from([
        (map_put_decl, "map-put".to_string()),
        (map_get_decl, "map-get".to_string()),
        (get_decl, "get".to_string()),
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
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: capture_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::String("typed_state".into()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(3),
                        lit: HirLiteral::String("hash".into()),
                    },
                    HirStmt::Call {
                        decl_id: map_put_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(1), RegId::new(2)],
                            named: vec![(b"kind".to_vec(), RegId::new(3))],
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(1), RegId::new(2)],
                            named: vec![(b"kind".to_vec(), RegId::new(3))],
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(0),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(4),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(0),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: lookup_var,
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::CellPath(Box::new(CellPath {
                            members: vec![string_member("vals")],
                        })),
                    },
                    HirStmt::FollowCellPath {
                        src_dst: RegId::new(0),
                        path: RegId::new(1),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::Int(1),
                    },
                    HirStmt::Call {
                        decl_id: get_decl,
                        src_dst: RegId::new(0),
                        args: HirCallArgs {
                            positional: vec![RegId::new(2)],
                            ..HirCallArgs::default()
                        },
                    },
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                }],
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
    .expect("map-put/map-get record list field should preserve semantics");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::ListGet { .. })),
        "expected map-get on record list field to lower through ListGet"
    );
}

#[test]
fn test_lower_map_get_uses_external_typed_struct_schema() {
    let hir = make_map_get_projection_program(DeclId::new(43), DeclId::new(44));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "count".to_string());

    let external_schema = HashMap::from([(
        MapRef {
            name: "cached_path".to_string(),
            kind: MapKind::Hash,
        },
        MirType::Struct {
            name: Some("path".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "mnt".to_string(),
                    ty: MirType::U64,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "dentry".to_string(),
                    ty: MirType::Ptr {
                        pointee: Box::new(MirType::Struct {
                            name: Some("dentry".to_string()),
                            kernel_btf_type_id: None,
                            fields: vec![StructField {
                                name: "d_flags".to_string(),
                                ty: MirType::U32,
                                offset: 0,
                                synthetic: false,
                                bitfield: None,
                            }],
                        }),
                        address_space: AddressSpace::Kernel,
                    },
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        },
    )]);

    let result = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("external typed map schema should lower");

    assert_eq!(result.generic_map_value_types, external_schema);
    assert!(result.type_hints.main.values().any(|ty| matches!(
        ty,
        MirType::Ptr {
            pointee,
            address_space: AddressSpace::Map,
        } if matches!(
            pointee.as_ref(),
            MirType::Struct { name, fields, .. }
                if name.as_deref() == Some("path")
                    && fields.len() == 2
                    && fields[0].name == "mnt"
                    && fields[1].name == "dentry"
        )
    )));
}

#[test]
fn test_lower_map_get_uses_external_record_string_semantics() {
    let lookup_var = VarId::new(330);
    let map_get_decl = DeclId::new(214);
    let decl_names = HashMap::from([(map_get_decl, "map-get".to_string())]);

    let func = HirFunction {
        blocks: vec![
            HirBlock {
                id: HirBlockId(0),
                stmts: vec![
                    HirStmt::LoadLiteral {
                        dst: RegId::new(0),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(1),
                        lit: HirLiteral::String("typed_state".into()),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(2),
                        lit: HirLiteral::String("hash".into()),
                    },
                    HirStmt::Call {
                        decl_id: map_get_decl,
                        src_dst: RegId::new(3),
                        args: HirCallArgs {
                            positional: vec![RegId::new(1), RegId::new(0)],
                            named: vec![(b"kind".to_vec(), RegId::new(2))],
                            ..HirCallArgs::default()
                        },
                    },
                    HirStmt::StoreVariable {
                        var_id: lookup_var,
                        src: RegId::new(3),
                    },
                    HirStmt::LoadLiteral {
                        dst: RegId::new(4),
                        lit: HirLiteral::Int(0),
                    },
                    HirStmt::BinaryOp {
                        lhs_dst: RegId::new(3),
                        op: Operator::Comparison(Comparison::NotEqual),
                        rhs: RegId::new(4),
                    },
                ],
                terminator: HirTerminator::BranchIf {
                    cond: RegId::new(3),
                    if_true: HirBlockId(1),
                    if_false: HirBlockId(2),
                },
            },
            HirBlock {
                id: HirBlockId(1),
                stmts: vec![
                    HirStmt::LoadVariable {
                        dst: RegId::new(0),
                        var_id: lookup_var,
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
                ],
                terminator: HirTerminator::Return { src: RegId::new(0) },
            },
            HirBlock {
                id: HirBlockId(2),
                stmts: vec![HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(0),
                }],
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
    let hir = HirProgram::new(func, HashMap::new(), vec![], None);

    let external_schema = HashMap::from([(
        MapRef {
            name: "typed_state".to_string(),
            kind: MapKind::Hash,
        },
        MirType::Struct {
            name: Some("state".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "msg".to_string(),
                    ty: MirType::Array {
                        elem: Box::new(MirType::U8),
                        len: 24,
                    },
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "pid".to_string(),
                    ty: MirType::I64,
                    offset: 24,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        },
    )]);
    let external_semantics = HashMap::from([(
        MapRef {
            name: "typed_state".to_string(),
            kind: MapKind::Hash,
        },
        AnnotatedValueSemantics::Record(vec![(
            "msg".to_string(),
            AnnotatedValueSemantics::String {
                slot_len: 16,
                content_cap: 15,
            },
        )]),
    )]);

    let result = lower_hir_to_mir_with_hints_maps_and_semantics(
        &hir,
        None,
        &decl_names,
        None,
        Some(&external_schema),
        Some(&external_semantics),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("external map schema and semantics should preserve string field behavior");

    assert_eq!(result.generic_map_value_types, external_schema);
    assert_eq!(result.generic_map_value_semantics, external_semantics);
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::StringAppend { .. })),
        "expected externally seeded map schema to materialize a stack string slot"
    );
}

#[test]
fn test_lower_map_put_rejects_conflicting_external_schema() {
    let hir = make_map_put_program(DeclId::new(42), 0, "hash");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-put".to_string());

    let external_schema = HashMap::from([(
        MapRef {
            name: "cached_path".to_string(),
            kind: MapKind::Hash,
        },
        MirType::I64,
    )]);

    let err = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("conflicting pinned schema should fail");

    assert!(err.to_string().contains("conflicts with pinned map schema"));
}

#[test]
fn test_lower_map_get_whole_struct_count_uses_bytes_counters() {
    let hir = make_map_get_whole_value_program(DeclId::new(43), DeclId::new(44));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "count".to_string());

    let external_schema = HashMap::from([(
        MapRef {
            name: "cached_path".to_string(),
            kind: MapKind::Hash,
        },
        MirType::Struct {
            name: Some("path".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "mnt".to_string(),
                    ty: MirType::U64,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "dentry".to_string(),
                    ty: MirType::Ptr {
                        pointee: Box::new(MirType::Struct {
                            name: Some("dentry".to_string()),
                            kernel_btf_type_id: None,
                            fields: vec![StructField {
                                name: "d_flags".to_string(),
                                ty: MirType::U32,
                                offset: 0,
                                synthetic: false,
                                bitfield: None,
                            }],
                        }),
                        address_space: AddressSpace::Kernel,
                    },
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        },
    )]);

    let result = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("whole-value typed map-get count should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::MapUpdate { map, .. } if map.name == BYTES_COUNTER_MAP_NAME
            ))
    );
}

#[test]
fn test_lower_map_get_whole_struct_emit_uses_full_struct_size() {
    let hir = make_map_get_whole_value_program(DeclId::new(43), DeclId::new(44));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "emit".to_string());

    let external_schema = HashMap::from([(
        MapRef {
            name: "cached_path".to_string(),
            kind: MapKind::Hash,
        },
        MirType::Struct {
            name: Some("path".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "mnt".to_string(),
                    ty: MirType::U64,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "dentry".to_string(),
                    ty: MirType::Ptr {
                        pointee: Box::new(MirType::Struct {
                            name: Some("dentry".to_string()),
                            kernel_btf_type_id: None,
                            fields: vec![StructField {
                                name: "d_flags".to_string(),
                                ty: MirType::U32,
                                offset: 0,
                                synthetic: false,
                                bitfield: None,
                            }],
                        }),
                        address_space: AddressSpace::Kernel,
                    },
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        },
    )]);

    let result = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("whole-value typed map-get emit should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::EmitEvent { size, .. } if *size == 16))
    );
}

#[test]
fn test_lower_map_peek_whole_struct_emit_uses_full_struct_size() {
    let hir = make_map_take_whole_value_program(DeclId::new(43), DeclId::new(44), "queue");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([
        (DeclId::new(43), "map-peek".to_string()),
        (DeclId::new(44), "emit".to_string()),
    ]);
    let external_schema = path_struct_schema("recent_paths", MapKind::Queue);

    let result = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("whole-value queue map-peek emit should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::EmitEvent { size, .. } if *size == 16))
    );
}

#[test]
fn test_lower_map_pop_whole_struct_count_uses_bytes_counters() {
    let hir = make_map_take_whole_value_program(DeclId::new(43), DeclId::new(44), "stack");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([
        (DeclId::new(43), "map-pop".to_string()),
        (DeclId::new(44), "count".to_string()),
    ]);
    let external_schema = path_struct_schema("recent_paths", MapKind::Stack);

    let result = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("whole-value stack map-pop count should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::MapUpdate { map, .. } if map.name == BYTES_COUNTER_MAP_NAME
            ))
    );
}

#[test]
fn test_lower_map_get_record_emit_preserves_nested_struct_field_type() {
    let hir = make_map_get_record_emit_program(DeclId::new(43), DeclId::new(44));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "emit".to_string());

    let external_schema = HashMap::from([(
        MapRef {
            name: "cached_path".to_string(),
            kind: MapKind::Hash,
        },
        MirType::Struct {
            name: Some("path".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "mnt".to_string(),
                    ty: MirType::U64,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "dentry".to_string(),
                    ty: MirType::Ptr {
                        pointee: Box::new(MirType::Struct {
                            name: Some("dentry".to_string()),
                            kernel_btf_type_id: None,
                            fields: vec![StructField {
                                name: "d_flags".to_string(),
                                ty: MirType::U32,
                                offset: 0,
                                synthetic: false,
                                bitfield: None,
                            }],
                        }),
                        address_space: AddressSpace::Kernel,
                    },
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        },
    )]);

    let result = lower_hir_to_mir_with_hints_and_maps(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        Some(&external_schema),
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("record emit around typed map-get should lower");

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
                    if fields.len() == 1
                        && fields[0].name == "path"
                        && matches!(
                            fields[0].ty,
                            MirType::Struct { ref name, ref fields, .. }
                                if name.as_deref() == Some("path")
                                    && fields.len() == 2
                                    && fields[0].name == "mnt"
                                    && fields[1].name == "dentry"
                        )
            ))
    );
}

#[test]
fn test_lower_map_put_respects_kind_and_flags() {
    let hir = make_map_put_program(DeclId::new(42), 1, "per-cpu-hash");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-put".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-put should lower");

    let update = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapUpdate {
                map, key, flags, ..
            } if map.name == "cached_path" => Some((map.kind, *key, *flags)),
            _ => None,
        })
        .expect("expected generic map update");
    assert_eq!(update.0, MapKind::PerCpuHash);
    assert_eq!(update.2, 1);
}

#[test]
fn test_lower_map_put_respects_lru_hash_kind() {
    let hir = make_map_put_program(DeclId::new(42), 1, "lru-hash");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-put".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("lru map-put should lower");

    let update = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapUpdate {
                map, key, flags, ..
            } if map.name == "cached_path" => Some((map.kind, *key, *flags)),
            _ => None,
        })
        .expect("expected generic map update");
    assert_eq!(update.0, MapKind::LruHash);
    assert_eq!(update.2, 1);
}

#[test]
fn test_lower_map_put_respects_lpm_trie_kind() {
    let hir = make_map_put_program(DeclId::new(42), 1, "lpm-trie");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-put".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("lpm trie map-put should lower");

    let update = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapUpdate {
                map, key, flags, ..
            } if map.name == "cached_path" => Some((map.kind, *key, *flags)),
            _ => None,
        })
        .expect("expected generic map update");
    assert_eq!(update.0, MapKind::LpmTrie);
    assert_eq!(update.2, 1);
}

#[test]
fn test_lower_map_push_respects_queue_kind_and_flags() {
    let hir = make_map_push_program(DeclId::new(42), 1, "queue");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-push".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("queue map-push should lower");

    let push = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapPush { map, val, flags } if map.name == "recent_pids" => {
                Some((map.kind, *val, *flags))
            }
            _ => None,
        })
        .expect("expected generic map push");
    assert_eq!(push.0, MapKind::Queue);
    assert_eq!(push.2, 1);
}

#[test]
fn test_lower_map_push_respects_stack_kind() {
    let hir = make_map_push_program(DeclId::new(42), 0, "stack");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-push".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("stack map-push should lower");

    let kind = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapPush { map, .. } if map.name == "recent_pids" => Some(map.kind),
            _ => None,
        })
        .expect("expected generic map push");
    assert_eq!(kind, MapKind::Stack);
}

#[test]
fn test_lower_map_push_registers_queue_value_schema() {
    let hir = make_map_push_program(DeclId::new(42), 0, "queue");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-push".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("queue map-push should register a value schema");

    assert!(matches!(
        result.generic_map_value_types.get(&MapRef {
            name: "recent_pids".to_string(),
            kind: MapKind::Queue,
        }),
        Some(ty) if !matches!(ty, MirType::Unknown)
    ));
}

#[test]
fn test_lower_map_peek_uses_prior_queue_schema() {
    let hir = make_map_peek_program(Some(DeclId::new(42)), DeclId::new(43), "queue");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([
        (DeclId::new(42), "map-push".to_string()),
        (DeclId::new(43), "map-peek".to_string()),
    ]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-peek should lower after a typed map-push");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef { name, kind: MapKind::Queue },
                    ..
                } if name == "recent_pids"
            ))
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
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::MapPeekElem as u32 && args.len() == 2
            ))
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .any(|block| matches!(block.terminator, MirInst::Branch { .. }))
    );
    assert!(result.type_hints.main.values().any(|ty| matches!(
        ty,
        MirType::MapRef { val_ty, .. } if !matches!(val_ty.as_ref(), MirType::Unknown)
    )));
}

#[test]
fn test_lower_map_pop_requires_known_queue_schema() {
    let hir = make_map_pop_program(None, DeclId::new(42), "queue");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-pop".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("map-pop without a known value schema should fail");

    assert!(
        err.to_string()
            .contains("map-pop requires known value layout for 'recent_pids'")
    );
}

#[test]
fn test_lower_map_put_of_map_get_root_preserves_copied_map_schema() {
    let hir = make_map_copy_projection_program(DeclId::new(42), DeclId::new(43), DeclId::new(44));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-put".to_string());
    decl_names.insert(DeclId::new(43), "map-get".to_string());
    decl_names.insert(DeclId::new(44), "count".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-to-map copy projection should lower");

    assert!(matches!(
        result.generic_map_value_types.get(&MapRef {
            name: "copied_path".to_string(),
            kind: MapKind::Hash,
        }),
        Some(MirType::Struct { name, fields, .. })
            if name.as_deref() == Some("path")
                && fields.len() == 2
                && fields[0].name == "mnt"
                && fields[1].name == "dentry"
    ));
}

#[test]
fn test_lower_map_delete_respects_kind() {
    let hir = make_map_delete_program(DeclId::new(42), "per-cpu-hash");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-delete".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-delete should lower");

    let kind = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapDelete { map, .. } if map.name == "cached_path" => Some(map.kind),
            _ => None,
        })
        .expect("expected generic map delete");
    assert_eq!(kind, MapKind::PerCpuHash);
}

#[test]
fn test_lower_map_delete_rejects_array_kind() {
    let hir = make_map_delete_program(DeclId::new(42), "array");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-delete".to_string());

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("array map delete should be rejected during lowering");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(msg.contains("map delete is not supported for array map kind"));
            assert!(msg.contains("Array"));
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_lower_map_put_rejects_queue_kind() {
    let hir = make_map_put_program(DeclId::new(42), 0, "queue");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-put".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("queue map-put should be rejected during lowering");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(msg.contains("map-put is not supported for map kind"));
            assert!(msg.contains("Queue"));
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_lower_map_put_rejects_redirect_only_devmap_kind() {
    let hir = make_map_put_program(DeclId::new(42), 0, "devmap");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-put".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("devmap map-put should be rejected during lowering");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains("map-put --kind devmap is reserved for bpf_redirect_map"),
                "{msg}"
            );
            assert!(msg.contains("generic map commands only support"), "{msg}");
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_lower_map_get_rejects_sockmap_kind() {
    let mut hir = make_map_get_projection_program(DeclId::new(42), DeclId::new(43));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([
        (DeclId::new(42), "map-get".to_string()),
        (DeclId::new(43), "count".to_string()),
    ]);

    for stmt in &mut hir.main.blocks[0].stmts {
        if let HirStmt::LoadLiteral {
            dst,
            lit: HirLiteral::String(kind),
        } = stmt
            && *dst == RegId::new(3)
        {
            *kind = b"sockmap".to_vec();
        }
    }

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("sockmap map-get should be rejected during lowering");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(msg.contains("map-get is not supported for socket map kind"));
            assert!(msg.contains("SockMap"));
            assert!(msg.contains("use specialized socket-map helpers instead"));
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_lower_map_get_rejects_redirect_only_cpumap_kind() {
    let mut hir = make_map_get_projection_program(DeclId::new(42), DeclId::new(43));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([
        (DeclId::new(42), "map-get".to_string()),
        (DeclId::new(43), "count".to_string()),
    ]);

    for stmt in &mut hir.main.blocks[0].stmts {
        if let HirStmt::LoadLiteral {
            dst,
            lit: HirLiteral::String(kind),
        } = stmt
            && *dst == RegId::new(3)
        {
            *kind = b"cpumap".to_vec();
        }
    }

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("cpumap map-get should be rejected during lowering");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains("map-get --kind cpumap is reserved for bpf_redirect_map"),
                "{msg}"
            );
            assert!(msg.contains("generic map commands only support"), "{msg}");
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_lower_map_put_rejects_sockhash_kind() {
    let hir = make_map_put_program(DeclId::new(42), 0, "sockhash");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-put".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("sockhash map-put should be rejected during lowering");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(msg.contains("map-put is not supported for socket map kind"));
            assert!(msg.contains("SockHash"));
            assert!(msg.contains("use specialized socket-map update helpers instead"));
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_lower_map_delete_rejects_queue_kind() {
    let hir = make_map_delete_program(DeclId::new(42), "queue");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-delete".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("queue map-delete should be rejected during lowering");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(msg.contains("map delete is not supported for map kind"));
            assert!(msg.contains("Queue"));
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_lower_map_delete_rejects_redirect_only_xskmap_kind() {
    let hir = make_map_delete_program(DeclId::new(42), "xskmap");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-delete".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("xskmap map-delete should be rejected during lowering");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains("map-delete --kind xskmap is reserved for bpf_redirect_map"),
                "{msg}"
            );
            assert!(msg.contains("generic map commands only support"), "{msg}");
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_lower_map_delete_rejects_sockmap_kind() {
    let hir = make_map_delete_program(DeclId::new(42), "sockmap");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-delete".to_string())]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("sockmap map-delete should be rejected during lowering");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(msg.contains("map-delete is not supported for socket map kind"));
            assert!(msg.contains("SockMap"));
            assert!(
                msg.contains(
                    "socket maps require specialized redirect/update helpers instead of generic map-delete"
                )
            );
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_lower_captured_string_map_name_respects_literal_metadata() {
    let hir = make_captured_map_delete_program(DeclId::new(42), VarId::new(11), "hash");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "map-delete".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("captured string map name should lower");

    let map_name = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapDelete { map, .. } => Some(map.name.as_str()),
            _ => None,
        })
        .expect("expected generic map delete");

    assert_eq!(map_name, "captured_path");
}
