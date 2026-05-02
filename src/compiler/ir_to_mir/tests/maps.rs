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

fn map_define_with_max_entries_hir(
    max_entries: i64,
    kind: &str,
) -> (HirProgram, HashMap<DeclId, String>) {
    let map_define_decl = DeclId::new(41);
    let decl_names = HashMap::from([(map_define_decl, "map-define".to_string())]);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("small_map".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(kind.into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("int".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::Int(max_entries),
                },
                HirStmt::Call {
                    decl_id: map_define_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![
                            (b"kind".to_vec(), RegId::new(1)),
                            (b"value-type".to_vec(), RegId::new(2)),
                            (b"max-entries".to_vec(), RegId::new(3)),
                        ],
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
    (
        HirProgram::new(func, HashMap::new(), vec![], None),
        decl_names,
    )
}

fn validate_map_value_type_spec_for_kind(spec: &str, kind: MapKind) -> Result<(), CompileError> {
    let (ty, _) = HirToMirLowering::parse_named_map_value_type_spec(spec)?;
    HirToMirLowering::validate_named_map_value_type_for_map(
        &MapRef {
            name: "typed_value".to_string(),
            kind,
        },
        &ty,
        "test --value-type",
    )
}

fn make_task_storage_map_get_program(map_get_decl: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let stmts = vec![
        HirStmt::LoadVariable {
            dst: RegId::new(0),
            var_id: ctx_var,
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(1),
            lit: HirLiteral::CellPath(Box::new(CellPath {
                members: vec![string_member("task")],
            })),
        },
        HirStmt::FollowCellPath {
            src_dst: RegId::new(0),
            path: RegId::new(1),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(2),
            lit: HirLiteral::String(b"task_state".to_vec()),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(3),
            lit: HirLiteral::String(b"task-storage".to_vec()),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(4),
            lit: HirLiteral::Int(0),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(5),
            lit: HirLiteral::Int(1),
        },
        HirStmt::Call {
            decl_id: map_get_decl,
            src_dst: RegId::new(0),
            args: HirCallArgs {
                positional: vec![RegId::new(2)],
                named: vec![
                    (b"kind".to_vec(), RegId::new(3)),
                    (b"init".to_vec(), RegId::new(4)),
                    (b"flags".to_vec(), RegId::new(5)),
                ],
                ..Default::default()
            },
        },
    ];
    let spans_len = stmts.len() + 1;
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); spans_len],
        ast: vec![None; spans_len],
        comments: vec![],
        register_count: 6,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_task_storage_map_delete_program(map_delete_decl: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let stmts = vec![
        HirStmt::LoadVariable {
            dst: RegId::new(0),
            var_id: ctx_var,
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(1),
            lit: HirLiteral::CellPath(Box::new(CellPath {
                members: vec![string_member("task")],
            })),
        },
        HirStmt::FollowCellPath {
            src_dst: RegId::new(0),
            path: RegId::new(1),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(2),
            lit: HirLiteral::String(b"task_state".to_vec()),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(3),
            lit: HirLiteral::String(b"task-storage".to_vec()),
        },
        HirStmt::Call {
            decl_id: map_delete_decl,
            src_dst: RegId::new(0),
            args: HirCallArgs {
                positional: vec![RegId::new(2)],
                named: vec![(b"kind".to_vec(), RegId::new(3))],
                ..Default::default()
            },
        },
    ];
    let spans_len = stmts.len() + 1;
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); spans_len],
        ast: vec![None; spans_len],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_task_storage_map_contains_program(map_contains_decl: DeclId) -> HirProgram {
    let ctx_var = VarId::new(0);
    let stmts = vec![
        HirStmt::LoadVariable {
            dst: RegId::new(0),
            var_id: ctx_var,
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(1),
            lit: HirLiteral::CellPath(Box::new(CellPath {
                members: vec![string_member("task")],
            })),
        },
        HirStmt::FollowCellPath {
            src_dst: RegId::new(0),
            path: RegId::new(1),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(2),
            lit: HirLiteral::String(b"task_state".to_vec()),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(3),
            lit: HirLiteral::String(b"task-storage".to_vec()),
        },
        HirStmt::Call {
            decl_id: map_contains_decl,
            src_dst: RegId::new(0),
            args: HirCallArgs {
                positional: vec![RegId::new(2)],
                named: vec![(b"kind".to_vec(), RegId::new(3))],
                ..Default::default()
            },
        },
    ];
    let spans_len = stmts.len() + 1;
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); spans_len],
        ast: vec![None; spans_len],
        comments: vec![],
        register_count: 4,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_sock_ops_socket_map_put_program(
    map_put_decl: DeclId,
    kind: &str,
    flags: i64,
) -> HirProgram {
    let ctx_var = VarId::new(0);
    let stmts = vec![
        HirStmt::LoadVariable {
            dst: RegId::new(0),
            var_id: ctx_var,
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(1),
            lit: HirLiteral::String(b"active_sockets".to_vec()),
        },
        HirStmt::LoadVariable {
            dst: RegId::new(2),
            var_id: ctx_var,
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(3),
            lit: HirLiteral::CellPath(Box::new(CellPath {
                members: vec![string_member("remote_port")],
            })),
        },
        HirStmt::FollowCellPath {
            src_dst: RegId::new(2),
            path: RegId::new(3),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(4),
            lit: HirLiteral::String(kind.as_bytes().to_vec()),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(5),
            lit: HirLiteral::Int(flags),
        },
        HirStmt::Call {
            decl_id: map_put_decl,
            src_dst: RegId::new(0),
            args: HirCallArgs {
                positional: vec![RegId::new(1), RegId::new(2)],
                named: vec![
                    (b"kind".to_vec(), RegId::new(4)),
                    (b"flags".to_vec(), RegId::new(5)),
                ],
                ..Default::default()
            },
        },
    ];
    let spans_len = stmts.len() + 1;
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); spans_len],
        ast: vec![None; spans_len],
        comments: vec![],
        register_count: 6,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
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
fn test_lower_map_get_task_storage_uses_storage_helper() {
    let hir = make_task_storage_map_get_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-get".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("task-storage map-get should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef {
                        name,
                        kind: MapKind::TaskStorage,
                    },
                    ..
                } if name == "task_state"
            ))
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::TaskStorageGet as u32
                        && args.len() == 4
                        && matches!(args[3], MirValue::Const(1))
            ))
    );
    assert!(matches!(
        result.generic_map_value_types.get(&MapRef {
            name: "task_state".to_string(),
            kind: MapKind::TaskStorage,
        }),
        Some(MirType::I64)
    ));
}

#[test]
fn test_lower_map_delete_task_storage_uses_storage_helper() {
    let hir = make_task_storage_map_delete_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-delete".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("task-storage map-delete should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef {
                        name,
                        kind: MapKind::TaskStorage,
                    },
                    ..
                } if name == "task_state"
            ))
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::TaskStorageDelete as u32 && args.len() == 2
            ))
    );
}

#[test]
fn test_lower_map_contains_task_storage_uses_storage_lookup() {
    let hir = make_task_storage_map_contains_program(DeclId::new(42));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-contains".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("task-storage map-contains should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef {
                        name,
                        kind: MapKind::TaskStorage,
                    },
                    ..
                } if name == "task_state"
            ))
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::TaskStorageGet as u32
                        && args.len() == 4
                        && matches!(args[2], MirValue::Const(0))
                        && matches!(args[3], MirValue::Const(0))
            ))
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::BinOp {
                    op: BinOpKind::Ne,
                    rhs: MirValue::Const(0),
                    ..
                }
            ))
    );
    assert_eq!(result.type_hints.main.get(&VReg(0)), Some(&MirType::Bool));
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
fn test_lower_map_put_sockmap_uses_socket_update_helper() {
    let hir = make_sock_ops_socket_map_put_program(DeclId::new(42), "sockmap", 7);
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let decl_names = HashMap::from([(DeclId::new(42), "map-put".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sockmap map-put should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef {
                        name,
                        kind: MapKind::SockMap,
                    },
                    ..
                } if name == "active_sockets"
            ))
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::SockMapUpdate as u32
                        && args.len() == 4
                        && matches!(args[3], MirValue::Const(7))
            ))
    );
}

#[test]
fn test_lower_map_put_sockhash_uses_socket_update_helper() {
    let hir = make_sock_ops_socket_map_put_program(DeclId::new(42), "sockhash", 0);
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let decl_names = HashMap::from([(DeclId::new(42), "map-put".to_string())]);

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("sockhash map-put should lower");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::LoadMapFd {
                    map: MapRef {
                        name,
                        kind: MapKind::SockHash,
                    },
                    ..
                } if name == "active_sockets"
            ))
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::CallHelper { helper, args, .. }
                    if *helper == BpfHelper::SockHashUpdate as u32
                        && args.len() == 4
                        && matches!(args[3], MirValue::Const(0))
            ))
    );
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
fn test_lower_map_push_respects_bloom_filter_kind() {
    let hir = make_map_push_program(DeclId::new(42), 0, "bloom-filter");
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
    .expect("bloom-filter map-push should lower");

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
    assert_eq!(kind, MapKind::BloomFilter);
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
fn test_lower_map_peek_rejects_bloom_filter_kind() {
    let hir = make_map_peek_program(Some(DeclId::new(41)), DeclId::new(42), "bloom-filter");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([
        (DeclId::new(41), "map-push".to_string()),
        (DeclId::new(42), "map-peek".to_string()),
    ]);

    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("first-class bloom-filter map-peek should be rejected");

    assert!(
        err.to_string()
            .contains("map-peek requires --kind queue or --kind stack, got bloom-filter")
    );
}

#[test]
fn test_lower_map_pop_rejects_bloom_filter_kind() {
    let hir = make_map_pop_program(None, DeclId::new(42), "bloom-filter");
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
    .expect_err("bloom-filter map-pop should be rejected");

    assert!(
        err.to_string()
            .contains("map-pop requires --kind queue or --kind stack, got bloom-filter")
    );
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
            assert!(msg.contains("array"));
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
            assert!(msg.contains("queue"));
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
fn test_lower_map_put_rejects_prog_array_kind_with_tail_call_guidance() {
    let hir = make_map_put_program(DeclId::new(42), 0, "prog-array");
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
    .expect_err("prog-array map-put should be rejected during lowering");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains("map-put --kind prog-array is reserved for program-array maps"),
                "{msg}"
            );
            assert!(msg.contains("use tail-call"), "{msg}");
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_lower_map_put_rejects_recognized_unmodeled_map_kinds_with_guidance() {
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let decl_names = HashMap::from([(DeclId::new(42), "map-put".to_string())]);

    for (kind, expected) in [
        ("array-of-maps", "inner-map metadata is not modeled yet"),
        ("hash-of-maps", "inner-map metadata is not modeled yet"),
        ("struct-ops", "reserved for struct_ops objects"),
        ("user-ringbuf", "reserved for user-ringbuf helper surfaces"),
        ("arena", "arena map_extra/mmap support is not modeled yet"),
        ("deprecated-cgroup-storage", "deprecated cgroup-storage map"),
        ("per-cpu-cgroup-storage", "deprecated cgroup-storage map"),
    ] {
        let hir = make_map_put_program(DeclId::new(42), 0, kind);
        let err = match lower_hir_to_mir_with_hints(
            &hir,
            Some(&probe_ctx),
            &decl_names,
            None,
            &HashMap::new(),
            &HashMap::new(),
        ) {
            Ok(_) => panic!("{kind} map-put should be rejected during lowering"),
            Err(err) => err,
        };

        match err {
            CompileError::UnsupportedInstruction(msg) => {
                assert!(msg.contains(expected), "{kind}: {msg}");
            }
            other => panic!("unexpected lowering error for {kind}: {other:?}"),
        }
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
            assert!(msg.contains("sockmap"));
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
fn test_lower_map_get_rejects_ringbuf_kind_with_emit_guidance() {
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
            *kind = b"ringbuf".to_vec();
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
    .expect_err("ringbuf map-get should be rejected during lowering");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains("map-get --kind ringbuf is reserved for ring-buffer event maps"),
                "{msg}"
            );
            assert!(msg.contains("use emit"), "{msg}");
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
            assert!(msg.contains("helper 'bpf_sock_hash_update' is only valid in sock_ops"));
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
            assert!(msg.contains("queue"));
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_lower_map_delete_rejects_stack_trace_kind_with_stack_guidance() {
    let hir = make_map_delete_program(DeclId::new(42), "stack-trace");
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
    .expect_err("stack-trace map-delete should be rejected during lowering");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains("map-delete --kind stack-trace is reserved for stack-trace maps"),
                "{msg}"
            );
            assert!(msg.contains("ctx.kstack/ctx.ustack"), "{msg}");
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
            assert!(msg.contains("sockmap"));
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

#[test]
fn test_map_define_key_type_registers_and_materializes_record_key() {
    let map_define_decl = DeclId::new(41);
    let map_put_decl = DeclId::new(42);
    let decl_names = HashMap::from([
        (map_define_decl, "map-define".to_string()),
        (map_put_decl, "map-put".to_string()),
    ]);

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
                    lit: HirLiteral::Int(1),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(0),
                    key: RegId::new(1),
                    val: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("cookie".into()),
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
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String("typed_keys".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::String("hash".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::String("record{pid:int,cookie:int}".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(8),
                    lit: HirLiteral::String("int".into()),
                },
                HirStmt::Call {
                    decl_id: map_define_decl,
                    src_dst: RegId::new(9),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5)],
                        named: vec![
                            (b"kind".to_vec(), RegId::new(6)),
                            (b"key-type".to_vec(), RegId::new(7)),
                            (b"value-type".to_vec(), RegId::new(8)),
                        ],
                        ..HirCallArgs::default()
                    },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(10),
                    lit: HirLiteral::Int(42),
                },
                HirStmt::Call {
                    decl_id: map_put_decl,
                    src_dst: RegId::new(10),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5), RegId::new(0)],
                        named: vec![(b"kind".to_vec(), RegId::new(6))],
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
    .expect("map-define record key schema should lower");

    let map_ref = MapRef {
        name: "typed_keys".to_string(),
        kind: MapKind::Hash,
    };
    let key_ty = result
        .generic_map_key_types
        .get(&map_ref)
        .expect("map-define should register a key schema");
    assert_eq!(key_ty.size(), 16);

    let key_vreg = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapUpdate { map, key, .. } if map == &map_ref => Some(*key),
            _ => None,
        })
        .expect("expected typed-key map update");
    assert_eq!(
        result.type_hints.main.get(&key_vreg),
        Some(&MirType::Ptr {
            pointee: Box::new(key_ty.clone()),
            address_space: AddressSpace::Stack,
        })
    );
}

#[test]
fn test_map_define_max_entries_registers_capacity() {
    let (hir, decl_names) = map_define_with_max_entries_hir(128, "hash");
    let map_ref = MapRef {
        name: "small_map".to_string(),
        kind: MapKind::Hash,
    };

    let result = lower_hir_to_mir_with_hints_key_value_maps_and_semantics(
        &hir,
        None,
        &decl_names,
        None,
        None,
        None,
        None,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-define max entries should lower");

    assert_eq!(result.generic_map_max_entries.get(&map_ref), Some(&128));
    assert_eq!(
        result.type_hints.generic_map_max_entries.get(&map_ref),
        Some(&128)
    );
}

#[test]
fn test_map_define_rejects_zero_max_entries() {
    let (hir, decl_names) = map_define_with_max_entries_hir(0, "hash");

    let err = lower_hir_to_mir_with_hints_key_value_maps_and_semantics(
        &hir,
        None,
        &decl_names,
        None,
        None,
        None,
        None,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("zero max entries should be rejected");

    assert!(err.to_string().contains("must be positive"));
}

#[test]
fn test_map_define_rejects_conflicting_external_max_entries() {
    let (hir, decl_names) = map_define_with_max_entries_hir(256, "hash");
    let map_ref = MapRef {
        name: "small_map".to_string(),
        kind: MapKind::Hash,
    };
    let external_max_entries = HashMap::from([(map_ref, 128)]);

    let err = lower_hir_to_mir_with_hints_key_value_maps_and_semantics(
        &hir,
        None,
        &decl_names,
        None,
        None,
        Some(&external_max_entries),
        None,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("conflicting pinned max entries should fail");

    assert!(err.to_string().contains("conflicts with pinned map schema"));
}

#[test]
fn test_map_define_rejects_conflicting_declared_max_entries() {
    let (mut hir, decl_names) = map_define_with_max_entries_hir(128, "hash");
    let block = &mut hir.main.blocks[0];
    block.stmts.extend([
        HirStmt::LoadLiteral {
            dst: RegId::new(5),
            lit: HirLiteral::Int(256),
        },
        HirStmt::Call {
            decl_id: DeclId::new(41),
            src_dst: RegId::new(6),
            args: HirCallArgs {
                positional: vec![RegId::new(0)],
                named: vec![
                    (b"kind".to_vec(), RegId::new(1)),
                    (b"value-type".to_vec(), RegId::new(2)),
                    (b"max-entries".to_vec(), RegId::new(5)),
                ],
                ..HirCallArgs::default()
            },
        },
    ]);
    block.terminator = HirTerminator::Return { src: RegId::new(6) };
    hir.main.register_count = 7;

    let err = lower_hir_to_mir_with_hints_key_value_maps_and_semantics(
        &hir,
        None,
        &decl_names,
        None,
        None,
        None,
        None,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("conflicting declared max entries should fail");

    assert!(
        err.to_string()
            .contains("conflicts with declared map schema")
    );
}

#[test]
fn test_map_define_rejects_local_storage_max_entries() {
    let (hir, decl_names) = map_define_with_max_entries_hir(128, "task-storage");

    let err = lower_hir_to_mir_with_hints_key_value_maps_and_semantics(
        &hir,
        None,
        &decl_names,
        None,
        None,
        None,
        None,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("local-storage max entries should be rejected");

    assert!(err.to_string().contains("object-local storage"));
}

#[test]
fn test_external_key_schema_materializes_record_key() {
    let map_put_decl = DeclId::new(42);
    let decl_names = HashMap::from([(map_put_decl, "map-put".to_string())]);

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
                    lit: HirLiteral::Int(1),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(0),
                    key: RegId::new(1),
                    val: RegId::new(2),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("cookie".into()),
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
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::String("typed_keys".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(6),
                    lit: HirLiteral::String("hash".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(7),
                    lit: HirLiteral::Int(42),
                },
                HirStmt::Call {
                    decl_id: map_put_decl,
                    src_dst: RegId::new(7),
                    args: HirCallArgs {
                        positional: vec![RegId::new(5), RegId::new(0)],
                        named: vec![(b"kind".to_vec(), RegId::new(6))],
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
    let map_ref = MapRef {
        name: "typed_keys".to_string(),
        kind: MapKind::Hash,
    };
    let key_ty = HirToMirLowering::parse_named_map_key_type_spec("record{pid:int,cookie:int}")
        .expect("record key type should parse");
    let external_key_schema = HashMap::from([(map_ref.clone(), key_ty.clone())]);

    let result = lower_hir_to_mir_with_hints_key_value_maps_and_semantics(
        &hir,
        None,
        &decl_names,
        None,
        Some(&external_key_schema),
        None,
        None,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("external record key schema should lower");

    assert_eq!(result.generic_map_key_types, external_key_schema);
    let key_vreg = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapUpdate { map, key, .. } if map == &map_ref => Some(*key),
            _ => None,
        })
        .expect("expected typed-key map update");
    assert_eq!(
        result.type_hints.main.get(&key_vreg),
        Some(&MirType::Ptr {
            pointee: Box::new(key_ty),
            address_space: AddressSpace::Stack,
        })
    );
}

#[test]
fn test_map_define_rejects_conflicting_external_key_schema() {
    let map_define_decl = DeclId::new(41);
    let decl_names = HashMap::from([(map_define_decl, "map-define".to_string())]);
    let map_ref = MapRef {
        name: "typed_keys".to_string(),
        kind: MapKind::Hash,
    };
    let external_key_schema = HashMap::from([(map_ref, MirType::U64)]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String("typed_keys".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("hash".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("record{pid:int,cookie:int}".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("int".into()),
                },
                HirStmt::Call {
                    decl_id: map_define_decl,
                    src_dst: RegId::new(4),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![
                            (b"kind".to_vec(), RegId::new(1)),
                            (b"key-type".to_vec(), RegId::new(2)),
                            (b"value-type".to_vec(), RegId::new(3)),
                        ],
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

    let err = lower_hir_to_mir_with_hints_key_value_maps_and_semantics(
        &hir,
        None,
        &decl_names,
        None,
        Some(&external_key_schema),
        None,
        None,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("conflicting pinned key schema should fail");

    assert!(err.to_string().contains("conflicts with pinned map schema"));
}

#[test]
fn test_map_value_type_spec_supports_bpf_spin_lock() {
    let (ty, semantics) =
        HirToMirLowering::parse_named_map_value_type_spec("record{lock:bpf_spin_lock,counter:u64}")
            .expect("bpf_spin_lock map value type should parse");

    assert!(semantics.is_none());
    let MirType::Struct { fields, .. } = ty else {
        panic!("expected record map value type, got {ty:?}");
    };
    let user_fields = fields
        .iter()
        .filter(|field| !field.synthetic)
        .collect::<Vec<_>>();
    assert_eq!(user_fields.len(), 2);
    assert_eq!(user_fields[0].name, "lock");
    assert_eq!(user_fields[0].ty, MirType::bpf_spin_lock_struct());
    assert_eq!(user_fields[0].offset, 0);
    assert_eq!(user_fields[1].name, "counter");
    assert_eq!(user_fields[1].ty, MirType::U64);
    assert_eq!(user_fields[1].offset, 8);
    assert_eq!(
        fields.iter().map(|field| field.ty.size()).sum::<usize>(),
        16
    );
    assert_eq!(
        fields
            .iter()
            .find(|field| field.synthetic && field.offset == 4)
            .map(|field| field.ty.size()),
        Some(4)
    );
}

#[test]
fn test_map_value_type_spec_supports_bpf_wq() {
    let (ty, semantics) =
        HirToMirLowering::parse_named_map_value_type_spec("record{work:bpf_wq,counter:u64}")
            .expect("bpf_wq map value type should parse");

    assert!(semantics.is_none());
    let MirType::Struct { fields, .. } = ty else {
        panic!("expected record map value type, got {ty:?}");
    };
    let user_fields = fields
        .iter()
        .filter(|field| !field.synthetic)
        .collect::<Vec<_>>();
    assert_eq!(user_fields.len(), 2);
    assert_eq!(user_fields[0].name, "work");
    assert_eq!(user_fields[0].ty, MirType::bpf_wq_struct());
    assert_eq!(user_fields[0].offset, 0);
    assert_eq!(user_fields[1].name, "counter");
    assert_eq!(user_fields[1].ty, MirType::U64);
    assert_eq!(user_fields[1].offset, 16);
    assert_eq!(
        fields.iter().map(|field| field.ty.size()).sum::<usize>(),
        24
    );
}

#[test]
fn test_map_value_type_spec_supports_kptr_slot() {
    let (ty, semantics) = HirToMirLowering::parse_named_map_value_type_spec(
        "record{task:kptr:task_struct,cookie:u64}",
    )
    .expect("kptr map value type should parse");

    assert!(semantics.is_none());
    let map_ptr_ty = MirType::Ptr {
        pointee: Box::new(ty.clone()),
        address_space: AddressSpace::Map,
    };
    assert_eq!(
        map_ptr_ty.map_pointer_kptr_slot_pointee_name(),
        Some("task_struct")
    );
    let MirType::Struct { fields, .. } = ty else {
        panic!("expected record map value type, got {ty:?}");
    };
    let user_fields = fields
        .iter()
        .filter(|field| !field.synthetic)
        .collect::<Vec<_>>();
    assert_eq!(user_fields.len(), 2);
    assert_eq!(user_fields[0].name, "task");
    assert_eq!(
        user_fields[0].ty.bpf_kptr_pointee_name(),
        Some("task_struct")
    );
    assert_eq!(user_fields[0].offset, 0);
    assert_eq!(user_fields[1].name, "cookie");
    assert_eq!(user_fields[1].ty, MirType::U64);
    assert_eq!(user_fields[1].offset, 8);
    assert_eq!(
        fields.iter().map(|field| field.ty.size()).sum::<usize>(),
        16
    );
}

#[test]
fn test_map_value_type_validation_accepts_managed_fields() {
    validate_map_value_type_spec_for_kind("record{lock:bpf_spin_lock,counter:u64}", MapKind::Hash)
        .expect("top-level spin lock in hash map should validate");
    validate_map_value_type_spec_for_kind("record{timer:bpf_timer,cookie:u64}", MapKind::LruHash)
        .expect("aligned timer in lru hash map should validate");
    validate_map_value_type_spec_for_kind(
        "record{task:kptr:task_struct,cookie:u64}",
        MapKind::Array,
    )
    .expect("aligned kptr slot in array map should validate");
    validate_map_value_type_spec_for_kind("record{work:bpf_wq,cookie:u64}", MapKind::LruHash)
        .expect("aligned bpf_wq in lru hash map should validate");
}

#[test]
fn test_map_value_type_validation_rejects_nested_spin_lock() {
    let err = validate_map_value_type_spec_for_kind(
        "record{nested:record{lock:bpf_spin_lock},counter:u64}",
        MapKind::Hash,
    )
    .expect_err("nested spin lock should be rejected");

    assert!(err.to_string().contains("top-level map-value record field"));
}

#[test]
fn test_map_value_type_validation_rejects_multiple_spin_locks() {
    let err = validate_map_value_type_spec_for_kind(
        "record{lock:bpf_spin_lock,other:bpf_spin_lock}",
        MapKind::Hash,
    )
    .expect_err("multiple spin locks should be rejected");

    assert!(err.to_string().contains("exactly one bpf_spin_lock"));
}

#[test]
fn test_map_value_type_validation_rejects_spin_lock_on_lru_hash() {
    let err = validate_map_value_type_spec_for_kind(
        "record{lock:bpf_spin_lock,counter:u64}",
        MapKind::LruHash,
    )
    .expect_err("spin lock on lru-hash should be rejected");

    assert!(
        err.to_string()
            .contains("only supported for hash and array")
    );
}

#[test]
fn test_map_value_type_validation_rejects_misaligned_timer() {
    let ty = MirType::Struct {
        name: None,
        kernel_btf_type_id: None,
        fields: vec![
            StructField {
                name: "cookie".to_string(),
                ty: MirType::U32,
                offset: 0,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "timer".to_string(),
                ty: MirType::bpf_timer_struct(),
                offset: 4,
                synthetic: false,
                bitfield: None,
            },
        ],
    };
    let err = HirToMirLowering::validate_named_map_value_type_for_map(
        &MapRef {
            name: "external_timer".to_string(),
            kind: MapKind::Hash,
        },
        &ty,
        "test --value-type",
    )
    .expect_err("misaligned external timer schema should be rejected");

    assert!(err.to_string().contains("8-byte aligned"));
}

#[test]
fn test_map_value_type_validation_rejects_timer_on_queue() {
    let err =
        validate_map_value_type_spec_for_kind("record{timer:bpf_timer,cookie:u64}", MapKind::Queue)
            .expect_err("timer on queue should be rejected");

    assert!(
        err.to_string()
            .contains("only supported for hash, array, and lru-hash")
    );
}

#[test]
fn test_map_value_type_validation_rejects_wq_array() {
    let err = validate_map_value_type_spec_for_kind(
        "record{work_items:array{bpf_wq:2},counter:u64}",
        MapKind::Hash,
    )
    .expect_err("arrays of bpf_wq should be rejected");

    assert!(
        err.to_string()
            .contains("arrays of verifier-managed bpf_wq")
    );
}

#[test]
fn test_map_value_type_validation_rejects_wq_on_queue() {
    let err =
        validate_map_value_type_spec_for_kind("record{work:bpf_wq,cookie:u64}", MapKind::Queue)
            .expect_err("bpf_wq on queue should be rejected");

    assert!(
        err.to_string()
            .contains("only supported for hash, array, and lru-hash")
    );
}

#[test]
fn test_map_value_type_validation_rejects_nested_kptr_slot() {
    let err = validate_map_value_type_spec_for_kind(
        "record{nested:record{task:kptr:task_struct},cookie:u64}",
        MapKind::Array,
    )
    .expect_err("nested kptr slot should be rejected");

    assert!(
        err.to_string()
            .contains("top-level map-value record fields")
    );
}

#[test]
fn test_map_value_type_validation_rejects_kptr_slot_on_queue() {
    let err = validate_map_value_type_spec_for_kind(
        "record{task:kptr:task_struct,cookie:u64}",
        MapKind::Queue,
    )
    .expect_err("kptr slot on queue should be rejected");

    assert!(
        err.to_string()
            .contains("currently supported for hash, array, and lru-hash")
    );
}

#[test]
fn test_map_value_type_spec_rejects_invalid_kptr_type_name() {
    let err = HirToMirLowering::parse_named_map_value_type_spec("record{task:kptr:task-struct}")
        .expect_err("invalid kptr type name should fail");

    assert!(
        err.to_string()
            .contains("requires a kernel struct type name")
    );
}

#[test]
fn test_map_define_rejects_key_type_for_keyless_map() {
    let map_define_decl = DeclId::new(41);
    let decl_names = HashMap::from([(map_define_decl, "map-define".to_string())]);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("queued".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("queue".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(3),
                    lit: HirLiteral::String("u32".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(4),
                    lit: HirLiteral::String("u64".into()),
                },
                HirStmt::Call {
                    decl_id: map_define_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        named: vec![
                            (b"kind".to_vec(), RegId::new(2)),
                            (b"key-type".to_vec(), RegId::new(3)),
                            (b"value-type".to_vec(), RegId::new(4)),
                        ],
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("keyless map key schemas should be rejected");
    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(msg.contains("--key-type is not supported for keyless"))
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}
