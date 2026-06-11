use super::helpers::*;
use super::*;
use crate::compiler::BpfHelper;
use crate::compiler::EbpfProgramType;
use crate::compiler::hir::{
    HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
};
use crate::compiler::mir::{AddressSpace, BYTES_COUNTER_MAP_NAME, BpfGraphRootKind, StructField};
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

fn map_define_with_value_type_hir(
    map_name: &str,
    kind: &str,
    value_type: &str,
) -> (HirProgram, HashMap<DeclId, String>) {
    let map_define_decl = DeclId::new(41);
    let decl_names = HashMap::from([(map_define_decl, "map-define".to_string())]);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::String(map_name.into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String(kind.into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String(value_type.into()),
                },
                HirStmt::Call {
                    decl_id: map_define_decl,
                    src_dst: RegId::new(3),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0)],
                        named: vec![
                            (b"kind".to_vec(), RegId::new(1)),
                            (b"value-type".to_vec(), RegId::new(2)),
                        ],
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
    (
        HirProgram::new(func, HashMap::new(), vec![], None),
        decl_names,
    )
}

fn map_define_map_in_map_hir(
    outer_kind: &str,
    include_inner_map: bool,
    include_outer_key_type: bool,
    include_outer_value_type: bool,
) -> (HirProgram, HashMap<DeclId, String>) {
    let map_define_decl = DeclId::new(41);
    let decl_names = HashMap::from([(map_define_decl, "map-define".to_string())]);
    let mut stmts = vec![
        HirStmt::LoadLiteral {
            dst: RegId::new(0),
            lit: HirLiteral::String("inner".into()),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(1),
            lit: HirLiteral::String("hash".into()),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(2),
            lit: HirLiteral::String("u64".into()),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(3),
            lit: HirLiteral::Int(16),
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
        HirStmt::LoadLiteral {
            dst: RegId::new(5),
            lit: HirLiteral::String("outer".into()),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(6),
            lit: HirLiteral::String(outer_kind.into()),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(7),
            lit: HirLiteral::String("inner".into()),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(8),
            lit: HirLiteral::Int(4),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(9),
            lit: HirLiteral::String("u32".into()),
        },
        HirStmt::LoadLiteral {
            dst: RegId::new(10),
            lit: HirLiteral::String("u64".into()),
        },
    ];
    let mut named = vec![
        (b"kind".to_vec(), RegId::new(6)),
        (b"max-entries".to_vec(), RegId::new(8)),
    ];
    if include_inner_map {
        named.push((b"inner-map".to_vec(), RegId::new(7)));
    }
    if include_outer_key_type {
        named.push((b"key-type".to_vec(), RegId::new(9)));
    }
    if include_outer_value_type {
        named.push((b"value-type".to_vec(), RegId::new(10)));
    }
    stmts.push(HirStmt::Call {
        decl_id: map_define_decl,
        src_dst: RegId::new(11),
        args: HirCallArgs {
            positional: vec![RegId::new(5)],
            named,
            ..HirCallArgs::default()
        },
    });
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts,
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

#[test]
fn test_map_value_type_spec_rejects_invalid_array_length_with_context() {
    let err = HirToMirLowering::parse_named_map_value_type_spec("array{u32:x}")
        .expect_err("map value type parser should reject invalid array lengths");

    assert!(
        err.to_string()
            .contains("map value type spec 'array{u32:x}' has an invalid array length"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_map_key_type_spec_rejects_invalid_array_length_with_context() {
    let err = HirToMirLowering::parse_named_map_key_type_spec("array{u32:x}")
        .expect_err("map key type parser should reject invalid array lengths");

    assert!(
        err.to_string()
            .contains("map key type spec 'array{u32:x}' has an invalid array length"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_map_value_type_spec_rejects_zero_byte_length_with_context() {
    let err = HirToMirLowering::parse_named_map_value_type_spec("bytes:0")
        .expect_err("map value type parser should reject zero byte lengths");

    assert!(
        err.to_string()
            .contains("map value type spec 'bytes:0' requires a positive byte-array length"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_map_key_type_spec_rejects_empty_record_with_context() {
    let err = HirToMirLowering::parse_named_map_key_type_spec("record{}")
        .expect_err("map key type parser should reject empty records");

    assert!(
        err.to_string()
            .contains("map key type spec 'record{}' requires at least one record field"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_map_key_type_spec_rejects_duplicate_record_field_with_context() {
    let err = HirToMirLowering::parse_named_map_key_type_spec("record{pid:u32,pid:u64}")
        .expect_err("map key type parser should reject duplicate record fields");

    assert!(
        err.to_string()
            .contains("record field 'pid' is duplicated in type spec 'record{pid:u32,pid:u64}'"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_map_value_type_spec_rejects_reserved_record_field_with_context() {
    let err = HirToMirLowering::parse_named_map_value_type_spec("record{__layout_pad0:u32}")
        .expect_err("map value type parser should reject reserved record fields");

    assert!(
        err.to_string()
            .contains("record field '__layout_pad0' uses reserved prefix '__layout_pad'"),
        "unexpected error: {err}"
    );
}

fn validate_manual_map_value_type_for_kind(ty: MirType, kind: MapKind) -> Result<(), CompileError> {
    HirToMirLowering::validate_named_map_value_type_for_map(
        &MapRef {
            name: "typed_value".to_string(),
            kind,
        },
        &ty,
        "test --value-type",
    )
}

fn manual_map_value_struct(fields: Vec<StructField>) -> MirType {
    MirType::Struct {
        name: None,
        kernel_btf_type_id: None,
        fields,
    }
}

fn manual_map_value_field(name: &str, ty: MirType, offset: usize) -> StructField {
    StructField {
        name: name.to_string(),
        ty,
        offset,
        synthetic: false,
        bitfield: None,
    }
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
                pipeline_input: Some(RegId::new(0)),
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
                            pipeline_input: Some(RegId::new(0)),
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
                            pipeline_input: Some(RegId::new(0)),
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
fn test_lower_map_put_fixed_record_array_source_list_builder_skips_runtime_list_ops() {
    let map_put_decl = DeclId::new(224);
    let decl_names = HashMap::from([(map_put_decl, "map-put".to_string())]);

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
                    lit: HirLiteral::String("entries_by_pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(12),
                    lit: HirLiteral::Int(7),
                },
                HirStmt::Call {
                    decl_id: map_put_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(11), RegId::new(12)],
                        pipeline_input: Some(RegId::new(0)),
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
    .expect("source list-of-record map-put value should lower as fixed map data");

    let expected_ty = MirType::Array {
        elem: Box::new(MirType::Struct {
            name: None,
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "pid".to_string(),
                    ty: MirType::I64,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "cpu".to_string(),
                    ty: MirType::I64,
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        }),
        len: 2,
    };
    let map_ref = MapRef {
        name: "entries_by_pid".to_string(),
        kind: MapKind::Hash,
    };
    assert_eq!(
        result.generic_map_value_types.get(&map_ref),
        Some(&expected_ty)
    );
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
        "compile-time map-put list-of-record builders must not emit runtime list operations"
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
                    map: MapRef { name, kind },
                    ..
                } if name == "entries_by_pid" && *kind == MapKind::Hash
            )),
        "expected fixed record-array map-put value to update the target map"
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
                            pipeline_input: Some(RegId::new(0)),
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
fn test_lower_map_get_rejects_invalid_external_graph_schema() {
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
        manual_map_value_struct(vec![
            manual_map_value_field("root", MirType::bpf_list_head_struct(), 0),
            manual_map_value_field("counter", MirType::U64, 16),
        ]),
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
    .expect_err("invalid pinned graph schema should be rejected before projection");

    let msg = err.to_string();
    assert!(msg.contains("map-get value schema"));
    assert!(msg.contains("contains:TYPE:FIELD"));
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
fn test_map_get_infers_prior_operation_kind_when_kind_is_omitted() {
    let map_put_decl = DeclId::new(42);
    let map_get_decl = DeclId::new(43);
    let mut hir = make_map_put_program(map_put_decl, 0, "array");
    let mut decl_names = HashMap::new();
    decl_names.insert(map_put_decl, "map-put".to_string());
    decl_names.insert(map_get_decl, "map-get".to_string());

    let block = &mut hir.main.blocks[0];
    block.stmts.push(HirStmt::Call {
        decl_id: map_get_decl,
        src_dst: RegId::new(3),
        args: HirCallArgs {
            positional: vec![RegId::new(2)],
            ..HirCallArgs::default()
        },
    });
    block.terminator = HirTerminator::Return { src: RegId::new(3) };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-get should infer the prior explicit map-put kind");

    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::MapLookup { map, .. }
                    if map.name == "cached_path" && map.kind == MapKind::Array
            )),
        "map-get without --kind should use the prior explicit operation kind"
    );
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
fn test_lower_map_put_rejects_live_src_dst_without_pipeline_input() {
    let map_put_decl = DeclId::new(42);
    let decl_names = HashMap::from([(map_put_decl, "map-put".to_string())]);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(99),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("seen".into()),
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

    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("map-put must not consume a merely live src_dst value");

    assert!(
        err.to_string()
            .contains("map-put requires a value from pipeline input")
    );
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
fn test_map_push_infers_prior_map_define_kind_when_kind_is_omitted() {
    let map_push_decl = DeclId::new(42);
    let (mut hir, mut decl_names) = map_define_with_value_type_hir("recent_pids", "queue", "int");
    decl_names.insert(map_push_decl, "map-push".to_string());

    let block = &mut hir.main.blocks[0];
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(4),
        lit: HirLiteral::Int(99),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_push_decl,
        src_dst: RegId::new(4),
        args: HirCallArgs {
            positional: vec![RegId::new(0)],
            pipeline_input: Some(RegId::new(4)),
            ..HirCallArgs::default()
        },
    });
    block.terminator = HirTerminator::Return { src: RegId::new(4) };
    hir.main.register_count = 5;

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-push should infer the declared queue map kind");

    let push = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapPush { map, flags, .. } if map.name == "recent_pids" => {
                Some((map.kind, *flags))
            }
            _ => None,
        })
        .expect("expected generic map push");
    assert_eq!(push, (MapKind::Queue, 0));
}

#[test]
fn test_lower_map_push_rejects_live_src_dst_without_pipeline_input() {
    let map_push_decl = DeclId::new(42);
    let decl_names = HashMap::from([(map_push_decl, "map-push".to_string())]);
    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::Int(99),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("recent".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("queue".into()),
                },
                HirStmt::Call {
                    decl_id: map_push_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(1)],
                        named: vec![(b"kind".to_vec(), RegId::new(2))],
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
    .expect_err("map-push must not consume a merely live src_dst value");

    assert!(
        err.to_string()
            .contains("map-push requires a value from pipeline input")
    );
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
fn test_lower_map_push_fixed_record_array_source_list_builder_skips_runtime_list_ops() {
    let map_push_decl = DeclId::new(225);
    let decl_names = HashMap::from([(map_push_decl, "map-push".to_string())]);

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
                    lit: HirLiteral::String("entry_batches".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(12),
                    lit: HirLiteral::String("queue".into()),
                },
                HirStmt::Call {
                    decl_id: map_push_decl,
                    src_dst: RegId::new(0),
                    args: HirCallArgs {
                        positional: vec![RegId::new(11)],
                        named: vec![(b"kind".to_vec(), RegId::new(12))],
                        pipeline_input: Some(RegId::new(0)),
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
    .expect("source list-of-record map-push value should lower as fixed map data");

    let expected_ty = MirType::Array {
        elem: Box::new(MirType::Struct {
            name: None,
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "pid".to_string(),
                    ty: MirType::I64,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "cpu".to_string(),
                    ty: MirType::I64,
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        }),
        len: 2,
    };
    let map_ref = MapRef {
        name: "entry_batches".to_string(),
        kind: MapKind::Queue,
    };
    assert_eq!(
        result.generic_map_value_types.get(&map_ref),
        Some(&expected_ty)
    );
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
        "compile-time map-push list-of-record builders must not emit runtime list operations"
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
                MirInst::MapPush {
                    map: MapRef { name, kind },
                    ..
                } if name == "entry_batches" && *kind == MapKind::Queue
            )),
        "expected fixed record-array map-push value to push to the target map"
    );
}

fn declared_queue_map_take_hir(
    map_take_decl: DeclId,
    command: &str,
) -> (HirProgram, HashMap<DeclId, String>) {
    let (mut hir, mut decl_names) = map_define_with_value_type_hir("recent_pids", "queue", "int");
    decl_names.insert(map_take_decl, command.to_string());

    let block = &mut hir.main.blocks[0];
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(4),
        lit: HirLiteral::Int(0),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_take_decl,
        src_dst: RegId::new(4),
        args: HirCallArgs {
            positional: vec![RegId::new(0)],
            ..HirCallArgs::default()
        },
    });
    block.terminator = HirTerminator::Return { src: RegId::new(4) };
    hir.main.register_count = 5;

    (hir, decl_names)
}

#[test]
fn test_map_peek_infers_prior_map_define_kind_when_kind_is_omitted() {
    let (hir, decl_names) = declared_queue_map_take_hir(DeclId::new(43), "map-peek");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-peek should infer the declared queue map kind");

    let map_ref = MapRef {
        name: "recent_pids".to_string(),
        kind: MapKind::Queue,
    };
    assert_eq!(
        result.generic_map_value_types.get(&map_ref),
        Some(&MirType::I64)
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::LoadMapFd { map, .. } if map == &map_ref))
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
}

#[test]
fn test_map_pop_infers_prior_map_define_kind_when_kind_is_omitted() {
    let (hir, decl_names) = declared_queue_map_take_hir(DeclId::new(43), "map-pop");
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-pop should infer the declared queue map kind");

    let map_ref = MapRef {
        name: "recent_pids".to_string(),
        kind: MapKind::Queue,
    };
    assert_eq!(
        result.generic_map_value_types.get(&map_ref),
        Some(&MirType::I64)
    );
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .any(|inst| matches!(inst, MirInst::LoadMapFd { map, .. } if map == &map_ref))
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
                    if *helper == BpfHelper::MapPopElem as u32 && args.len() == 2
            ))
    );
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
        (
            "array-of-maps",
            "map-put is not supported for map-in-map outer map",
        ),
        (
            "hash-of-maps",
            "map-put is not supported for map-in-map outer map",
        ),
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
fn test_lower_map_delete_rejects_bloom_filter_kind() {
    let hir = make_map_delete_program(DeclId::new(42), "bloom-filter");
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
    .expect_err("bloom-filter map-delete should be rejected during lowering");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(
                msg.contains("map-delete --kind bloom-filter is not deletable"),
                "{msg}"
            );
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
                        pipeline_input: Some(RegId::new(10)),
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
fn test_map_define_key_type_materializes_fixed_record_array_source_list_key() {
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
                    lit: HirLiteral::String("typed_array_keys".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(1),
                    lit: HirLiteral::String("hash".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(2),
                    lit: HirLiteral::String("array{record{pid:int,cpu:int}:2}".into()),
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
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::List { capacity: 2 },
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
                    lit: HirLiteral::Int(7),
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
                    lit: HirLiteral::Int(2),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(6),
                    key: RegId::new(9),
                    val: RegId::new(10),
                },
                HirStmt::ListPush {
                    src_dst: RegId::new(5),
                    item: RegId::new(6),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(11),
                    lit: HirLiteral::Record { capacity: 2 },
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(12),
                    lit: HirLiteral::String("pid".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(13),
                    lit: HirLiteral::Int(9),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(11),
                    key: RegId::new(12),
                    val: RegId::new(13),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(14),
                    lit: HirLiteral::String("cpu".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(15),
                    lit: HirLiteral::Int(3),
                },
                HirStmt::RecordInsert {
                    src_dst: RegId::new(11),
                    key: RegId::new(14),
                    val: RegId::new(15),
                },
                HirStmt::ListPush {
                    src_dst: RegId::new(5),
                    item: RegId::new(11),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(16),
                    lit: HirLiteral::Int(42),
                },
                HirStmt::Call {
                    decl_id: map_put_decl,
                    src_dst: RegId::new(16),
                    args: HirCallArgs {
                        positional: vec![RegId::new(0), RegId::new(5)],
                        named: vec![(b"kind".to_vec(), RegId::new(1))],
                        pipeline_input: Some(RegId::new(16)),
                        ..HirCallArgs::default()
                    },
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
        register_count: 17,
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
    .expect("map-define fixed record-array key schema should lower");

    let expected_key_ty = MirType::Array {
        elem: Box::new(MirType::Struct {
            name: None,
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "pid".to_string(),
                    ty: MirType::I64,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "cpu".to_string(),
                    ty: MirType::I64,
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        }),
        len: 2,
    };
    let map_ref = MapRef {
        name: "typed_array_keys".to_string(),
        kind: MapKind::Hash,
    };
    assert_eq!(
        result.generic_map_key_types.get(&map_ref),
        Some(&expected_key_ty)
    );

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
        .expect("expected typed-array-key map update");
    assert_eq!(
        result.type_hints.main.get(&key_vreg),
        Some(&MirType::Ptr {
            pointee: Box::new(expected_key_ty),
            address_space: AddressSpace::Stack,
        })
    );
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
        "compile-time map key list-of-record builders must not emit runtime list operations"
    );
}

#[test]
fn test_fixed_record_array_source_list_key_requires_declared_key_type() {
    let map_put_decl = DeclId::new(42);
    let decl_names = HashMap::from([(map_put_decl, "map-put".to_string())]);

    let func = HirFunction {
        blocks: vec![HirBlock {
            id: HirBlockId(0),
            stmts: vec![
                HirStmt::LoadLiteral {
                    dst: RegId::new(0),
                    lit: HirLiteral::List { capacity: 1 },
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
                    lit: HirLiteral::String("missing_key_schema".into()),
                },
                HirStmt::LoadLiteral {
                    dst: RegId::new(5),
                    lit: HirLiteral::Int(42),
                },
                HirStmt::Call {
                    decl_id: map_put_decl,
                    src_dst: RegId::new(5),
                    args: HirCallArgs {
                        positional: vec![RegId::new(4), RegId::new(0)],
                        pipeline_input: Some(RegId::new(5)),
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
    .expect_err("aggregate map keys should require an explicit key type");

    assert!(
        err.to_string()
            .contains("requires a prior map-define --key-type declaration")
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
fn test_map_get_infers_prior_map_define_kind_when_kind_is_omitted() {
    let map_get_decl = DeclId::new(42);
    let (mut hir, mut decl_names) = map_define_with_max_entries_hir(128, "array");
    decl_names.insert(map_get_decl, "map-get".to_string());

    let block = &mut hir.main.blocks[0];
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(5),
        lit: HirLiteral::Int(0),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_get_decl,
        src_dst: RegId::new(5),
        args: HirCallArgs {
            positional: vec![RegId::new(0)],
            ..HirCallArgs::default()
        },
    });
    block.terminator = HirTerminator::Return { src: RegId::new(5) };
    hir.main.register_count = 6;

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-get should infer the declared array map kind");

    let expected = MapRef {
        name: "small_map".to_string(),
        kind: MapKind::Array,
    };
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(inst, MirInst::MapLookup { map, .. } if *map == expected)),
        "map-get without --kind should use the prior map-define kind"
    );
}

#[test]
fn test_map_get_accepts_declared_map_in_map_when_kind_is_omitted() {
    let map_get_decl = DeclId::new(42);
    let (mut hir, mut decl_names) = map_define_map_in_map_hir("array-of-maps", true, false, false);
    decl_names.insert(map_get_decl, "map-get".to_string());

    let block = &mut hir.main.blocks[0];
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(12),
        lit: HirLiteral::Int(0),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_get_decl,
        src_dst: RegId::new(12),
        args: HirCallArgs {
            positional: vec![RegId::new(5)],
            ..HirCallArgs::default()
        },
    });
    block.terminator = HirTerminator::Return {
        src: RegId::new(12),
    };
    hir.main.register_count = 13;

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-get should infer the declared map-in-map kind");

    let expected = MapRef {
        name: "outer".to_string(),
        kind: MapKind::ArrayOfMaps,
    };
    let outer_lookup_dst = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .find_map(|inst| match inst {
            MirInst::MapLookup { dst, map, .. } if *map == expected => Some(*dst),
            _ => None,
        })
        .expect("expected outer map-in-map lookup");
    assert!(
        result
            .type_hints
            .main
            .get(&outer_lookup_dst)
            .is_some_and(MirType::is_bpf_map_ptr),
        "outer map-in-map lookup should produce a bpf_map kernel pointer"
    );
}

#[test]
fn test_map_get_on_map_in_map_result_lowers_dynamic_inner_lookup() {
    let map_get_decl = DeclId::new(42);
    let (mut hir, mut decl_names) = map_define_map_in_map_hir("array-of-maps", true, false, false);
    decl_names.insert(map_get_decl, "map-get".to_string());

    let block = &mut hir.main.blocks[0];
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(12),
        lit: HirLiteral::Int(0),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_get_decl,
        src_dst: RegId::new(12),
        args: HirCallArgs {
            positional: vec![RegId::new(5)],
            ..HirCallArgs::default()
        },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(13),
        lit: HirLiteral::Int(7),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_get_decl,
        src_dst: RegId::new(13),
        args: HirCallArgs {
            positional: vec![RegId::new(12)],
            ..HirCallArgs::default()
        },
    });
    block.terminator = HirTerminator::Return {
        src: RegId::new(13),
    };
    hir.main.register_count = 14;

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("dynamic map-get through map-in-map result should lower");

    let expected_inner = MapRef {
        name: "inner".to_string(),
        kind: MapKind::Hash,
    };
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::MapLookupDynamic { inner_map, .. } if *inner_map == expected_inner
            )),
        "expected dynamic lookup through the inner map template"
    );
}

#[test]
fn test_map_put_on_map_in_map_result_lowers_dynamic_inner_update() {
    let map_get_decl = DeclId::new(42);
    let map_put_decl = DeclId::new(43);
    let (mut hir, mut decl_names) = map_define_map_in_map_hir("array-of-maps", true, false, false);
    decl_names.insert(map_get_decl, "map-get".to_string());
    decl_names.insert(map_put_decl, "map-put".to_string());
    if let HirStmt::LoadLiteral { lit, .. } = &mut hir.main.blocks[0].stmts[2] {
        *lit = HirLiteral::String("int".into());
    }

    let block = &mut hir.main.blocks[0];
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(12),
        lit: HirLiteral::Int(0),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_get_decl,
        src_dst: RegId::new(12),
        args: HirCallArgs {
            positional: vec![RegId::new(5)],
            ..HirCallArgs::default()
        },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(13),
        lit: HirLiteral::Int(7),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(14),
        lit: HirLiteral::Int(99),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_put_decl,
        src_dst: RegId::new(14),
        args: HirCallArgs {
            positional: vec![RegId::new(12), RegId::new(13)],
            pipeline_input: Some(RegId::new(14)),
            ..HirCallArgs::default()
        },
    });
    block.terminator = HirTerminator::Return {
        src: RegId::new(14),
    };
    hir.main.register_count = 15;

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("dynamic map-put through map-in-map result should lower");

    let expected_inner = MapRef {
        name: "inner".to_string(),
        kind: MapKind::Hash,
    };
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::MapUpdateDynamic { inner_map, .. } if *inner_map == expected_inner
            )),
        "expected dynamic update through the inner map template"
    );
}

#[test]
fn test_map_delete_on_map_in_map_result_lowers_dynamic_inner_delete() {
    let map_get_decl = DeclId::new(42);
    let map_delete_decl = DeclId::new(43);
    let (mut hir, mut decl_names) = map_define_map_in_map_hir("array-of-maps", true, false, false);
    decl_names.insert(map_get_decl, "map-get".to_string());
    decl_names.insert(map_delete_decl, "map-delete".to_string());

    let block = &mut hir.main.blocks[0];
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(12),
        lit: HirLiteral::Int(0),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_get_decl,
        src_dst: RegId::new(12),
        args: HirCallArgs {
            positional: vec![RegId::new(5)],
            ..HirCallArgs::default()
        },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(13),
        lit: HirLiteral::Int(7),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_delete_decl,
        src_dst: RegId::new(13),
        args: HirCallArgs {
            positional: vec![RegId::new(12)],
            ..HirCallArgs::default()
        },
    });
    block.terminator = HirTerminator::Return {
        src: RegId::new(13),
    };
    hir.main.register_count = 14;

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("dynamic map-delete through map-in-map result should lower");

    let expected_inner = MapRef {
        name: "inner".to_string(),
        kind: MapKind::Hash,
    };
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::MapDeleteDynamic { inner_map, .. } if *inner_map == expected_inner
            )),
        "expected dynamic delete through the inner map template"
    );

    let mut delete_key_and_result = None;
    let mut pending_delete_key = None;
    for inst in result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
    {
        match inst {
            MirInst::MapDeleteDynamic { inner_map, key, .. } if *inner_map == expected_inner => {
                pending_delete_key = Some(*key);
            }
            MirInst::Copy {
                dst,
                src: MirValue::Const(0),
            } if pending_delete_key.is_some() => {
                delete_key_and_result = pending_delete_key.map(|key| (key, *dst));
                break;
            }
            _ => {}
        }
    }
    let (key_vreg, result_vreg) =
        delete_key_and_result.expect("expected dynamic delete result copy");
    assert_ne!(
        key_vreg, result_vreg,
        "dynamic map-delete must not reuse the key vreg for its integer result"
    );
}

#[test]
fn test_map_contains_accepts_declared_map_in_map_outer() {
    let map_contains_decl = DeclId::new(42);
    let (mut hir, mut decl_names) = map_define_map_in_map_hir("array-of-maps", true, false, false);
    decl_names.insert(map_contains_decl, "map-contains".to_string());

    let block = &mut hir.main.blocks[0];
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(12),
        lit: HirLiteral::Int(0),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_contains_decl,
        src_dst: RegId::new(12),
        args: HirCallArgs {
            positional: vec![RegId::new(5)],
            ..HirCallArgs::default()
        },
    });
    block.terminator = HirTerminator::Return {
        src: RegId::new(12),
    };
    hir.main.register_count = 13;

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-contains should lower for map-in-map outer maps");

    let expected_outer = MapRef {
        name: "outer".to_string(),
        kind: MapKind::ArrayOfMaps,
    };
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::MapLookup { map, .. } if *map == expected_outer
            )),
        "expected map-in-map outer map lookup for membership"
    );
}

#[test]
fn test_map_contains_on_map_in_map_result_lowers_dynamic_inner_lookup() {
    let map_get_decl = DeclId::new(42);
    let map_contains_decl = DeclId::new(43);
    let (mut hir, mut decl_names) = map_define_map_in_map_hir("array-of-maps", true, false, false);
    decl_names.insert(map_get_decl, "map-get".to_string());
    decl_names.insert(map_contains_decl, "map-contains".to_string());

    let block = &mut hir.main.blocks[0];
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(12),
        lit: HirLiteral::Int(0),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_get_decl,
        src_dst: RegId::new(12),
        args: HirCallArgs {
            positional: vec![RegId::new(5)],
            ..HirCallArgs::default()
        },
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(13),
        lit: HirLiteral::Int(7),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_contains_decl,
        src_dst: RegId::new(13),
        args: HirCallArgs {
            positional: vec![RegId::new(12)],
            ..HirCallArgs::default()
        },
    });
    block.terminator = HirTerminator::Return {
        src: RegId::new(13),
    };
    hir.main.register_count = 14;

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("dynamic map-contains through map-in-map result should lower");

    let expected_inner = MapRef {
        name: "inner".to_string(),
        kind: MapKind::Hash,
    };
    assert!(
        result
            .program
            .main
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|inst| matches!(
                inst,
                MirInst::MapLookupDynamic { inner_map, .. } if *inner_map == expected_inner
            )),
        "expected dynamic lookup through the inner map template for membership"
    );

    let mut contains_key_and_result = None;
    let mut pending_lookup_key = None;
    for inst in result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
    {
        match inst {
            MirInst::MapLookupDynamic { inner_map, key, .. } if *inner_map == expected_inner => {
                pending_lookup_key = Some(*key);
            }
            MirInst::BinOp {
                dst,
                op: BinOpKind::Ne,
                ..
            } if pending_lookup_key.is_some() => {
                contains_key_and_result = pending_lookup_key.map(|key| (key, *dst));
                break;
            }
            _ => {}
        }
    }
    let (key_vreg, result_vreg) =
        contains_key_and_result.expect("expected dynamic contains result comparison");
    assert_ne!(
        key_vreg, result_vreg,
        "dynamic map-contains must not reuse the key vreg for its bool result"
    );
}

#[test]
fn test_map_get_rejects_kind_that_conflicts_with_prior_map_define() {
    let map_get_decl = DeclId::new(42);
    let (mut hir, mut decl_names) = map_define_with_max_entries_hir(128, "array");
    decl_names.insert(map_get_decl, "map-get".to_string());

    let block = &mut hir.main.blocks[0];
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(5),
        lit: HirLiteral::Int(0),
    });
    block.stmts.push(HirStmt::LoadLiteral {
        dst: RegId::new(6),
        lit: HirLiteral::String("hash".into()),
    });
    block.stmts.push(HirStmt::Call {
        decl_id: map_get_decl,
        src_dst: RegId::new(5),
        args: HirCallArgs {
            positional: vec![RegId::new(0)],
            named: vec![(b"kind".to_vec(), RegId::new(6))],
            ..HirCallArgs::default()
        },
    });
    block.terminator = HirTerminator::Return { src: RegId::new(5) };
    hir.main.register_count = 7;

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let err = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("explicit --kind should not conflict with prior map-define kind");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(msg.contains("--kind hash conflicts"), "{msg}");
            assert!(msg.contains("small_map"), "{msg}");
            assert!(msg.contains("array"), "{msg}");
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_map_define_array_of_maps_accepts_declared_inner_template_contract() {
    let (hir, decl_names) = map_define_map_in_map_hir("array-of-maps", true, false, false);
    let result = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("array-of-maps map-define should accept explicit inner-map metadata contract");

    let inner_ref = MapRef {
        name: "inner".to_string(),
        kind: MapKind::Hash,
    };
    let outer_ref = MapRef {
        name: "outer".to_string(),
        kind: MapKind::ArrayOfMaps,
    };
    assert_eq!(
        result.generic_map_value_types.get(&inner_ref),
        Some(&MirType::U64)
    );
    assert_eq!(result.generic_map_max_entries.get(&inner_ref), Some(&16));
    assert_eq!(result.generic_map_max_entries.get(&outer_ref), Some(&4));
    assert_eq!(
        result.generic_map_inner_templates.get(&outer_ref),
        Some(&inner_ref)
    );
    assert_eq!(
        result
            .type_hints
            .generic_map_inner_templates
            .get(&outer_ref),
        Some(&inner_ref)
    );
    assert!(result.type_hints.declared_generic_maps.contains(&inner_ref));
    assert!(result.type_hints.declared_generic_maps.contains(&outer_ref));
    assert!(
        !result.generic_map_value_types.contains_key(&outer_ref),
        "map-in-map outer value layout is defined by --inner-map, not --value-type"
    );
}

#[test]
fn test_external_map_in_map_inner_template_is_preserved() {
    let (hir, decl_names) = map_define_with_value_type_hir("inner", "hash", "u64");
    let inner_ref = MapRef {
        name: "inner".to_string(),
        kind: MapKind::Hash,
    };
    let outer_ref = MapRef {
        name: "outer".to_string(),
        kind: MapKind::ArrayOfMaps,
    };
    let external_inner_templates = HashMap::from([(outer_ref.clone(), inner_ref.clone())]);

    let result = lower_hir_to_mir_with_hints_key_value_maps_and_semantics(
        &hir,
        None,
        &decl_names,
        None,
        None,
        None,
        Some(&external_inner_templates),
        None,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("pinned map-in-map template metadata should seed lowering");

    assert_eq!(
        result.generic_map_inner_templates.get(&outer_ref),
        Some(&inner_ref)
    );
    assert_eq!(
        result
            .type_hints
            .generic_map_inner_templates
            .get(&outer_ref),
        Some(&inner_ref)
    );
    assert!(
        !result.type_hints.declared_generic_maps.contains(&outer_ref),
        "externally seeded map-in-map metadata should not emit a source-declared runtime map"
    );
}

#[test]
fn test_map_define_map_in_map_rejects_conflicting_external_inner_template() {
    let (hir, decl_names) = map_define_map_in_map_hir("array-of-maps", true, false, false);
    let outer_ref = MapRef {
        name: "outer".to_string(),
        kind: MapKind::ArrayOfMaps,
    };
    let pinned_inner_ref = MapRef {
        name: "pinned_inner".to_string(),
        kind: MapKind::Hash,
    };
    let external_inner_templates = HashMap::from([(outer_ref, pinned_inner_ref)]);

    let err = lower_hir_to_mir_with_hints_key_value_maps_and_semantics(
        &hir,
        None,
        &decl_names,
        None,
        None,
        None,
        Some(&external_inner_templates),
        None,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("conflicting pinned map-in-map template should fail");

    assert!(
        err.to_string().contains("conflicts with pinned map schema"),
        "{err}"
    );
}

#[test]
fn test_map_define_map_in_map_requires_inner_map() {
    let (hir, decl_names) = map_define_map_in_map_hir("array-of-maps", false, false, false);
    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("map-in-map outer map should require --inner-map");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(msg.contains("requires --inner-map"), "{msg}");
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_map_define_hash_of_maps_requires_outer_key_type() {
    let (hir, decl_names) = map_define_map_in_map_hir("hash-of-maps", true, false, false);
    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("hash-of-maps outer map should require --key-type");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(msg.contains("requires --key-type"), "{msg}");
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_map_define_map_in_map_rejects_outer_value_type() {
    let (hir, decl_names) = map_define_map_in_map_hir("array-of-maps", true, false, true);
    let err = lower_hir_to_mir_with_hints(
        &hir,
        None,
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect_err("map-in-map outer map should reject --value-type");

    match err {
        CompileError::UnsupportedInstruction(msg) => {
            assert!(msg.contains("--value-type is not supported"), "{msg}");
            assert!(msg.contains("--inner-map"), "{msg}");
        }
        other => panic!("unexpected lowering error: {other:?}"),
    }
}

#[test]
fn test_map_define_graph_root_schema_registers_value_type() {
    let (hir, decl_names) = map_define_with_value_type_hir(
        "graph_items",
        "hash",
        "record{root:bpf_list_head:node_data:node,cookie:u64}",
    );
    let map_ref = MapRef {
        name: "graph_items".to_string(),
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
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("map-define graph root schema should lower");

    let value_ty = result
        .generic_map_value_types
        .get(&map_ref)
        .expect("map-define should register a graph root value schema");
    let MirType::Struct { fields, .. } = value_ty else {
        panic!("expected record value schema, got {value_ty:?}");
    };
    let root = fields
        .iter()
        .find(|field| field.name == "root")
        .and_then(|field| field.ty.bpf_graph_root_info())
        .expect("root field should carry graph contains metadata");
    assert_eq!(root.kind, BpfGraphRootKind::ListHead);
    assert_eq!(root.value_type, "node_data");
    assert_eq!(root.node_field, "node");
    assert_eq!(
        result.type_hints.generic_map_value_types.get(&map_ref),
        Some(value_ty)
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
                        pipeline_input: Some(RegId::new(7)),
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
fn test_map_key_type_spec_supports_fixed_array_bytes() {
    let ty = HirToMirLowering::parse_named_map_key_type_spec("array{bytes:4:2}")
        .expect("fixed-array bytes map key type should parse");

    assert_eq!(
        ty,
        MirType::Array {
            elem: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 4,
            }),
            len: 2,
        }
    );
}

#[test]
fn test_map_key_type_spec_supports_fixed_array_string() {
    let ty = HirToMirLowering::parse_named_map_key_type_spec("array{string:8:2}")
        .expect("fixed-array string map key type should parse");

    assert_eq!(
        ty,
        MirType::Array {
            elem: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 24,
            }),
            len: 2,
        }
    );
}

#[test]
fn test_map_key_type_spec_supports_fixed_array_numeric_list() {
    let ty = HirToMirLowering::parse_named_map_key_type_spec("array{list:int:2:2}")
        .expect("fixed-array numeric-list map key type should parse");

    assert_eq!(
        ty,
        MirType::Array {
            elem: Box::new(MirType::Array {
                elem: Box::new(MirType::I64),
                len: 3,
            }),
            len: 2,
        }
    );
}

#[test]
fn test_map_key_type_spec_supports_record_fixed_array_numeric_list_field() {
    let ty = HirToMirLowering::parse_named_map_key_type_spec(
        "record{sets:array{list:int:2:2},pid:int}",
    )
    .expect("record key with fixed-array numeric-list field should parse");

    assert_eq!(
        ty,
        MirType::Struct {
            name: None,
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "sets".to_string(),
                    ty: MirType::Array {
                        elem: Box::new(MirType::Array {
                            elem: Box::new(MirType::I64),
                            len: 3,
                        }),
                        len: 2,
                    },
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "pid".to_string(),
                    ty: MirType::I64,
                    offset: 48,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        }
    );
}

#[test]
fn test_map_value_type_spec_supports_fixed_array_string_semantics() {
    let (ty, semantics) = HirToMirLowering::parse_named_map_value_type_spec("array{string:8:2}")
        .expect("fixed-array string map value type should parse");

    assert_eq!(
        ty,
        MirType::Array {
            elem: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 24,
            }),
            len: 2,
        }
    );
    assert_eq!(
        semantics,
        Some(AnnotatedValueSemantics::FixedArray {
            elem: Box::new(AnnotatedValueSemantics::String {
                slot_len: 16,
                content_cap: 8,
            }),
            len: 2,
        })
    );
}

#[test]
fn test_map_value_type_spec_supports_fixed_array_numeric_list_semantics() {
    let (ty, semantics) = HirToMirLowering::parse_named_map_value_type_spec("array{list:int:4:2}")
        .expect("fixed-array numeric-list map value type should parse");

    assert_eq!(
        ty,
        MirType::Array {
            elem: Box::new(MirType::Array {
                elem: Box::new(MirType::I64),
                len: 5,
            }),
            len: 2,
        }
    );
    assert_eq!(
        semantics,
        Some(AnnotatedValueSemantics::FixedArray {
            elem: Box::new(AnnotatedValueSemantics::NumericList {
                max_len: 4,
                known_len: None,
            }),
            len: 2,
        })
    );
}

#[test]
fn test_declared_map_value_semantics_accepts_fixed_record_array_known_list_length() {
    let (_, declared) = HirToMirLowering::parse_named_map_value_type_spec(
        "array{record{id:int,samples:list:int:2}:2}",
    )
    .expect("fixed-array record map value type should parse");
    let declared = declared.expect("declared fixed-array record should carry list semantics");
    let observed = AnnotatedValueSemantics::FixedArray {
        elem: Box::new(AnnotatedValueSemantics::Record(vec![(
            "samples".to_string(),
            AnnotatedValueSemantics::NumericList {
                max_len: 2,
                known_len: Some(2),
            },
        )])),
        len: 2,
    };

    assert!(
        HirToMirLowering::merge_annotated_value_semantics(&declared, &observed).is_some(),
        "declared map value semantics should accept compatible literal list lengths"
    );
}

#[test]
fn test_map_value_type_spec_rejects_fixed_array_kptr_element() {
    let err = HirToMirLowering::parse_named_map_value_type_spec("array{kptr:task_struct:2}")
        .expect_err("fixed arrays of kptr slots should remain unsupported");

    assert!(
        err.to_string()
            .contains("elements that can be embedded in fixed arrays"),
        "unexpected error: {err}"
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
fn test_map_value_type_spec_supports_bpf_refcount() {
    let (ty, semantics) =
        HirToMirLowering::parse_named_map_value_type_spec("record{refs:bpf_refcount,counter:u64}")
            .expect("bpf_refcount map value type should parse");

    assert!(semantics.is_none());
    let MirType::Struct { fields, .. } = ty else {
        panic!("expected record map value type, got {ty:?}");
    };
    let user_fields = fields
        .iter()
        .filter(|field| !field.synthetic)
        .collect::<Vec<_>>();
    assert_eq!(user_fields.len(), 2);
    assert_eq!(user_fields[0].name, "refs");
    assert_eq!(user_fields[0].ty, MirType::bpf_refcount_struct());
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
fn test_map_value_type_spec_supports_graph_root_schema() {
    let (ty, semantics) = HirToMirLowering::parse_named_map_value_type_spec(
        "record{root:bpf_list_head:node_data:node,counter:u64}",
    )
    .expect("graph root map value type should parse");

    assert!(semantics.is_none());
    let MirType::Struct { fields, .. } = ty else {
        panic!("expected record map value type, got {ty:?}");
    };
    let user_fields = fields
        .iter()
        .filter(|field| !field.synthetic)
        .collect::<Vec<_>>();
    assert_eq!(user_fields.len(), 2);
    assert_eq!(user_fields[0].name, "root");
    assert_eq!(
        user_fields[0].ty,
        MirType::bpf_list_head_root_struct("node_data", "node")
    );
    let root = user_fields[0]
        .ty
        .bpf_graph_root_info()
        .expect("root should carry contains metadata");
    assert_eq!(root.kind, BpfGraphRootKind::ListHead);
    assert_eq!(root.value_type, "node_data");
    assert_eq!(root.node_field, "node");
    assert_eq!(user_fields[0].offset, 0);
    assert_eq!(user_fields[1].name, "counter");
    assert_eq!(user_fields[1].ty, MirType::U64);
    assert_eq!(user_fields[1].offset, 16);
}

#[test]
fn test_map_value_type_spec_supports_graph_root_payload_schema() {
    let (ty, semantics) = HirToMirLowering::parse_named_map_value_type_spec(
        "record{root:bpf_list_head:node_data:node:record{cookie:u64,refs:bpf_refcount},counter:u64}",
    )
    .expect("graph root object payload schema should parse");

    assert!(semantics.is_none());
    let MirType::Struct { fields, .. } = ty else {
        panic!("expected record map value type, got {ty:?}");
    };
    let root = fields
        .iter()
        .find(|field| field.name == "root")
        .and_then(|field| field.ty.bpf_graph_root_info())
        .expect("root should carry contains metadata");
    assert_eq!(root.kind, BpfGraphRootKind::ListHead);
    assert_eq!(root.value_type, "node_data");
    assert_eq!(root.node_field, "node");

    let object_ty = root
        .object_type
        .expect("root should carry object payload schema");
    let MirType::Struct {
        name: Some(name),
        fields: object_fields,
        ..
    } = object_ty
    else {
        panic!("expected named graph object payload type, got {object_ty:?}");
    };
    assert_eq!(name, "node_data");
    let user_object_fields = object_fields
        .iter()
        .filter(|field| !field.synthetic)
        .collect::<Vec<_>>();
    assert_eq!(user_object_fields.len(), 3);
    assert_eq!(user_object_fields[0].name, "node");
    assert_eq!(user_object_fields[0].ty, MirType::bpf_list_node_struct());
    assert_eq!(user_object_fields[0].offset, 0);
    let payload_base = (BpfGraphRootKind::ListHead.node_size() + 7) & !7;
    assert_eq!(user_object_fields[1].name, "cookie");
    assert_eq!(user_object_fields[1].ty, MirType::U64);
    assert_eq!(user_object_fields[1].offset, payload_base);
    assert_eq!(user_object_fields[2].name, "refs");
    assert_eq!(user_object_fields[2].ty, MirType::bpf_refcount_struct());
    assert_eq!(user_object_fields[2].offset, payload_base + 8);
    assert_eq!(object_ty.size(), payload_base + 16);
}

#[test]
fn test_map_value_type_spec_supports_nested_graph_root_payload_refcount() {
    let (ty, semantics) = HirToMirLowering::parse_named_map_value_type_spec(
        "record{root:bpf_rb_root:rb_item:rb:record{meta:record{refs:bpf_refcount},cookie:u64},counter:u64}",
    )
    .expect("graph root object payload schema should allow nested bpf_refcount fields");

    assert!(semantics.is_none());
    let MirType::Struct { fields, .. } = ty else {
        panic!("expected record map value type, got {ty:?}");
    };
    let root = fields
        .iter()
        .find(|field| field.name == "root")
        .and_then(|field| field.ty.bpf_graph_root_info())
        .expect("root should carry contains metadata");
    assert_eq!(root.kind, BpfGraphRootKind::RbRoot);
    let object_ty = root
        .object_type
        .expect("root should carry object payload schema");
    assert!(
        object_ty.contains_bpf_refcount_struct(),
        "nested graph payload refcount should be visible to refcount acquire checks"
    );
    let MirType::Struct {
        name: Some(name),
        fields: object_fields,
        ..
    } = object_ty
    else {
        panic!("expected named graph object payload type, got {object_ty:?}");
    };
    assert_eq!(name, "rb_item");
    let meta = object_fields
        .iter()
        .find(|field| field.name == "meta")
        .expect("graph payload should include meta record");
    assert!(
        meta.ty.contains_bpf_refcount_struct(),
        "nested meta record should contain bpf_refcount"
    );
}

#[test]
fn test_map_value_type_spec_rejects_graph_root_payload_unmatched_braces_with_context() {
    let err = HirToMirLowering::parse_named_map_value_type_spec(
        "bpf_list_head:node_data:node:record{refs:bpf_refcount",
    )
    .expect_err("graph root payload schema with unmatched braces should reject");

    assert!(
        err.to_string().contains(
            "map value type spec 'bpf_list_head:node_data:node:record{refs:bpf_refcount' has unmatched '{' braces"
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn test_map_value_type_spec_supports_rbtree_root_schema() {
    let (ty, semantics) =
        HirToMirLowering::parse_named_map_value_type_spec("record{root:bpf_rb_root:rb_item:rb}")
            .expect("rbtree root map value type should parse");

    assert!(semantics.is_none());
    let MirType::Struct { fields, .. } = ty else {
        panic!("expected record map value type, got {ty:?}");
    };
    let root = fields
        .iter()
        .find(|field| field.name == "root")
        .and_then(|field| field.ty.bpf_graph_root_info())
        .expect("rbtree root should carry contains metadata");
    assert_eq!(root.kind, BpfGraphRootKind::RbRoot);
    assert_eq!(root.value_type, "rb_item");
    assert_eq!(root.node_field, "rb");
}

#[test]
fn test_map_value_type_spec_rejects_graph_root_payload_duplicate_node_field() {
    let err = HirToMirLowering::parse_named_map_value_type_spec(
        "record{root:bpf_list_head:node_data:node:record{node:u64,cookie:u64}}",
    )
    .expect_err("graph object payload should not redeclare node field");

    let msg = err.to_string();
    assert!(msg.contains(
        "record field 'root' type spec 'bpf_list_head:node_data:node:record{node:u64,cookie:u64}'"
    ));
    assert!(msg.contains("object payload duplicates node field"));
}

#[test]
fn test_map_value_type_spec_rejects_empty_graph_root_payload_with_path() {
    let err = HirToMirLowering::parse_named_map_value_type_spec(
        "record{root:bpf_list_head:node_data:node:,counter:u64}",
    )
    .expect_err("empty graph object payload schema should be rejected");

    let msg = err.to_string();
    assert!(msg.contains("record field 'root' type spec 'bpf_list_head:node_data:node:'"));
    assert!(msg.contains("empty object payload schema"));
}

#[test]
fn test_map_value_type_spec_rejects_non_record_graph_root_payload_with_path() {
    let err = HirToMirLowering::parse_named_map_value_type_spec(
        "record{root:bpf_rb_root:rb_item:rb:u64,counter:u64}",
    )
    .expect_err("graph object payload schema should be record typed");

    let msg = err.to_string();
    assert!(msg.contains("record field 'root' type spec 'bpf_rb_root:rb_item:rb:u64'"));
    assert!(msg.contains("requires the object payload schema to be record{...}"));
}

#[test]
fn test_map_value_type_spec_rejects_graph_root_payload_refcount_array_with_path() {
    let err = HirToMirLowering::parse_named_map_value_type_spec(
        "record{root:bpf_list_head:node_data:node:record{refs:array{bpf_refcount:2},cookie:u64},counter:u64}",
    )
    .expect_err("graph object payload should reject arrays of bpf_refcount fields");

    let msg = err.to_string();
    assert!(msg.contains("record field 'root.refs' type spec 'array{bpf_refcount:2}'"));
    assert!(msg.contains("arrays of verifier-managed bpf_refcount fields are not supported"));
}

#[test]
fn test_map_value_type_spec_rejects_top_level_graph_root_payload_refcount_array_with_path() {
    let err = HirToMirLowering::parse_named_map_value_type_spec(
        "bpf_list_head:node_data:node:record{refs:array{bpf_refcount:2},cookie:u64}",
    )
    .expect_err("top-level graph object payload should reject arrays of bpf_refcount fields");

    let msg = err.to_string();
    assert!(msg.contains("record field 'refs' type spec 'array{bpf_refcount:2}'"));
    assert!(msg.contains("arrays of verifier-managed bpf_refcount fields are not supported"));
}

#[test]
fn test_map_value_type_spec_rejects_nested_graph_root_payload_refcount_array_with_path() {
    let err = HirToMirLowering::parse_named_map_value_type_spec(
        "record{root:bpf_rb_root:rb_item:rb:record{nested:record{refs:array{bpf_refcount:2}},cookie:u64},counter:u64}",
    )
    .expect_err("nested graph object payload should reject arrays of bpf_refcount fields");

    let msg = err.to_string();
    assert!(msg.contains("record field 'root.nested.refs' type spec 'array{bpf_refcount:2}'"));
    assert!(msg.contains("arrays of verifier-managed bpf_refcount fields are not supported"));
}

#[test]
fn test_map_value_type_spec_rejects_bare_graph_root() {
    let err =
        HirToMirLowering::parse_named_map_value_type_spec("record{root:bpf_list_head,counter:u64}")
            .expect_err("bare list root should require named object schema support");

    let msg = err.to_string();
    assert!(msg.contains("record field 'root' type spec 'bpf_list_head'"));
    assert!(msg.contains("named object type schema"));
    assert!(msg.contains("contains:TYPE:FIELD"));
}

#[test]
fn test_map_value_type_spec_rejects_invalid_graph_root_schema() {
    let err = HirToMirLowering::parse_named_map_value_type_spec(
        "record{root:bpf_rb_root:rb-item:rb,counter:u64}",
    )
    .expect_err("invalid graph object type name should be rejected");

    let msg = err.to_string();
    assert!(msg.contains("record field 'root' type spec 'bpf_rb_root:rb-item:rb'"));
    assert!(msg.contains("requires a named object type"));
}

#[test]
fn test_map_value_type_spec_rejects_invalid_graph_root_node_field_with_path() {
    let err = HirToMirLowering::parse_named_map_value_type_spec(
        "record{root:bpf_list_head:node_data:node-field,counter:u64}",
    )
    .expect_err("invalid graph node field name should be rejected");

    let msg = err.to_string();
    assert!(msg.contains("record field 'root' type spec 'bpf_list_head:node_data:node-field'"));
    assert!(msg.contains("requires a valid node field name"));
}

#[test]
fn test_map_value_type_spec_rejects_bare_graph_node() {
    let err =
        HirToMirLowering::parse_named_map_value_type_spec("record{node:bpf_rb_node,counter:u64}")
            .expect_err("bare rbtree node should require named object schema support");

    let msg = err.to_string();
    assert!(msg.contains("record field 'node' type spec 'bpf_rb_node'"));
    assert!(msg.contains("matching bpf_list_node/bpf_rb_node object fields"));
}

#[test]
fn test_map_value_type_spec_rejects_dynptr() {
    let err =
        HirToMirLowering::parse_named_map_value_type_spec("record{dptr:bpf_dynptr,counter:u64}")
            .expect_err("dynptr map value type should be rejected");

    let msg = err.to_string();
    assert!(msg.contains("record field 'dptr' type spec 'bpf_dynptr'"));
    assert!(msg.contains("stack-only verifier state"));
}

#[test]
fn test_map_value_type_validation_rejects_external_dynptr() {
    let ty = manual_map_value_struct(vec![
        manual_map_value_field("dptr", MirType::bpf_dynptr_struct(), 0),
        manual_map_value_field("counter", MirType::U64, 16),
    ]);
    let err = validate_manual_map_value_type_for_kind(ty, MapKind::Hash)
        .expect_err("external dynptr map value schema should be rejected");

    let msg = err.to_string();
    assert!(msg.contains("bpf_dynptr"));
    assert!(msg.contains("stack-only verifier objects"));
}

#[test]
fn test_map_value_type_validation_rejects_direct_graph_root_without_contains_metadata() {
    let ty = manual_map_value_struct(vec![
        manual_map_value_field("root", MirType::bpf_list_head_struct(), 0),
        manual_map_value_field("counter", MirType::U64, 16),
    ]);
    let err = validate_manual_map_value_type_for_kind(ty, MapKind::Hash)
        .expect_err("direct graph root should require contains metadata");

    let msg = err.to_string();
    assert!(msg.contains("bpf_list_head"));
    assert!(msg.contains("contains:TYPE:FIELD"));
}

#[test]
fn test_map_value_type_validation_rejects_direct_graph_node() {
    let ty = manual_map_value_struct(vec![
        manual_map_value_field("node", MirType::bpf_rb_node_struct(), 0),
        manual_map_value_field("counter", MirType::U64, 24),
    ]);
    let err = validate_manual_map_value_type_for_kind(ty, MapKind::Hash)
        .expect_err("direct graph node should require named object schema support");

    let msg = err.to_string();
    assert!(msg.contains("bpf_rb_node"));
    assert!(msg.contains("bpf_list_node/bpf_rb_node"));
}

#[test]
fn test_map_value_type_validation_accepts_internal_graph_root_with_contains_metadata() {
    let ty = manual_map_value_struct(vec![
        manual_map_value_field(
            "root",
            MirType::bpf_list_head_root_struct("node_data", "node"),
            0,
        ),
        manual_map_value_field("counter", MirType::U64, 16),
    ]);

    validate_manual_map_value_type_for_kind(ty, MapKind::Hash)
        .expect("internal graph root wrapper should carry contains metadata");
}

#[test]
fn test_map_value_type_validation_rejects_nested_graph_root() {
    let ty = manual_map_value_struct(vec![manual_map_value_field(
        "nested",
        manual_map_value_struct(vec![manual_map_value_field(
            "root",
            MirType::bpf_rb_root_struct_with_contains("node_data", "node"),
            0,
        )]),
        0,
    )]);
    let err = validate_manual_map_value_type_for_kind(ty, MapKind::Hash)
        .expect_err("nested graph root should be rejected");

    assert!(
        err.to_string()
            .contains("top-level map-value record fields")
    );
}

#[test]
fn test_map_value_type_validation_rejects_misaligned_graph_root() {
    let ty = manual_map_value_struct(vec![
        manual_map_value_field("prefix", MirType::U32, 0),
        manual_map_value_field(
            "root",
            MirType::bpf_list_head_root_struct("node_data", "node"),
            4,
        ),
    ]);
    let err = validate_manual_map_value_type_for_kind(ty, MapKind::Hash)
        .expect_err("misaligned graph root should be rejected");

    assert!(err.to_string().contains("8-byte aligned"));
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
    validate_map_value_type_spec_for_kind("record{refs:bpf_refcount,cookie:u64}", MapKind::LruHash)
        .expect("aligned bpf_refcount in lru hash map should validate");
    validate_map_value_type_spec_for_kind(
        "record{root:bpf_list_head:node_data:node,cookie:u64}",
        MapKind::Hash,
    )
    .expect("graph roots with source contains metadata should be valid for hash maps");
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
fn test_map_value_type_validation_rejects_spin_lock_array() {
    let err = validate_map_value_type_spec_for_kind(
        "record{locks:array{bpf_spin_lock:2},counter:u64}",
        MapKind::Hash,
    )
    .expect_err("arrays of bpf_spin_lock should be rejected");

    assert!(
        err.to_string()
            .contains("arrays of verifier-managed bpf_spin_lock")
    );
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
fn test_map_value_type_validation_rejects_timer_array() {
    let err = validate_map_value_type_spec_for_kind(
        "record{timers:array{bpf_timer:2},counter:u64}",
        MapKind::Hash,
    )
    .expect_err("arrays of bpf_timer should be rejected");

    assert!(
        err.to_string()
            .contains("arrays of verifier-managed bpf_timer")
    );
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
fn test_map_value_type_validation_rejects_refcount_array() {
    let err = validate_map_value_type_spec_for_kind(
        "record{refs:array{bpf_refcount:2},counter:u64}",
        MapKind::Hash,
    )
    .expect_err("arrays of bpf_refcount should be rejected");

    assert!(
        err.to_string()
            .contains("arrays of verifier-managed bpf_refcount")
    );
}

#[test]
fn test_map_value_type_validation_rejects_refcount_on_queue() {
    let err = validate_map_value_type_spec_for_kind(
        "record{refs:bpf_refcount,cookie:u64}",
        MapKind::Queue,
    )
    .expect_err("bpf_refcount on queue should be rejected");

    assert!(
        err.to_string()
            .contains("currently supported for hash, array, and lru-hash")
    );
}

#[test]
fn test_map_value_type_validation_rejects_nested_refcount() {
    let err = validate_map_value_type_spec_for_kind(
        "record{nested:record{refs:bpf_refcount},cookie:u64}",
        MapKind::Hash,
    )
    .expect_err("nested bpf_refcount should be rejected");

    assert!(err.to_string().contains("top-level map-value record field"));
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
fn test_map_value_type_validation_rejects_kptr_array() {
    let ty = manual_map_value_struct(vec![
        manual_map_value_field(
            "tasks",
            MirType::Array {
                elem: Box::new(MirType::bpf_kptr_slot_struct("task_struct")),
                len: 2,
            },
            0,
        ),
        manual_map_value_field("cookie", MirType::U64, 16),
    ]);
    let err = validate_manual_map_value_type_for_kind(ty, MapKind::Array)
        .expect_err("arrays of kptr slots should be rejected");

    assert!(err.to_string().contains("arrays of verifier-managed kptr"));
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

    assert!(err.to_string().contains(
        "record field 'task' type spec 'kptr:task-struct' requires a kernel struct type name"
    ));
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
