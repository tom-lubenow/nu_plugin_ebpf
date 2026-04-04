use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::hir::{
    HirBlock, HirBlockId, HirFunction, HirLiteral, HirProgram, HirStmt, HirTerminator,
};
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::AddressSpace;
use crate::kernel_btf::{KernelBtf, TrampolineFieldSelector, TypeInfo};
use nu_protocol::ast::{CellPath, PathMember};
use nu_protocol::casing::Casing;
use nu_protocol::{DeclId, RegId, Span, VarId};
use std::collections::HashMap;

#[test]
fn test_mir_function_creation() {
    let mut func = MirFunction::new();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    assert_eq!(v0.0, 0);
    assert_eq!(v1.0, 1);
    assert_eq!(func.vreg_count, 2);
}

#[test]
fn test_basic_block_creation() {
    let mut func = MirFunction::new();
    let b0 = func.alloc_block();
    let b1 = func.alloc_block();

    assert_eq!(b0.0, 0);
    assert_eq!(b1.0, 1);
    assert_eq!(func.blocks.len(), 2);
}

#[test]
fn test_list_instructions_creation() {
    // Test that list MIR instructions can be created correctly
    let mut func = MirFunction::new();
    let bb0 = func.alloc_block();
    func.entry = bb0;

    // Allocate virtual registers
    let list_ptr = func.alloc_vreg();
    let item1 = func.alloc_vreg();
    let item2 = func.alloc_vreg();
    let len = func.alloc_vreg();
    let result = func.alloc_vreg();

    // Allocate stack slot for list buffer
    let slot = func.alloc_stack_slot(72, 8, StackSlotKind::ListBuffer); // 8 + 8*8 = 72 bytes

    // Create list instructions
    func.block_mut(bb0).instructions.push(MirInst::ListNew {
        dst: list_ptr,
        buffer: slot,
        max_len: 8,
    });

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: item1,
        src: MirValue::Const(42),
    });

    func.block_mut(bb0).instructions.push(MirInst::ListPush {
        list: list_ptr,
        item: item1,
    });

    func.block_mut(bb0).instructions.push(MirInst::Copy {
        dst: item2,
        src: MirValue::Const(100),
    });

    func.block_mut(bb0).instructions.push(MirInst::ListPush {
        list: list_ptr,
        item: item2,
    });

    func.block_mut(bb0).instructions.push(MirInst::ListLen {
        dst: len,
        list: list_ptr,
    });

    func.block_mut(bb0).instructions.push(MirInst::ListGet {
        dst: result,
        list: list_ptr,
        idx: MirValue::Const(0),
    });

    func.block_mut(bb0).terminator = MirInst::Return {
        val: Some(MirValue::VReg(result)),
    };

    // Verify instructions were created
    assert_eq!(func.block(bb0).instructions.len(), 7);

    // Verify list instructions have correct structure
    match &func.block(bb0).instructions[0] {
        MirInst::ListNew {
            dst,
            buffer,
            max_len,
        } => {
            assert_eq!(*dst, list_ptr);
            assert_eq!(*buffer, slot);
            assert_eq!(*max_len, 8);
        }
        _ => panic!("Expected ListNew instruction"),
    }

    match &func.block(bb0).instructions[2] {
        MirInst::ListPush { list, item } => {
            assert_eq!(*list, list_ptr);
            assert_eq!(*item, item1);
        }
        _ => panic!("Expected ListPush instruction"),
    }

    match &func.block(bb0).instructions[5] {
        MirInst::ListLen { dst, list } => {
            assert_eq!(*dst, len);
            assert_eq!(*list, list_ptr);
        }
        _ => panic!("Expected ListLen instruction"),
    }

    match &func.block(bb0).instructions[6] {
        MirInst::ListGet { dst, list, idx } => {
            assert_eq!(*dst, result);
            assert_eq!(*list, list_ptr);
            match idx {
                MirValue::Const(0) => {}
                _ => panic!("Expected constant index 0"),
            }
        }
        _ => panic!("Expected ListGet instruction"),
    }
}

#[test]
fn test_list_def_and_uses() {
    // Test that list instructions correctly report definitions and uses
    let mut func = MirFunction::new();
    let list_ptr = func.alloc_vreg();
    let item = func.alloc_vreg();
    let len = func.alloc_vreg();
    let result = func.alloc_vreg();
    let slot = func.alloc_stack_slot(72, 8, StackSlotKind::ListBuffer);

    // ListNew defines dst
    let inst = MirInst::ListNew {
        dst: list_ptr,
        buffer: slot,
        max_len: 8,
    };
    assert_eq!(inst.def(), Some(list_ptr));
    assert!(inst.uses().is_empty());

    // ListPush uses both list and item, defines nothing
    let inst = MirInst::ListPush {
        list: list_ptr,
        item,
    };
    assert_eq!(inst.def(), None);
    let uses = inst.uses();
    assert_eq!(uses.len(), 2);
    assert!(uses.contains(&list_ptr));
    assert!(uses.contains(&item));

    // ListLen defines dst, uses list
    let inst = MirInst::ListLen {
        dst: len,
        list: list_ptr,
    };
    assert_eq!(inst.def(), Some(len));
    let uses = inst.uses();
    assert_eq!(uses.len(), 1);
    assert!(uses.contains(&list_ptr));

    // ListGet defines dst, uses list (and maybe idx if VReg)
    let inst = MirInst::ListGet {
        dst: result,
        list: list_ptr,
        idx: MirValue::Const(0),
    };
    assert_eq!(inst.def(), Some(result));
    let uses = inst.uses();
    assert_eq!(uses.len(), 1);
    assert!(uses.contains(&list_ptr));

    // ListGet with VReg index
    let idx_vreg = func.alloc_vreg();
    let inst = MirInst::ListGet {
        dst: result,
        list: list_ptr,
        idx: MirValue::VReg(idx_vreg),
    };
    let uses = inst.uses();
    assert_eq!(uses.len(), 2);
    assert!(uses.contains(&list_ptr));
    assert!(uses.contains(&idx_vreg));
}

fn make_ctx_path_program(path: CellPath) -> HirProgram {
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
                    lit: HirLiteral::CellPath(Box::new(path)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 3],
        ast: vec![None; 3],
        comments: vec![],
        register_count: 2,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

fn make_ctx_path_call_program(path: CellPath, decl_id: DeclId) -> HirProgram {
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
                    lit: HirLiteral::CellPath(Box::new(path)),
                },
                HirStmt::FollowCellPath {
                    src_dst: RegId::new(0),
                    path: RegId::new(1),
                },
                HirStmt::Call {
                    decl_id,
                    src_dst: RegId::new(0),
                    args: HirCallArgs::default(),
                },
            ],
            terminator: HirTerminator::Return { src: RegId::new(0) },
        }],
        entry: HirBlockId(0),
        spans: vec![Span::test_data(); 4],
        ast: vec![None; 4],
        comments: vec![],
        register_count: 2,
        file_count: 0,
    };
    HirProgram::new(func, HashMap::new(), vec![], Some(ctx_var))
}

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
fn test_lower_fentry_aggregate_scalar_field_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("tv_nsec")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "__audit_tk_injoffset");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("aggregate field projection should lower");

    let block = result.program.main.block(result.program.main.entry);
    assert!(block.instructions.iter().any(|inst| matches!(
        inst,
        MirInst::LoadCtxField {
            field: CtxField::Arg(0),
            slot: Some(_),
            ..
        }
    )));
    let load = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::Load { offset, ty, .. } => Some((*offset, ty.clone())),
            _ => None,
        })
        .expect("expected projected field load");
    assert_eq!(load.0, 8);
    assert_eq!(load.1, MirType::I64);
}

#[test]
fn test_lower_fentry_aggregate_pointer_field_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("p")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "__copy_xstate_to_uabi_buf");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("aggregate pointer field projection should lower");

    let block = result.program.main.block(result.program.main.entry);
    let load = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::Load { offset, ty, .. } => Some((*offset, ty.clone())),
            _ => None,
        })
        .expect("expected projected pointer field load");
    assert_eq!(load.0, 0);
    assert_eq!(
        load.1,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        }
    );
}

#[test]
fn test_lower_fexit_aggregate_ret_field_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("retval"), string_member("size")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fexit, "__jump_label_patch");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("aggregate retval field projection should lower");

    let block = result.program.main.block(result.program.main.entry);
    let load = block
        .instructions
        .iter()
        .find_map(|inst| match inst {
            MirInst::Load { offset, ty, .. } => Some((*offset, ty.clone())),
            _ => None,
        })
        .expect("expected projected retval field load");
    assert_eq!(load.0, 8);
    assert_eq!(load.1, MirType::I32);
}

#[test]
fn test_lower_fentry_pointer_root_scalar_field_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("f_flags")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("pointer-root field projection should lower");

    let blocks = &result.program.main.blocks;
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadCtxField {
                    field: CtxField::Arg(0),
                    slot: None,
                    ..
                }
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::CallHelper {
                    helper,
                    ..
                } if *helper == BpfHelper::ProbeReadKernel as u32
            )))
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.instructions.iter().any(|inst| matches!(
                inst,
                MirInst::LoadSlot {
                    ty: MirType::U32,
                    ..
                }
            )))
    );
}

#[test]
fn test_lower_fentry_pointer_hop_scalar_field_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![
            string_member("arg0"),
            string_member("f_inode"),
            string_member("i_ino"),
        ],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("pointer-hop field projection should lower");

    let helper_reads = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
            )
        })
        .count();
    assert!(
        helper_reads >= 2,
        "expected chained kernel reads for intermediate pointer hop"
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
                MirInst::LoadSlot {
                    ty: MirType::Ptr {
                        address_space: AddressSpace::Kernel,
                        ..
                    },
                    ..
                }
            )),
        "expected intermediate pointer load from helper scratch slot"
    );
}

#[test]
fn test_lower_fentry_array_element_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("comm"), int_member(0)],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("array element projection should lower");

    let helper_reads = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
            )
        })
        .count();
    assert!(
        helper_reads >= 1,
        "expected a helper read for pointer-backed array element access"
    );
}

#[test]
fn test_lower_fentry_array_leaf_projection() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("comm")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("array leaf projection should lower");

    let helper_reads = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .filter(|inst| {
            matches!(
                inst,
                MirInst::CallHelper { helper, .. }
                    if *helper == BpfHelper::ProbeReadKernel as u32
            )
        })
        .count();
    assert!(
        helper_reads >= 1,
        "expected a helper read for pointer-backed array leaf access"
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
        "expected array leaf projection to produce a stack-backed pointer"
    );
}

#[test]
fn test_lower_fentry_array_leaf_emit_uses_full_byte_size() {
    let hir = make_ctx_path_call_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("comm")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "emit".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("array leaf emit should lower");

    let emit_size = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::EmitEvent { size, .. } => Some(*size),
            _ => None,
        })
        .expect("expected emit event");
    assert_eq!(emit_size, 16);
}

#[test]
fn test_lower_fentry_array_leaf_count_uses_string_counter_map() {
    let hir = make_ctx_path_call_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("comm")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "wake_up_new_task");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "count".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("array leaf count should lower");

    let map_name = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapUpdate { map, .. } => Some(map.name.as_str()),
            _ => None,
        })
        .expect("expected map update");
    assert_eq!(map_name, "str_counters");
}

#[test]
fn test_lower_fentry_struct_leaf_emit_uses_struct_size() {
    let projection = KernelBtf::get()
        .function_trampoline_arg_field(
            "security_file_open",
            0,
            &[TrampolineFieldSelector::Field("f_path".to_string())],
        )
        .expect("security_file_open f_path projection should resolve")
        .expect("security_file_open arg0.f_path should exist");
    let TypeInfo::Struct { size, .. } = projection.type_info else {
        panic!("expected security_file_open arg0.f_path to resolve to a struct");
    };

    let hir = make_ctx_path_call_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("f_path")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "emit".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("struct leaf emit should lower");

    let emit_size = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::EmitEvent { size, .. } => Some(*size),
            _ => None,
        })
        .expect("expected emit event");
    assert_eq!(emit_size, size);
}

#[test]
fn test_lower_fentry_struct_leaf_preserves_struct_fields() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("f_path")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("struct leaf access should lower");

    let hinted_ty = result
        .type_hints
        .main
        .values()
        .find_map(|ty| match ty {
            MirType::Ptr { pointee, .. } => match pointee.as_ref() {
                MirType::Struct { name, .. } if name.as_deref() == Some("path") => {
                    Some(pointee.as_ref().clone())
                }
                _ => None,
            },
            _ => None,
        })
        .expect("expected struct leaf type hint");

    let MirType::Struct { fields, .. } = hinted_ty else {
        panic!("expected trampoline struct hint");
    };
    assert!(
        fields
            .iter()
            .any(|field| field.name == "mnt" && !field.synthetic)
    );
    assert!(
        fields
            .iter()
            .any(|field| field.name == "dentry" && !field.synthetic)
    );
    assert!(!fields.iter().any(|field| field.name == "__opaque"));
}

#[test]
fn test_lower_fentry_struct_leaf_count_uses_bytes_counter_map() {
    let hir = make_ctx_path_call_program(
        CellPath {
            members: vec![string_member("arg0"), string_member("f_path")],
        },
        DeclId::new(42),
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "security_file_open");
    let mut decl_names = HashMap::new();
    decl_names.insert(DeclId::new(42), "count".to_string());

    let result = lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &decl_names,
        None,
        &HashMap::new(),
        &HashMap::new(),
    )
    .expect("struct leaf count should lower");

    let map_name = result
        .program
        .main
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::MapUpdate { map, .. } => Some(map.name.as_str()),
            _ => None,
        })
        .expect("expected map update");
    assert_eq!(map_name, "bytes_counters");
}

#[test]
fn test_lower_nested_field_access_rejects_nonaggregate_ctx_value() {
    let hir = make_ctx_path_program(CellPath {
        members: vec![string_member("arg0"), string_member("tv_nsec")],
    });
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "ksys_read");

    let err = match lower_hir_to_mir_with_hints(
        &hir,
        Some(&probe_ctx),
        &HashMap::new(),
        None,
        &HashMap::new(),
        &HashMap::new(),
    ) {
        Ok(_) => panic!("non-aggregate trampoline field projection should fail"),
        Err(err) => err,
    };

    assert!(err.to_string().contains(
        "nested ctx field access requires a struct/union trampoline value or pointer to one"
    ));
}
