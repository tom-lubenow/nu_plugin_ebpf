use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::mir::CtxStoreTarget;
use crate::kernel_btf::{KernelBtf, TrampolineValueKind, TypeInfo};

const BPF_SOCK_OPS_RTO_CB: i64 = 8;
const BPF_SOCK_OPS_PARSE_HDR_OPT_CB: i64 = 13;
const BPF_SOCK_OPS_HDR_OPT_LEN_CB: i64 = 14;
const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: i64 = 4;
const BPF_SOCK_OPS_TSTAMP_SCHED_CB: i64 = 16;

fn packet_u8_ptr() -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::U8),
        address_space: AddressSpace::Packet,
    }
}

fn find_aggregate_fentry_arg_candidate() -> (String, u8, usize) {
    for (func_name, arg_idx) in [
        ("__copy_xstate_to_uabi_buf", 0usize),
        ("__audit_tk_injoffset", 0),
    ] {
        let Ok(Some(spec)) = KernelBtf::get().function_trampoline_arg(func_name, arg_idx) else {
            continue;
        };
        if let TrampolineValueKind::Aggregate { size_bytes } = spec.kind {
            return (func_name.to_string(), arg_idx as u8, size_bytes);
        }
    }
    panic!("expected an aggregate fentry candidate on this kernel");
}

fn find_aggregate_fexit_ret_candidate() -> (String, usize) {
    let mut attempts = Vec::new();
    for func_name in ["__jump_label_patch", "__ioapic_read_entry"] {
        match KernelBtf::get().function_trampoline_ret(func_name) {
            Ok(Some(spec)) => {
                if let TrampolineValueKind::Aggregate { size_bytes } = spec.kind {
                    return (func_name.to_string(), size_bytes);
                }
                attempts.push(format!("{func_name}: {:?}", spec.kind));
            }
            Ok(None) => attempts.push(format!("{func_name}: no return value")),
            Err(err) => attempts.push(format!("{func_name}: {err}")),
        }
    }
    panic!(
        "expected an aggregate fexit candidate on this kernel; tried: {}",
        attempts.join(", ")
    );
}

fn find_struct_ops_arg_candidate() -> Option<(String, String)> {
    for (value_type_name, callback_name) in [
        ("sched_ext_ops", "select_cpu"),
        ("tcp_congestion_ops", "cong_avoid"),
        ("tcp_congestion_ops", "init"),
    ] {
        if matches!(
            KernelBtf::get().struct_ops_callback_arg_type_info(value_type_name, callback_name, 0),
            Ok(Some(_))
        ) {
            return Some((value_type_name.to_string(), callback_name.to_string()));
        }
    }
    None
}

fn find_tp_btf_arg_candidate() -> Option<String> {
    for tracepoint_name in [
        "sys_enter",
        "sys_exit",
        "sched_process_exec",
        "sched_process_fork",
    ] {
        if matches!(
            KernelBtf::get().tp_btf_arg_type_info(tracepoint_name, 0),
            Ok(Some(_))
        ) {
            return Some(tracepoint_name.to_string());
        }
    }
    None
}

fn find_tracepoint_pointer_field_candidate() -> Option<(String, String)> {
    for (target, field_name) in [
        ("syscalls/sys_enter_openat", "filename"),
        ("syscalls/sys_enter_openat2", "filename"),
        ("syscalls/sys_enter_execve", "filename"),
    ] {
        let (category, name) = target.split_once('/')?;
        let Ok(ctx) = KernelBtf::get().get_tracepoint_context(category, name) else {
            continue;
        };
        let Some(field) = ctx.get_field(field_name) else {
            continue;
        };
        if field.type_info.is_ptr() {
            return Some((target.to_string(), field_name.to_string()));
        }
    }
    None
}

fn mir_type_from_type_info(type_info: &TypeInfo) -> Option<MirType> {
    match type_info {
        TypeInfo::Int { size, signed } => Some(match (*size, *signed) {
            (1, false) => MirType::U8,
            (1, true) => MirType::I8,
            (2, false) => MirType::U16,
            (2, true) => MirType::I16,
            (4, false) => MirType::U32,
            (4, true) => MirType::I32,
            (8, false) => MirType::U64,
            (8, true) => MirType::I64,
            _ => return None,
        }),
        TypeInfo::Ptr { target, is_user } => Some(MirType::Ptr {
            pointee: Box::new(mir_type_from_type_info(target).unwrap_or(MirType::U8)),
            address_space: if *is_user {
                AddressSpace::User
            } else {
                AddressSpace::Kernel
            },
        }),
        TypeInfo::Array { element, len } => Some(MirType::Array {
            elem: Box::new(mir_type_from_type_info(element)?),
            len: *len,
        }),
        TypeInfo::Struct {
            name,
            btf_type_id,
            fields,
            size,
        } => {
            if *size == 0 {
                return None;
            }
            let byte_array = |len| {
                Some(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len,
                })
            };
            if fields.is_empty() {
                return Some(MirType::Struct {
                    name: Some(name.clone()),
                    kernel_btf_type_id: *btf_type_id,
                    fields: vec![crate::compiler::mir::StructField {
                        name: "__opaque".to_string(),
                        ty: byte_array(*size)?,
                        offset: 0,
                        synthetic: false,
                        bitfield: None,
                    }],
                });
            }
            let mut out = Vec::new();
            let mut cursor = 0usize;
            let mut pad_index = 0usize;
            for field in fields {
                if field.size == 0
                    || field.offset >= *size
                    || (field.offset < cursor && field.bitfield.is_none())
                {
                    continue;
                }
                if field.offset > cursor {
                    out.push(crate::compiler::mir::StructField {
                        name: format!("__layout_pad{}", pad_index),
                        ty: byte_array(field.offset - cursor)?,
                        offset: cursor,
                        synthetic: false,
                        bitfield: None,
                    });
                    pad_index += 1;
                }
                let ty = mir_type_from_type_info(&field.type_info)
                    .or_else(|| byte_array(field.size))
                    .filter(|ty| ty.size() == field.size)
                    .or_else(|| byte_array(field.size))?;
                let field_end = field.offset.checked_add(field.size)?;
                if field_end > *size {
                    continue;
                }
                out.push(crate::compiler::mir::StructField {
                    name: field.name.clone(),
                    ty: ty.clone(),
                    offset: field.offset,
                    synthetic: false,
                    bitfield: field
                        .bitfield
                        .map(|bitfield| crate::compiler::mir::BitfieldInfo {
                            bit_offset: bitfield.bit_offset,
                            bit_size: bitfield.bit_size,
                        }),
                });
                cursor = cursor.max(field_end);
            }
            if out.is_empty() {
                return Some(MirType::Struct {
                    name: Some(name.clone()),
                    kernel_btf_type_id: *btf_type_id,
                    fields: vec![crate::compiler::mir::StructField {
                        name: "__opaque".to_string(),
                        ty: byte_array(*size)?,
                        offset: 0,
                        synthetic: false,
                        bitfield: None,
                    }],
                });
            }
            if cursor < *size {
                out.push(crate::compiler::mir::StructField {
                    name: format!("__layout_pad{}", pad_index),
                    ty: byte_array(*size - cursor)?,
                    offset: cursor,
                    synthetic: false,
                    bitfield: None,
                });
            }
            Some(MirType::Struct {
                name: Some(name.clone()),
                kernel_btf_type_id: *btf_type_id,
                fields: out,
            })
        }
        _ => None,
    }
}

fn expected_runtime_trampoline_type(type_info: &TypeInfo) -> MirType {
    match type_info {
        TypeInfo::Struct { .. } | TypeInfo::Array { .. } => MirType::Ptr {
            pointee: Box::new(
                mir_type_from_type_info(type_info).unwrap_or(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: type_info.size(),
                }),
            ),
            address_space: AddressSpace::Stack,
        },
        _ => mir_type_from_type_info(type_info).unwrap_or(MirType::I64),
    }
}

#[test]
fn test_infer_constant() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0)).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(42),
    });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::I64));
}

#[test]
fn test_infer_ctx_pid() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Pid,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_ctx_numa_node() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::NumaNode,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::I64));
}

#[test]
fn test_infer_tc_egress_helper_backed_ctx_fields() {
    for (field, expected_ty) in [
        (CtxField::CgroupClassid, MirType::U32),
        (CtxField::RouteRealm, MirType::U32),
        (CtxField::SkbCgroupId, MirType::U64),
    ] {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();

        func.block_mut(BlockId(0))
            .instructions
            .push(MirInst::LoadCtxField {
                dst: v0,
                field,
                slot: None,
            });
        func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();

        assert_eq!(types.get(&v0), Some(&expected_ty));
    }
}

#[test]
fn test_infer_ctx_xdp_buff_len() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::XdpBuffLen,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U64));
}

#[test]
fn test_infer_ctx_csum_level() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::CsumLevel,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::I64));
}

#[test]
fn test_infer_ctx_hash_recalc() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::HashRecalc,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_ctx_comm() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Comm,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    assert_eq!(
        types.get(&v0),
        Some(&MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16
            }),
            address_space: AddressSpace::Stack,
        })
    );
}

#[test]
fn test_infer_binop_add() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(10),
    });
    block.instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::Const(20),
    });
    block.instructions.push(MirInst::BinOp {
        dst: v2,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::VReg(v1),
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v2), Some(&MirType::I64));
}

#[test]
fn test_infer_comparison() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: v0,
        field: CtxField::Pid,
        slot: None,
    });
    block.instructions.push(MirInst::BinOp {
        dst: v1,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::Const(1234),
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v1), Some(&MirType::Bool));
}

#[test]
fn test_type_hint_mismatch_errors() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0)).instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(1),
    });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let mut hints = HashMap::new();
    hints.insert(
        v0,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );

    let mut ti = TypeInference::new_with_env(None, None, None, Some(&hints), None);
    assert!(ti.infer(&func).is_err());
}

#[test]
fn test_infer_uprobe_arg_is_user_ptr() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Arg(0),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Uprobe, "test");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    match types.get(&v0) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::User);
        }
        other => panic!("Expected user pointer, got {:?}", other),
    }
}

#[test]
fn test_infer_kprobe_arg_is_int() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Arg(0),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Kprobe, "test");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::I64));
}

#[test]
fn test_type_error_tracepoint_arg_is_rejected() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Arg(0),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Tracepoint, "syscalls/sys_enter_openat");
    let mut ti = TypeInference::new(Some(ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected tracepoint arg field to be rejected");

    assert!(errs.iter().any(|e| {
        e.message
            .contains("ctx.arg0 is only available on contexts with argument access")
    }));
}

#[test]
fn test_infer_perf_event_arg_is_i64() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Arg(0),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
    );
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::I64));
}

#[test]
fn test_infer_tracepoint_id_field_is_concrete_integer() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::TracepointField("id".to_string()),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Tracepoint, "syscalls/sys_enter_openat");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();
    let expected = KernelBtf::get()
        .get_tracepoint_context("syscalls", "sys_enter_openat")
        .unwrap()
        .get_field("id")
        .and_then(|field| mir_type_from_type_info(&field.type_info))
        .expect("expected concrete id field type");

    assert_eq!(types.get(&v0), Some(&expected));
}

#[test]
fn test_infer_tracepoint_filename_field_is_kernel_pointer() {
    let Some((target, field_name)) = find_tracepoint_pointer_field_candidate() else {
        return;
    };
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::TracepointField(field_name.clone()),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Tracepoint, &target);
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();
    let (category, name) = target
        .split_once('/')
        .expect("tracepoint target should include category");
    let expected = KernelBtf::get()
        .get_tracepoint_context(category, name)
        .unwrap()
        .get_field(&field_name)
        .and_then(|field| mir_type_from_type_info(&field.type_info))
        .expect("expected concrete pointer field type");

    assert_eq!(types.get(&v0), Some(&expected));
    assert!(matches!(
        types.get(&v0),
        Some(MirType::Ptr {
            address_space: AddressSpace::Kernel,
            ..
        })
    ));
}

#[test]
fn test_infer_tracepoint_args_field_is_stack_backed_array() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let expected_pointee = KernelBtf::get()
        .get_tracepoint_context("syscalls", "sys_enter_openat")
        .unwrap()
        .get_field("args")
        .and_then(|field| mir_type_from_type_info(&field.type_info))
        .expect("expected concrete args field type");
    let slot = func.alloc_stack_slot(expected_pointee.size(), 8, StackSlotKind::Local);

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::TracepointField("args".to_string()),
            slot: Some(slot),
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Tracepoint, "syscalls/sys_enter_openat");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(
        types.get(&v0),
        Some(&MirType::Ptr {
            pointee: Box::new(expected_pointee),
            address_space: AddressSpace::Stack,
        })
    );
}

#[test]
fn test_type_error_kretprobe_arg_is_rejected() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Arg(0),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Kretprobe, "do_sys_openat2");
    let mut ti = TypeInference::new(Some(ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected kretprobe arg field to be rejected");

    assert!(errs.iter().any(|e| {
        e.message
            .contains("ctx.arg0 is only available on contexts with argument access")
    }));
}

#[test]
fn test_infer_fentry_arg_is_int() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Arg(0),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Fentry, "ksys_read");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();
    let expected = expected_runtime_trampoline_type(
        &KernelBtf::get()
            .function_trampoline_arg_type_info("ksys_read", 0)
            .unwrap()
            .expect("expected ksys_read arg0 type info"),
    );

    assert_eq!(types.get(&v0), Some(&expected));
}

#[test]
fn test_infer_raw_tracepoint_arg_is_u64() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Arg(0),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::RawTracepoint, "sys_enter");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U64));
}

#[test]
fn test_infer_tp_btf_arg_matches_kernel_btf() {
    let Some(tracepoint_name) = find_tp_btf_arg_candidate() else {
        return;
    };

    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Arg(0),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::TpBtf, &tracepoint_name);
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();
    let expected = expected_runtime_trampoline_type(
        &KernelBtf::get()
            .tp_btf_arg_type_info(&tracepoint_name, 0)
            .unwrap()
            .expect("expected tp_btf arg0 type info"),
    );

    assert_eq!(types.get(&v0), Some(&expected));
}

#[test]
fn test_infer_struct_ops_arg_matches_kernel_btf() {
    let Some((value_type_name, callback_name)) = find_struct_ops_arg_candidate() else {
        return;
    };

    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Arg(0),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new_struct_ops_callback(&value_type_name, &callback_name);
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();
    let expected_type_info = KernelBtf::get()
        .struct_ops_callback_arg_type_info(&value_type_name, &callback_name, 0)
        .unwrap()
        .expect("expected struct_ops callback arg0 type info");
    let inferred = types
        .get(&v0)
        .expect("expected inferred type for struct_ops callback arg0");

    match (&expected_type_info, inferred) {
        (
            TypeInfo::Ptr {
                is_user: false,
                target,
                ..
            },
            MirType::Ptr {
                pointee,
                address_space,
            },
        ) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
            if let (
                TypeInfo::Struct { btf_type_id, .. },
                MirType::Struct {
                    kernel_btf_type_id, ..
                },
            ) = (&**target, &**pointee)
            {
                assert_eq!(kernel_btf_type_id, btf_type_id);
            }
        }
        _ => {
            let expected = expected_runtime_trampoline_type(&expected_type_info);
            assert_eq!(inferred, &expected);
        }
    }
}

#[test]
fn test_infer_fentry_pointer_arg_matches_kernel_btf_address_space() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Arg(1),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_sys_openat2");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();
    let expected_user_space = match KernelBtf::get()
        .function_trampoline_arg("do_sys_openat2", 1)
        .unwrap()
    {
        Some(spec) => match spec.kind {
            TrampolineValueKind::Pointer { user_space } => user_space,
            other => {
                panic!("Expected pointer trampoline arg for do_sys_openat2 arg1, got {other:?}")
            }
        },
        None => panic!("Expected do_sys_openat2 arg1 to exist"),
    };

    match types.get(&v0) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(
                *address_space,
                if expected_user_space {
                    AddressSpace::User
                } else {
                    AddressSpace::Kernel
                }
            );
        }
        other => panic!(
            "Expected pointer for fentry do_sys_openat2 ctx.arg1, got {:?}",
            other
        ),
    }
}

#[test]
fn test_infer_lsm_pointer_arg_matches_kernel_btf_address_space() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Arg(0),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Lsm, "file_open");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();
    let expected_user_space = match KernelBtf::get().lsm_hook_arg("file_open", 0).unwrap() {
        Some(spec) => match spec.kind {
            TrampolineValueKind::Pointer { user_space } => user_space,
            other => {
                panic!("Expected pointer trampoline arg for lsm:file_open arg0, got {other:?}")
            }
        },
        None => panic!("Expected lsm:file_open arg0 to exist"),
    };

    match types.get(&v0) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(
                *address_space,
                if expected_user_space {
                    AddressSpace::User
                } else {
                    AddressSpace::Kernel
                }
            );
        }
        other => panic!(
            "Expected pointer for lsm:file_open ctx.arg0, got {:?}",
            other
        ),
    }
}

#[test]
fn test_infer_cgroup_sysctl_write_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SysctlWrite,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_cgroup_sock_family_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Family,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_cgroup_sock_state_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SockState,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_cgroup_sock_remote_port_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::RemotePort,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_cgroup_sock_rx_queue_mapping_field_as_i32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SockRxQueueMapping,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::I32));
}

#[test]
fn test_infer_cgroup_sock_local_port_field_as_u32_on_post_bind() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::LocalPort,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_cgroup_skb_family_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Family,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_cgroup_sock_socket_field_as_kernel_pointer() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert!(matches!(
        types.get(&v0),
        Some(&MirType::Ptr {
            address_space: AddressSpace::Kernel,
            ..
        })
    ));
}

#[test]
fn test_infer_cgroup_sockopt_optname_field_as_i32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SockoptOptname,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::I32));
}

#[test]
fn test_infer_cgroup_sockopt_socket_field_as_kernel_pointer() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert!(matches!(
        types.get(&v0),
        Some(&MirType::Ptr {
            address_space: AddressSpace::Kernel,
            ..
        })
    ));
}

#[test]
fn test_infer_cgroup_sockopt_optval_field_as_kernel_u8_pointer() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SockoptOptval,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(
        types.get(&v0),
        Some(&MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        })
    );
}

#[test]
fn test_infer_sk_lookup_local_port_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::LocalPort,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_cgroup_skb_local_port_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::LocalPort,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_sk_lookup_socket_field_as_kernel_pointer() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert!(matches!(
        types.get(&v0),
        Some(&MirType::Ptr {
            address_space: AddressSpace::Kernel,
            ..
        })
    ));
}

#[test]
fn test_infer_sk_lookup_cookie_field_as_u64() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::LookupCookie,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U64));
}

#[test]
fn test_infer_lirc_mode2_value_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::LircValue,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::LircMode2, "/dev/lirc0");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_sk_lookup_remote_ip6_field_as_stack_backed_u32_array() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::Local);

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::RemoteIp6,
            slot: Some(slot),
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(
        types.get(&v0),
        Some(&MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U32),
                len: 4,
            }),
            address_space: AddressSpace::Stack,
        })
    );
}

#[test]
fn test_infer_sock_ops_op_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SockOp,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_sock_ops_snd_cwnd_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SockOpsSndCwnd,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_sock_ops_snd_nxt_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SockOpsSndNxt,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_sock_ops_skb_hwtstamp_field_rejects_without_packet_aware_callback() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SockOpsSkbHwtstamp,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let err = ti
        .infer(&func)
        .expect_err("expected unguarded sock_ops skb_hwtstamp load to be rejected");

    assert!(err.iter().any(|e| {
        e.message.contains(
            "ctx.skb_hwtstamp on sock_ops requires proving a packet-aware ctx.op callback before use",
        )
    }));
}

#[test]
fn test_infer_sock_ops_bytes_acked_field_as_u64() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SockOpsBytesAcked,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U64));
}

#[test]
fn test_infer_sock_ops_mss_cache_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SockOpsMssCache,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_sock_ops_packet_len_field_rejects_without_packet_aware_callback() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::PacketLen,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let err = ti
        .infer(&func)
        .expect_err("expected unguarded sock_ops packet_len load to be rejected");

    assert!(err.iter().any(|e| {
        e.message.contains(
            "ctx.packet_len on sock_ops requires proving a packet-aware ctx.op callback before use",
        )
    }));
}

#[test]
fn test_infer_sock_ops_packet_len_field_as_u32_when_guarded() {
    let mut func = make_test_function();
    let guarded = func.alloc_block();
    let done = func.alloc_block();
    let op = func.alloc_vreg();
    let matches = func.alloc_vreg();
    let len = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: op,
            field: CtxField::SockOp,
            slot: None,
        });
    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::BinOp {
            dst: matches,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(op),
            rhs: MirValue::Const(BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB),
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Branch {
        cond: matches,
        if_true: guarded,
        if_false: done,
    };

    func.block_mut(guarded)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: len,
            field: CtxField::PacketLen,
            slot: None,
        });
    func.block_mut(guarded).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&len), Some(&MirType::U32));
}

#[test]
fn test_infer_sock_ops_data_field_rejects_for_non_packet_callback() {
    let mut func = make_test_function();
    let guarded = func.alloc_block();
    let done = func.alloc_block();
    let op = func.alloc_vreg();
    let matches = func.alloc_vreg();
    let data = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: op,
            field: CtxField::SockOp,
            slot: None,
        });
    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::BinOp {
            dst: matches,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(op),
            rhs: MirValue::Const(BPF_SOCK_OPS_RTO_CB),
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Branch {
        cond: matches,
        if_true: guarded,
        if_false: done,
    };

    func.block_mut(guarded)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(guarded).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let err = ti
        .infer(&func)
        .expect_err("expected non-packet sock_ops callback to reject ctx.data");

    assert!(err.iter().any(|e| {
        e.message.contains(
            "ctx.data on sock_ops requires proving a packet-aware ctx.op callback before use",
        )
    }));
}

#[test]
fn test_infer_sock_ops_data_field_as_packet_u8_pointer_when_guarded() {
    let mut func = make_test_function();
    let guarded = func.alloc_block();
    let done = func.alloc_block();
    let op = func.alloc_vreg();
    let matches = func.alloc_vreg();
    let data = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: op,
            field: CtxField::SockOp,
            slot: None,
        });
    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::BinOp {
            dst: matches,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(op),
            rhs: MirValue::Const(BPF_SOCK_OPS_PARSE_HDR_OPT_CB),
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Branch {
        cond: matches,
        if_true: guarded,
        if_false: done,
    };

    func.block_mut(guarded)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(guarded).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&data), Some(&packet_u8_ptr()));
}

#[test]
fn test_infer_sock_ops_tcp_flags_field_as_u32_for_hdr_opt_len_callback() {
    let mut func = make_test_function();
    let guarded = func.alloc_block();
    let done = func.alloc_block();
    let op = func.alloc_vreg();
    let matches = func.alloc_vreg();
    let flags = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: op,
            field: CtxField::SockOp,
            slot: None,
        });
    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::BinOp {
            dst: matches,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(op),
            rhs: MirValue::Const(BPF_SOCK_OPS_HDR_OPT_LEN_CB),
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Branch {
        cond: matches,
        if_true: guarded,
        if_false: done,
    };

    func.block_mut(guarded)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: flags,
            field: CtxField::SockOpsSkbTcpFlags,
            slot: None,
        });
    func.block_mut(guarded).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&flags), Some(&MirType::U32));
}

#[test]
fn test_infer_sock_ops_skb_hwtstamp_field_as_u64_when_guarded() {
    let mut func = make_test_function();
    let guarded = func.alloc_block();
    let done = func.alloc_block();
    let op = func.alloc_vreg();
    let matches = func.alloc_vreg();
    let hwtstamp = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: op,
            field: CtxField::SockOp,
            slot: None,
        });
    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::BinOp {
            dst: matches,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(op),
            rhs: MirValue::Const(BPF_SOCK_OPS_TSTAMP_SCHED_CB),
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Branch {
        cond: matches,
        if_true: guarded,
        if_false: done,
    };

    func.block_mut(guarded)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: hwtstamp,
            field: CtxField::SockOpsSkbHwtstamp,
            slot: None,
        });
    func.block_mut(guarded).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&hwtstamp), Some(&MirType::U64));
}

#[test]
fn test_infer_sk_msg_packet_len_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::PacketLen,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_sk_msg_data_field_as_packet_u8_pointer() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(
        types.get(&v0),
        Some(&MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        })
    );
}

#[test]
fn test_infer_sk_msg_socket_field_as_kernel_pointer() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert!(matches!(
        types.get(&v0),
        Some(&MirType::Ptr {
            address_space: AddressSpace::Kernel,
            ..
        })
    ));
}

#[test]
fn test_infer_sock_ops_socket_field_as_kernel_pointer() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert!(matches!(
        types.get(&v0),
        Some(&MirType::Ptr {
            address_space: AddressSpace::Kernel,
            ..
        })
    ));
}

#[test]
fn test_infer_sk_msg_socket_field_includes_extended_metadata() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    let Some(MirType::Ptr { pointee, .. }) = types.get(&v0) else {
        panic!("expected ctx.sk to infer as a pointer");
    };
    let MirType::Struct { fields, .. } = pointee.as_ref() else {
        panic!("expected ctx.sk pointee to be a struct");
    };

    assert!(
        fields
            .iter()
            .any(|field| field.name == "src_port" && field.ty == MirType::U32)
    );
    assert!(
        fields
            .iter()
            .any(|field| field.name == "dst_port" && field.ty == MirType::U16)
    );
    assert!(
        fields
            .iter()
            .any(|field| field.name == "state" && field.ty == MirType::U32)
    );
    assert!(
        fields
            .iter()
            .any(|field| field.name == "rx_queue_mapping" && field.ty == MirType::I32)
    );
}

#[test]
fn test_infer_tc_socket_field_includes_extended_metadata() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    let Some(MirType::Ptr { pointee, .. }) = types.get(&v0) else {
        panic!("expected ctx.sk to infer as a pointer");
    };
    let MirType::Struct { fields, .. } = pointee.as_ref() else {
        panic!("expected ctx.sk pointee to be a struct");
    };

    assert!(
        fields
            .iter()
            .any(|field| field.name == "src_port" && field.ty == MirType::U32)
    );
    assert!(
        fields
            .iter()
            .any(|field| field.name == "dst_port" && field.ty == MirType::U16)
    );
    assert!(
        fields
            .iter()
            .any(|field| field.name == "rx_queue_mapping" && field.ty == MirType::I32)
    );
}

#[test]
fn test_infer_sk_msg_remote_ip6_field_as_stack_backed_u32_array() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::Local);

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::RemoteIp6,
            slot: Some(slot),
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(
        types.get(&v0),
        Some(&MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U32),
                len: 4,
            }),
            address_space: AddressSpace::Stack,
        })
    );
}

#[test]
fn test_infer_sk_skb_remote_ip6_field_as_stack_backed_u32_array() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::Local);

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::RemoteIp6,
            slot: Some(slot),
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(
        types.get(&v0),
        Some(&MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U32),
                len: 4,
            }),
            address_space: AddressSpace::Stack,
        })
    );
}

#[test]
fn test_infer_socket_filter_packet_len_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::PacketLen,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_socket_filter_socket_cookie_field_as_u64() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SocketCookie,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U64));
}

#[test]
fn test_infer_socket_filter_socket_uid_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SocketUid,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_sk_skb_parser_socket_uid_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SocketUid,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SkSkbParser, "/sys/fs/bpf/demo_sockmap");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_sk_msg_netns_cookie_field_as_u64() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::NetnsCookie,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U64));
}

#[test]
fn test_infer_cgroup_sockopt_netns_cookie_field_as_u64() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::NetnsCookie,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U64));
}

#[test]
fn test_infer_kprobe_cgroup_id_field_as_u64() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::CgroupId,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U64));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_infer_perf_event_sample_period_field_as_u64() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::PerfSamplePeriod,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
    );
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U64));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_infer_perf_event_addr_field_as_u64() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::PerfAddr,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
    );
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U64));
}

#[test]
fn test_infer_perf_event_helper_fields_as_u64() {
    for field in [
        CtxField::PerfCounter,
        CtxField::PerfEnabled,
        CtxField::PerfRunning,
    ] {
        let mut func = make_test_function();
        let v0 = func.alloc_vreg();

        func.block_mut(BlockId(0))
            .instructions
            .push(MirInst::LoadCtxField {
                dst: v0,
                field,
                slot: None,
            });
        func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

        let ctx = ProbeContext::new(
            EbpfProgramType::PerfEvent,
            "software:cpu-clock:period=100000",
        );
        let mut ti = TypeInference::new(Some(ctx));
        let types = ti.infer(&func).unwrap();

        assert_eq!(types.get(&v0), Some(&MirType::U64));
    }
}

#[test]
fn test_infer_socket_filter_mark_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SockMark,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_sk_skb_ifindex_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Ifindex,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_sk_skb_hash_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SkbHash,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_socket_filter_pkt_type_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::PktType,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_cgroup_skb_tstamp_field_as_u64() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Tstamp,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U64));
}

#[test]
fn test_infer_tc_tstamp_type_field_as_u8() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::TstampType,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U8));
}

#[test]
fn test_infer_cgroup_skb_hwtstamp_field_as_u64() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Hwtstamp,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U64));
}

#[test]
fn test_infer_socket_filter_tstamp_field_rejects() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Tstamp,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(ctx));
    let err = ti
        .infer(&func)
        .expect_err("expected socket_filter tstamp field to be rejected");

    assert!(err.iter().any(|e| {
        e.message
            .contains("ctx.tstamp is only available on tc and cgroup_skb programs")
    }));
}

#[test]
fn test_infer_socket_filter_tstamp_type_field_rejects() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::TstampType,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(ctx));
    let err = ti
        .infer(&func)
        .expect_err("expected socket_filter tstamp_type field to be rejected");

    assert!(err.iter().any(|e| {
        e.message
            .contains("ctx.tstamp_type is only available on tc programs")
    }));
}

#[test]
fn test_infer_socket_filter_hwtstamp_field_rejects() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Hwtstamp,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(ctx));
    let err = ti
        .infer(&func)
        .expect_err("expected socket_filter hwtstamp field to be rejected");

    assert!(err.iter().any(|e| {
        e.message
            .contains("ctx.hwtstamp is only available on tc and cgroup_skb programs")
    }));
}

#[test]
fn test_infer_sk_skb_mark_field_rejects() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SockMark,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    let mut ti = TypeInference::new(Some(ctx));
    let err = ti
        .infer(&func)
        .expect_err("expected sk_skb mark field to be rejected");

    assert!(err.iter().any(|e| {
        e.message.contains(
            "ctx.mark is only available on cgroup_sock, socket_filter, tc, and cgroup_skb programs",
        )
    }));
}

#[test]
fn test_infer_socket_filter_eth_protocol_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::EthProtocol,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_socket_filter_cb_field_as_stack_backed_u32_array() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let slot = func.alloc_stack_slot(20, 8, StackSlotKind::Local);

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SkbCb,
            slot: Some(slot),
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(
        types.get(&v0),
        Some(&MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U32),
                len: 5,
            }),
            address_space: AddressSpace::Stack,
        })
    );
}

#[test]
fn test_infer_sock_ops_remote_ip6_field_as_stack_backed_u32_array() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::Local);

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::RemoteIp6,
            slot: Some(slot),
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(
        types.get(&v0),
        Some(&MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U32),
                len: 4,
            }),
            address_space: AddressSpace::Stack,
        })
    );
}

#[test]
fn test_infer_sock_ops_args_field_as_stack_backed_u32_array() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::Local);

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::SockOpsArgs,
            slot: Some(slot),
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(
        types.get(&v0),
        Some(&MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U32),
                len: 4,
            }),
            address_space: AddressSpace::Stack,
        })
    );
}

#[test]
fn test_infer_cgroup_device_access_type_field_as_u32() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::DeviceAccessType,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::CgroupDevice, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
}

#[test]
fn test_infer_fentry_aggregate_arg_is_stack_backed_byte_array() {
    let (func_name, arg_idx, _size_bytes) = find_aggregate_fentry_arg_candidate();
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Arg(arg_idx),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Fentry, &func_name);
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();
    let expected = expected_runtime_trampoline_type(
        &KernelBtf::get()
            .function_trampoline_arg_type_info(&func_name, arg_idx as usize)
            .unwrap()
            .expect("expected aggregate arg type info"),
    );

    assert_eq!(types.get(&v0), Some(&expected));
    assert_eq!(expected.size(), 8);
    assert!(matches!(expected, MirType::Ptr { .. }));
}

#[test]
fn test_infer_fexit_retval_is_int() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::RetVal,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Fexit, "do_sys_openat2");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();
    let expected = expected_runtime_trampoline_type(
        &KernelBtf::get()
            .function_trampoline_ret_type_info("do_sys_openat2")
            .unwrap()
            .expect("expected do_sys_openat2 retval type info"),
    );

    assert_eq!(types.get(&v0), Some(&expected));
}

#[test]
fn test_infer_fexit_aggregate_retval_is_stack_backed_byte_array() {
    let (func_name, _size_bytes) = find_aggregate_fexit_ret_candidate();
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::RetVal,
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Fexit, &func_name);
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();
    let expected = expected_runtime_trampoline_type(
        &KernelBtf::get()
            .function_trampoline_ret_type_info(&func_name)
            .unwrap()
            .expect("expected aggregate retval type info"),
    );

    assert_eq!(types.get(&v0), Some(&expected));
    assert_eq!(expected.size(), 8);
    assert!(matches!(expected, MirType::Ptr { .. }));
}

#[test]
fn test_infer_fentry_root_pointer_arg_preserves_typed_pointee() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Arg(0),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");
    let mut ti = TypeInference::new(Some(ctx));
    let types = ti.infer(&func).unwrap();

    let Some(MirType::Ptr { pointee, .. }) = types.get(&v0) else {
        panic!("expected typed pointer for do_close_on_exec ctx.arg0");
    };
    let MirType::Struct {
        kernel_btf_type_id,
        fields,
        ..
    } = pointee.as_ref()
    else {
        panic!("expected typed struct pointee for do_close_on_exec ctx.arg0");
    };
    assert!(kernel_btf_type_id.is_some());
    assert!(fields.iter().any(|field| field.name == "fdt"));
}

#[test]
fn test_type_error_kprobe_tracepoint_field_is_rejected() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::TracepointField("filename".to_string()),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Kprobe, "do_sys_openat2");
    let mut ti = TypeInference::new(Some(ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected kprobe tracepoint field to be rejected");

    assert!(errs.iter().any(|e| {
        e.message
            .contains("ctx.filename is only available on typed tracepoints")
    }));
}

#[test]
fn test_type_error_kprobe_arg_index_out_of_range_is_rejected() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::Arg(6),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Kprobe, "do_sys_openat2");
    let mut ti = TypeInference::new(Some(ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected out-of-range pt_regs arg to be rejected");

    assert!(
        errs.iter()
            .any(|e| e.message.contains("Argument index 6 out of range")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_tracepoint_missing_field_is_rejected() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    func.block_mut(BlockId(0))
        .instructions
        .push(MirInst::LoadCtxField {
            dst: v0,
            field: CtxField::TracepointField("__definitely_missing".to_string()),
            slot: None,
        });
    func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

    let ctx = ProbeContext::new(EbpfProgramType::Tracepoint, "syscalls/sys_enter_openat");
    let mut ti = TypeInference::new(Some(ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected missing tracepoint field to be rejected");

    assert!(
        errs.iter().any(|e| e
            .message
            .contains("Tracepoint field '__definitely_missing' not found")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_infer_map_lookup_returns_ptr() {
    use crate::compiler::mir::{MapKind, MapRef};

    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(123),
    });
    block.instructions.push(MirInst::MapLookup {
        dst: v1,
        map: MapRef {
            name: "test_map".to_string(),
            kind: MapKind::Hash,
        },
        key: v0,
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    match types.get(&v1) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Map);
        }
        other => panic!("Expected map pointer, got {:?}", other),
    }
}

#[test]
fn test_copy_propagates_type() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: v0,
        field: CtxField::Timestamp,
        slot: None,
    });
    block.instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::VReg(v0),
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    // Both should be U64 (timestamp type)
    assert_eq!(types.get(&v0), Some(&MirType::U64));
    assert_eq!(types.get(&v1), Some(&MirType::U64));
}

#[test]
fn test_time_ctx_fields_are_u64() {
    for field in [
        CtxField::Timestamp,
        CtxField::BootTimestamp,
        CtxField::CoarseTimestamp,
        CtxField::TaiTimestamp,
        CtxField::Jiffies,
    ] {
        let mut func = make_test_function();
        let dst = func.alloc_vreg();

        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst,
            field,
            slot: None,
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();
        assert_eq!(types.get(&dst), Some(&MirType::U64));
    }
}

#[test]
fn test_tracing_helper_ctx_fields_are_u64() {
    for field in [CtxField::FuncIp, CtxField::AttachCookie] {
        let mut func = make_test_function();
        let dst = func.alloc_vreg();

        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst,
            field,
            slot: None,
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(Some(ProbeContext::new(
            EbpfProgramType::Kprobe,
            "ksys_read",
        )));
        let types = ti.infer(&func).unwrap();
        assert_eq!(types.get(&dst), Some(&MirType::U64));
    }
}

#[test]
fn test_arg_count_ctx_field_is_u64() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst,
        field: CtxField::ArgCount,
        slot: None,
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(Some(ProbeContext::new(
        EbpfProgramType::Fentry,
        "do_sys_openat2",
    )));
    let types = ti.infer(&func).unwrap();
    assert_eq!(types.get(&dst), Some(&MirType::U64));
}

#[test]
fn test_type_propagation_through_chain() {
    // Test that types propagate through a chain of copies
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: v0,
        field: CtxField::Pid, // U32
        slot: None,
    });
    block.instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::VReg(v0),
    });
    block.instructions.push(MirInst::Copy {
        dst: v2,
        src: MirValue::VReg(v1),
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    // All should be U32
    assert_eq!(types.get(&v0), Some(&MirType::U32));
    assert_eq!(types.get(&v1), Some(&MirType::U32));
    assert_eq!(types.get(&v2), Some(&MirType::U32));
}

#[test]
fn test_unification_through_binop() {
    // Test that types unify correctly through binary operations
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: v0,
        field: CtxField::Uid, // U32
        slot: None,
    });
    block.instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::VReg(v0),
    });
    // Compare v1 (which got type from v0) with constant
    block.instructions.push(MirInst::BinOp {
        dst: v2,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(v1),
        rhs: MirValue::Const(0),
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();

    assert_eq!(types.get(&v0), Some(&MirType::U32));
    assert_eq!(types.get(&v1), Some(&MirType::U32));
    assert_eq!(types.get(&v2), Some(&MirType::Bool));
}

#[test]
fn test_type_infer_accepts_store_skb_tstamp_on_tc() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SkbTstamp,
        val: MirValue::Const(7),
        ty: MirType::U64,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    ti.infer(&func)
        .expect("skb tstamp store should type-check on tc");
}

#[test]
fn test_type_infer_accepts_store_skb_tstamp_on_cgroup_skb_egress() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SkbTstamp,
        val: MirValue::Const(7),
        ty: MirType::U64,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    ti.infer(&func)
        .expect("skb tstamp store should type-check on cgroup_skb egress");
}

#[test]
fn test_type_infer_accepts_store_skb_mark_on_tc() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SkbMark,
        val: MirValue::Const(7),
        ty: MirType::U32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    ti.infer(&func)
        .expect("skb mark store should type-check on tc");
}

#[test]
fn test_type_infer_accepts_store_skb_mark_on_cgroup_skb() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SkbMark,
        val: MirValue::Const(7),
        ty: MirType::U32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    ti.infer(&func)
        .expect("skb mark store should type-check on cgroup_skb");
}

#[test]
fn test_type_infer_accepts_store_skb_cb_on_tc() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SkbCbWord(2),
        val: MirValue::Const(7),
        ty: MirType::U32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    ti.infer(&func)
        .expect("skb cb store should type-check on tc");
}

#[test]
fn test_type_infer_accepts_store_skb_cb_on_socket_filter() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SkbCbWord(0),
        val: MirValue::Const(7),
        ty: MirType::U32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(probe_ctx));
    ti.infer(&func)
        .expect("skb cb store should type-check on socket_filter");
}

#[test]
fn test_type_infer_accepts_store_skb_priority_on_sk_skb_parser() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SkbPriority,
        val: MirValue::Const(7),
        ty: MirType::U32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkbParser, "/sys/fs/bpf/demo_sockmap");
    let mut ti = TypeInference::new(Some(probe_ctx));
    ti.infer(&func)
        .expect("skb priority store should type-check on sk_skb_parser");
}

#[test]
fn test_type_infer_accepts_store_cgroup_sock_mark_on_sock_release() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::CgroupSockMark,
        val: MirValue::Const(7),
        ty: MirType::U32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_release");
    let mut ti = TypeInference::new(Some(probe_ctx));
    ti.infer(&func)
        .expect("cgroup_sock mark store should type-check on sock_release");
}

#[test]
fn test_type_error_store_skb_tstamp_rejects_non_skb_context() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SkbTstamp,
        val: MirValue::Const(7),
        ty: MirType::U64,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("skb tstamp store should be rejected outside skb-backed contexts");
    assert!(errs.iter().any(|e| {
        e.message.contains(
            "ctx.tstamp is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
        )
    }));
}

#[test]
fn test_type_error_store_skb_tstamp_rejects_socket_filter_context() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SkbTstamp,
        val: MirValue::Const(7),
        ty: MirType::U64,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("skb tstamp store should be rejected on socket_filter");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("ctx.tstamp is only available on tc and cgroup_skb programs")
    }));
}

#[test]
fn test_type_error_store_skb_tstamp_rejects_cgroup_skb_ingress_context() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SkbTstamp,
        val: MirValue::Const(7),
        ty: MirType::U64,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("skb tstamp store should be rejected on cgroup_skb ingress");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("ctx.tstamp is only writable on tc and cgroup_skb:egress programs")
    }));
}

#[test]
fn test_type_error_store_skb_mark_rejects_socket_filter_context() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SkbMark,
        val: MirValue::Const(7),
        ty: MirType::U32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("skb mark store should be rejected on socket_filter");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("ctx.mark is only writable on tc and cgroup_skb programs")
    }));
}

#[test]
fn test_type_error_store_cgroup_sock_mark_rejects_post_bind_context() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::CgroupSockMark,
        val: MirValue::Const(7),
        ty: MirType::U32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("cgroup_sock mark store should be rejected on post_bind4");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("ctx.mark is only writable on cgroup_sock sock_create/sock_release hooks")
    }));
}

#[test]
fn test_type_error_store_skb_tc_index_rejects_socket_filter_context() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SkbTcIndex,
        val: MirValue::Const(7),
        ty: MirType::U32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("skb tc_index store should be rejected on socket_filter");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("ctx.tc_index is only writable on tc, sk_skb, and sk_skb_parser programs")
    }));
}

#[test]
fn test_type_error_store_ctx_reply_rejects_non_sock_ops_program() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SockOpsReply,
        val: MirValue::Const(1),
        ty: MirType::U32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("sock_ops reply store should be rejected outside sock_ops");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("writable sock_ops reply fields are only supported on sock_ops programs")
    }));
}

#[test]
fn test_type_error_store_ctx_sk_txhash_rejects_non_sock_ops_program() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SockOpsSkTxhash,
        val: MirValue::Const(1),
        ty: MirType::U32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("sock_ops sk_txhash store should be rejected outside sock_ops");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("ctx.sk_txhash is only available on sock_ops programs")
    }));
}

#[test]
fn test_type_error_store_sockopt_retval_rejects_set_context() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SockoptRetval,
        val: MirValue::Const(0),
        ty: MirType::I32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:set");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("sockopt_retval store should be rejected on cgroup_sockopt:set");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("ctx.sockopt_retval is only available on cgroup_sockopt:get hooks")
    }));
}

#[test]
fn test_type_infer_accepts_store_sockopt_level_on_set_hook() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SockoptLevel,
        val: MirValue::Const(1),
        ty: MirType::I32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:set");
    let mut ti = TypeInference::new(Some(probe_ctx));
    ti.infer(&func)
        .expect("cgroup_sockopt level store should type-check on set hook");
}

#[test]
fn test_type_infer_accepts_store_sockopt_optlen_on_get_hook() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SockoptOptlen,
        val: MirValue::Const(8),
        ty: MirType::I32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let mut ti = TypeInference::new(Some(probe_ctx));
    ti.infer(&func)
        .expect("cgroup_sockopt optlen store should type-check on get hook");
}

#[test]
fn test_type_error_store_sockopt_level_rejects_get_context() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SockoptLevel,
        val: MirValue::Const(1),
        ty: MirType::I32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("sockopt level store should be rejected on cgroup_sockopt:get");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("ctx.level is only writable on cgroup_sockopt:set hooks")
    }));
}

#[test]
fn test_type_infer_accepts_store_sysctl_file_pos() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SysctlFilePos,
        val: MirValue::Const(4),
        ty: MirType::U32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(probe_ctx));
    ti.infer(&func)
        .expect("cgroup_sysctl file_pos store should type-check");
}

#[test]
fn test_type_error_store_sysctl_file_pos_rejects_non_sysctl_context() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::SysctlFilePos,
        val: MirValue::Const(4),
        ty: MirType::U32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("sysctl file_pos store should be rejected outside cgroup_sysctl");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("ctx.file_pos is only available on cgroup_sysctl programs")
    }));
}

#[test]
fn test_type_infer_accepts_store_cgroup_sock_addr_user_ip6_on_connect6() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::CgroupSockAddrUserIp6Word(0),
        val: MirValue::Const(0x20010db8),
        ty: MirType::U32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect6");
    let mut ti = TypeInference::new(Some(probe_ctx));
    ti.infer(&func)
        .expect("cgroup_sock_addr user_ip6.0 store should type-check on connect6");
}

#[test]
fn test_type_error_store_cgroup_sock_addr_msg_src_ip4_rejects_non_msg_hook() {
    let mut func = make_test_function();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::StoreCtxField {
        target: CtxStoreTarget::CgroupSockAddrMsgSrcIp4,
        val: MirValue::Const(0x7f000001),
        ty: MirType::U32,
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("msg_src_ip4 store should be rejected on non-msg cgroup_sock_addr hook");
    assert!(errs.iter().any(|e| {
        e.message.contains(
            "ctx.msg_src_ip4 is only available on cgroup_sock_addr sendmsg4/sendmsg6 hooks",
        )
    }));
}
