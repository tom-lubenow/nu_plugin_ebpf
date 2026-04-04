use super::*;
use crate::compiler::EbpfProgramType;
use crate::kernel_btf::{KernelBtf, TrampolineValueKind};

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
            .contains("ctx.arg0 is only available on function probes with argument access")
    }));
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
            .contains("ctx.arg0 is only available on function probes with argument access")
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

    assert_eq!(types.get(&v0), Some(&MirType::I64));
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
fn test_infer_fentry_aggregate_arg_is_stack_backed_byte_array() {
    let (func_name, arg_idx, size_bytes) = find_aggregate_fentry_arg_candidate();
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

    assert_eq!(
        types.get(&v0),
        Some(&MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: size_bytes,
            }),
            address_space: AddressSpace::Stack,
        })
    );
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

    assert_eq!(types.get(&v0), Some(&MirType::I64));
}

#[test]
fn test_infer_fexit_aggregate_retval_is_stack_backed_byte_array() {
    let (func_name, size_bytes) = find_aggregate_fexit_ret_candidate();
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

    assert_eq!(
        types.get(&v0),
        Some(&MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: size_bytes,
            }),
            address_space: AddressSpace::Stack,
        })
    );
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
