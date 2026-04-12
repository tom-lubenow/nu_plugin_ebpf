use super::*;
use crate::compiler::mir::CtxStoreTarget;
use crate::compiler::{EbpfProgramType, ProbeContext};
use crate::kernel_btf::KernelBtf;

fn new_mir_function() -> (MirFunction, BlockId) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    (func, entry)
}

fn kernel_u8_ptr() -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::U8),
        address_space: AddressSpace::Kernel,
    }
}

fn make_sockopt_optval_store_function(
    with_end_guard: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let (mut func, entry) = new_mir_function();
    let guard_block = func.alloc_block();
    let store_block = func.alloc_block();
    let join_block = func.alloc_block();

    let optval = func.alloc_vreg();
    let non_null = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: optval,
            field: CtxField::SockoptOptval,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(optval),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: non_null,
        if_true: guard_block,
        if_false: join_block,
    };

    if with_end_guard {
        let optval_end = func.alloc_vreg();
        let access_end = func.alloc_vreg();
        let len_ok = func.alloc_vreg();

        func.block_mut(guard_block)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: optval_end,
                field: CtxField::SockoptOptvalEnd,
                slot: None,
            });
        func.block_mut(guard_block)
            .instructions
            .push(MirInst::BinOp {
                dst: access_end,
                op: BinOpKind::Add,
                lhs: MirValue::VReg(optval),
                rhs: MirValue::Const(1),
            });
        func.block_mut(guard_block)
            .instructions
            .push(MirInst::BinOp {
                dst: len_ok,
                op: BinOpKind::Le,
                lhs: MirValue::VReg(access_end),
                rhs: MirValue::VReg(optval_end),
            });
        func.block_mut(guard_block).terminator = MirInst::Branch {
            cond: len_ok,
            if_true: store_block,
            if_false: join_block,
        };
    } else {
        func.block_mut(guard_block).terminator = MirInst::Jump {
            target: store_block,
        };
    }

    func.block_mut(store_block)
        .instructions
        .push(MirInst::Store {
            ptr: optval,
            offset: 0,
            val: MirValue::Const(42),
            ty: MirType::U8,
        });
    func.block_mut(store_block).terminator = MirInst::Jump { target: join_block };
    func.block_mut(join_block).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(optval, kernel_u8_ptr());
    if with_end_guard {
        let block = func.block(guard_block);
        for inst in &block.instructions {
            match inst {
                MirInst::LoadCtxField { dst, field, .. }
                    if matches!(field, CtxField::SockoptOptvalEnd) =>
                {
                    types.insert(*dst, kernel_u8_ptr());
                }
                MirInst::BinOp { dst, op, .. } if matches!(op, BinOpKind::Add) => {
                    types.insert(*dst, kernel_u8_ptr());
                }
                _ => {}
            }
        }
    }

    (func, types)
}

fn find_void_fexit_candidate() -> String {
    let mut attempts = Vec::new();
    for func_name in ["wake_up_new_task", "security_file_open", "__audit_free"] {
        match KernelBtf::get().function_trampoline_ret_type_info(func_name) {
            Ok(None) => return func_name.to_string(),
            Ok(Some(spec)) => attempts.push(format!("{func_name}: {:?}", spec)),
            Err(err) => attempts.push(format!("{func_name}: {err}")),
        }
    }
    panic!(
        "expected a void fexit candidate on this kernel; tried: {}",
        attempts.join(", ")
    );
}

#[test]
fn test_verify_mir_for_probe_context_rejects_invalid_tracepoint_field_load() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst,
            field: CtxField::TracepointField("filename".to_string()),
            slot: None,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "do_sys_openat2");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected tracepoint field load to be rejected on kprobe");
    assert!(err.iter().any(|e| {
        e.message
            .contains("ctx.filename is only available on typed tracepoints")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_rejects_out_of_range_pt_regs_arg_load() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst,
            field: CtxField::Arg(6),
            slot: None,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "do_sys_openat2");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected out-of-range pt_regs arg to be rejected");
    assert!(
        err.iter()
            .any(|e| e.message.contains("Argument index 6 out of range")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_rejects_missing_tracepoint_field_load() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst,
            field: CtxField::TracepointField("__definitely_missing".to_string()),
            slot: None,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tracepoint, "syscalls/sys_enter_openat");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected missing tracepoint field to be rejected");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("Tracepoint field '__definitely_missing' not found")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_rejects_unavailable_trampoline_arg_load() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst,
            field: CtxField::Arg(99),
            slot: None,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected unavailable trampoline arg to be rejected");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("ctx.arg99 is not available on fentry:do_close_on_exec")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_rejects_void_trampoline_retval_load() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst,
            field: CtxField::RetVal,
            slot: None,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let func_name = find_void_fexit_candidate();
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fexit, &func_name);
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected void trampoline retval to be rejected");
    assert!(
        err.iter().any(|e| {
            e.message.contains(&format!(
                "ctx.retval is not available on fexit:{} because the target returns void",
                func_name
            ))
        }),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_rejects_sockopt_retval_store_on_set_hook() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SockoptRetval,
            val: MirValue::Const(0),
            ty: MirType::I32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:set");
    let err = verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect_err("expected sockopt_retval store to be rejected on set hook");
    assert!(err.iter().any(|e| {
        e.message
            .contains("ctx.sockopt_retval is only available on cgroup_sockopt:get hooks")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_accepts_sockopt_level_store_on_set_hook() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SockoptLevel,
            val: MirValue::Const(1),
            ty: MirType::I32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:set");
    verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect("expected level store to be accepted on cgroup_sockopt:set");
}

#[test]
fn test_verify_mir_for_probe_context_accepts_sockopt_optlen_store_on_get_hook() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SockoptOptlen,
            val: MirValue::Const(8),
            ty: MirType::I32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect("expected optlen store to be accepted on cgroup_sockopt:get");
}

#[test]
fn test_verify_mir_accepts_guarded_sockopt_optval_byte_store() {
    let (func, types) = make_sockopt_optval_store_function(true);
    verify_mir(&func, &types).expect("expected guarded sockopt optval store to verify");
}

#[test]
fn test_verify_mir_rejects_unguarded_sockopt_optval_byte_store() {
    let (func, types) = make_sockopt_optval_store_function(false);
    let err =
        verify_mir(&func, &types).expect_err("expected unguarded sockopt optval store to fail");
    assert!(err.iter().any(|e| {
        e.message
            .contains("store on bounded context buffers requires a preceding end-pointer guard")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_rejects_sockopt_level_store_on_get_hook() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SockoptLevel,
            val: MirValue::Const(1),
            ty: MirType::I32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let err = verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect_err("expected level store to be rejected on cgroup_sockopt:get");
    assert!(err.iter().any(|e| {
        e.message
            .contains("ctx.level is only writable on cgroup_sockopt:set hooks")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_accepts_sysctl_file_pos_store() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SysctlFilePos,
            val: MirValue::Const(4),
            ty: MirType::U32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");
    verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect("expected file_pos store to be accepted on cgroup_sysctl");
}

#[test]
fn test_verify_mir_for_probe_context_rejects_sysctl_file_pos_store_on_non_sysctl_program() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SysctlFilePos,
            val: MirValue::Const(4),
            ty: MirType::U32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let err = verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect_err("expected file_pos store to be rejected outside cgroup_sysctl");
    assert!(err.iter().any(|e| {
        e.message
            .contains("ctx.file_pos is only available on cgroup_sysctl programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_accepts_cgroup_sock_addr_user_ip6_store_on_connect6() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::CgroupSockAddrUserIp6Word(1),
            val: MirValue::Const(0x20010db8),
            ty: MirType::U32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect6");
    verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect("expected connect6 user_ip6 store to be accepted");
}

#[test]
fn test_verify_mir_for_probe_context_rejects_cgroup_sock_addr_msg_src_ip4_store_on_non_msg_hook() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::CgroupSockAddrMsgSrcIp4,
            val: MirValue::Const(0x7f000001),
            ty: MirType::U32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    let err = verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect_err("expected msg_src_ip4 store to be rejected on non-msg hook");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "ctx.msg_src_ip4 is only available on cgroup_sock_addr sendmsg*/recvmsg* hooks",
        )
    }));
}
