use super::*;
use crate::compiler::mir::StructField;
use crate::compiler::subfn_summaries::SubfunctionReturnSummary;
use crate::compiler::{EbpfProgramType, MapRef, ProbeContext, ProgramCapability, ProgramTypeInfo};

#[test]
fn test_helper_pointer_arg_required() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 16, // bpf_get_current_comm(buf, size)
            args: vec![MirValue::Const(0), MirValue::Const(16)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected helper pointer-arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_syscall_helpers_accept_syscall_program() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let attr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let name_slot = func.alloc_stack_slot(16, 1, StackSlotKind::StringBuffer);
    let res_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sys_bpf = func.alloc_vreg();
    let btf_find = func.alloc_vreg();
    let sys_close = func.alloc_vreg();
    let kallsyms = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sys_bpf,
            helper: BpfHelper::SysBpf as u32,
            args: vec![
                MirValue::Const(0),
                MirValue::StackSlot(attr_slot),
                MirValue::Const(16),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: btf_find,
            helper: BpfHelper::BtfFindByNameKind as u32,
            args: vec![
                MirValue::StackSlot(name_slot),
                MirValue::Const(16),
                MirValue::Const(1),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sys_close,
            helper: BpfHelper::SysClose as u32,
            args: vec![MirValue::Const(3)],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: kallsyms,
            helper: BpfHelper::KallsymsLookupName as u32,
            args: vec![
                MirValue::StackSlot(name_slot),
                MirValue::Const(16),
                MirValue::Const(0),
                MirValue::StackSlot(res_slot),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([
        (sys_bpf, MirType::I64),
        (btf_find, MirType::I64),
        (sys_close, MirType::I64),
        (kallsyms, MirType::I64),
    ]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Syscall, "demo");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected modeled syscall helpers to verify on syscall programs");
}

#[test]
fn test_verify_mir_for_probe_context_syscall_program_rejects_unmodeled_helper() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetCurrentPidTgid as u32,
            args: vec![],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Syscall, "demo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected unmodeled syscall helper to be rejected");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_get_current_pid_tgid' is not modeled for syscall programs")
    }));
}

#[test]
fn test_verify_mir_helper_snprintf_accepts_rodata_format() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let fmt = func.alloc_vreg();
    let out_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadGlobal {
            dst: fmt,
            symbol: "__nu_rodata_fmt".to_string(),
            ty: MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16,
            },
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::Snprintf as u32,
            args: vec![
                MirValue::StackSlot(out_slot),
                MirValue::Const(32),
                MirValue::VReg(fmt),
                MirValue::StackSlot(data_slot),
                MirValue::Const(16),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    verify_mir(&func, &types).expect("expected bpf_snprintf with map format to verify");
}

#[test]
fn test_verify_mir_helper_snprintf_rejects_stack_format() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let out_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let fmt_slot = func.alloc_stack_slot(16, 1, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::Snprintf as u32,
            args: vec![
                MirValue::StackSlot(out_slot),
                MirValue::Const(32),
                MirValue::StackSlot(fmt_slot),
                MirValue::StackSlot(data_slot),
                MirValue::Const(16),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    let err = verify_mir(&func, &types).expect_err("expected stack fmt rejection");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper snprintf fmt expects pointer in [Map]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_snprintf_size_and_alignment() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let fmt = func.alloc_vreg();
    let out_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadGlobal {
            dst: fmt,
            symbol: "__nu_rodata_fmt".to_string(),
            ty: MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16,
            },
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::Snprintf as u32,
            args: vec![
                MirValue::StackSlot(out_slot),
                MirValue::Const(-1),
                MirValue::VReg(fmt),
                MirValue::StackSlot(data_slot),
                MirValue::Const(10),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    let err = verify_mir(&func, &types).expect_err("expected snprintf size/alignment errors");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 165 arg1 must be >= 0")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_snprintf' requires arg4 to be a multiple of 8")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_snprintf_btf_accepts_stack_buffers() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let out_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let btf_ptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SnprintfBtf as u32,
            args: vec![
                MirValue::StackSlot(out_slot),
                MirValue::Const(32),
                MirValue::StackSlot(btf_ptr_slot),
                MirValue::Const(16),
                MirValue::Const(15),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    verify_mir(&func, &types).expect("expected bpf_snprintf_btf stack buffers to verify");
}

#[test]
fn test_verify_mir_helper_snprintf_btf_size_and_shape() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let out_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let btf_ptr_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SnprintfBtf as u32,
            args: vec![
                MirValue::StackSlot(out_slot),
                MirValue::Const(-1),
                MirValue::StackSlot(btf_ptr_slot),
                MirValue::Const(8),
                MirValue::Const(16),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    let err = verify_mir(&func, &types).expect_err("expected snprintf_btf size/shape errors");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 149 arg1 must be >= 0")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper snprintf_btf ptr out of bounds")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_snprintf_btf' requires arg3 = 16")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_snprintf_btf' requires arg4 to contain only BTF_F_* bits")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_syscall_helpers_enforce_size_and_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let attr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let name_slot = func.alloc_stack_slot(16, 1, StackSlotKind::StringBuffer);
    let res_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sys_bpf = func.alloc_vreg();
    let btf_find = func.alloc_vreg();
    let kallsyms = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sys_bpf,
            helper: BpfHelper::SysBpf as u32,
            args: vec![
                MirValue::Const(0),
                MirValue::StackSlot(attr_slot),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: btf_find,
            helper: BpfHelper::BtfFindByNameKind as u32,
            args: vec![
                MirValue::StackSlot(name_slot),
                MirValue::Const(16),
                MirValue::Const(1),
                MirValue::Const(1),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: kallsyms,
            helper: BpfHelper::KallsymsLookupName as u32,
            args: vec![
                MirValue::StackSlot(name_slot),
                MirValue::Const(16),
                MirValue::Const(1),
                MirValue::StackSlot(res_slot),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([
        (sys_bpf, MirType::I64),
        (btf_find, MirType::I64),
        (kallsyms, MirType::I64),
    ]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Syscall, "demo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected syscall helper shape errors");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 166 arg2 must be > 0"))
    );
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_btf_find_by_name_kind' requires arg3 = 0")
    }));
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_kallsyms_lookup_name' requires arg2 = 0")
    }));
}

#[test]
fn test_unknown_helper_rejects_more_than_five_args() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 9999,
            args: vec![
                MirValue::Const(0),
                MirValue::Const(1),
                MirValue::Const(2),
                MirValue::Const(3),
                MirValue::Const(4),
                MirValue::Const(5),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper-argument count rejection");
    assert!(
        err.iter()
            .any(|e| e.message.contains("at most 5 arguments")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_signal_helpers() {
    for helper in [BpfHelper::SendSignal, BpfHelper::SendSignalThread] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args: vec![MirValue::Const(9)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);
        verify_mir(&func, &types).expect("expected signal helper to verify");
    }
}

#[test]
fn test_verify_mir_rejects_more_than_five_params() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 6;
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected param-count error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("at most 5 arguments")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_accepts_helper_context_argument_from_ctx_pointer_load() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetSocketCookie as u32,
            args: vec![MirValue::VReg(ctx)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types)
        .expect("expected bare ctx pointer load to satisfy helper context argument");
}

#[test]
fn test_verify_mir_accepts_helper_context_argument_from_ctx_pointer_copy() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let ctx_copy = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ctx_copy,
        src: MirValue::VReg(ctx),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetSocketCookie as u32,
            args: vec![MirValue::VReg(ctx_copy)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        ctx_copy,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types)
        .expect("expected copied raw ctx pointer to satisfy helper context argument");
}

#[test]
fn test_verify_mir_for_probe_context_get_socket_cookie_rejects_sk_lookup() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetSocketCookie as u32,
            args: vec![MirValue::VReg(ctx)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected get_socket_cookie sk_lookup program-surface error");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_get_socket_cookie' is only valid in fentry, fexit, fmod_ret, tp_btf, socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, sock_ops, sk_reuseport, sk_skb, and sk_skb_parser programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_get_socket_cookie_accepts_socket_filter() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetSocketCookie as u32,
            args: vec![MirValue::VReg(ctx)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected get_socket_cookie socket_filter context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_get_socket_cookie_rejects_fentry_context_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetSocketCookie as u32,
            args: vec![MirValue::VReg(ctx)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "tcp_connect");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected fentry raw ctx pointer to fail get_socket_cookie");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_get_socket_cookie' arg0 expects socket pointer in fentry programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_get_socket_cookie_accepts_fentry_socket_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: sk,
            field: CtxField::Arg(0),
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetSocketCookie as u32,
            args: vec![MirValue::VReg(sk)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        sk,
        MirType::Ptr {
            pointee: Box::new(ProbeContext::synthetic_socket_type()),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "tcp_connect");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected socket pointer arg to satisfy fentry get_socket_cookie");
}

#[test]
fn test_verify_mir_for_probe_context_get_socket_cookie_accepts_fentry_const_zero() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetSocketCookie as u32,
            args: vec![MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "tcp_connect");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected tracing get_socket_cookie(0) to verify");
}

#[test]
fn test_verify_mir_for_probe_context_get_socket_cookie_rejects_socket_filter_const_zero() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetSocketCookie as u32,
            args: vec![MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected socket_filter get_socket_cookie(0) to fail");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_get_socket_cookie' arg0 expects raw ctx pointer in socket_filter programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_get_socket_cookie_rejects_offset_context_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let ctx_offset = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ctx_offset,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(8),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetSocketCookie as u32,
            args: vec![MirValue::VReg(ctx_offset)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        ctx_offset,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected offset raw ctx pointer to fail get_socket_cookie");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_get_socket_cookie' arg0 expects raw ctx pointer in socket_filter programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_get_socket_cookie_rejects_cgroup_sock_addr_socket_field() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: sk,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetSocketCookie as u32,
            args: vec![MirValue::VReg(sk)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        sk,
        MirType::Ptr {
            pointee: Box::new(ProbeContext::synthetic_socket_type()),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected cgroup_sock_addr ctx.sk to fail get_socket_cookie");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_get_socket_cookie' arg0 expects raw ctx pointer in cgroup_sock_addr programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_get_socket_cookie_accepts_cgroup_sock_socket_alias() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: sk,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetSocketCookie as u32,
            args: vec![MirValue::VReg(sk)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        sk,
        MirType::Ptr {
            pointee: Box::new(ProbeContext::synthetic_socket_type()),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected cgroup_sock ctx.sk alias to satisfy get_socket_cookie");
}

#[test]
fn test_verify_mir_for_probe_context_get_socket_uid_accepts_cgroup_skb() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetSocketUid as u32,
            args: vec![MirValue::VReg(ctx)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected get_socket_uid cgroup_skb context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_get_socket_uid_accepts_tc() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetSocketUid as u32,
            args: vec![MirValue::VReg(ctx)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected get_socket_uid tc context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_get_netns_cookie_accepts_cgroup_sockopt() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetNetnsCookie as u32,
            args: vec![MirValue::VReg(ctx)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected get_netns_cookie cgroup_sockopt context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_get_netns_cookie_accepts_sk_msg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetNetnsCookie as u32,
            args: vec![MirValue::VReg(ctx)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected get_netns_cookie sk_msg context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_sk_cgroup_helpers_reject_sk_msg() {
    for (helper, args) in [
        (BpfHelper::SkCgroupId, vec![]),
        (BpfHelper::SkAncestorCgroupId, vec![MirValue::Const(0)]),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let sk = func.alloc_vreg();
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: sk,
                field: CtxField::Socket,
                slot: None,
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args: std::iter::once(MirValue::VReg(sk))
                    .chain(args.into_iter())
                    .collect(),
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            sk,
            MirType::Ptr {
                pointee: Box::new(MirType::Unknown),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected sk_cgroup helper sk_msg program-surface error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("is only valid in cgroup_skb programs"))
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_sk_cgroup_helpers_accept_cgroup_skb() {
    for (helper, args) in [
        (BpfHelper::SkCgroupId, vec![]),
        (BpfHelper::SkAncestorCgroupId, vec![MirValue::Const(0)]),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let call = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let ctx = func.alloc_vreg();
        let sock = func.alloc_vreg();
        let sock_non_null = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let cleanup_ret = func.alloc_vreg();
        let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: sock,
                helper: BpfHelper::SkLookupTcp as u32,
                args: vec![
                    MirValue::VReg(ctx),
                    MirValue::StackSlot(tuple_slot),
                    MirValue::Const(16),
                    MirValue::Const(0),
                    MirValue::Const(0),
                ],
            });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: sock_non_null,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(sock),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond: sock_non_null,
            if_true: call,
            if_false: done,
        };

        func.block_mut(call).instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: std::iter::once(MirValue::VReg(sock))
                .chain(args.into_iter())
                .collect(),
        });
        func.block_mut(call).instructions.push(MirInst::CallHelper {
            dst: cleanup_ret,
            helper: BpfHelper::SkRelease as u32,
            args: vec![MirValue::VReg(sock)],
        });
        func.block_mut(call).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(
            sock,
            MirType::Ptr {
                pointee: Box::new(MirType::Unknown),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(sock_non_null, MirType::Bool);
        types.insert(dst, MirType::I64);
        types.insert(cleanup_ret, MirType::I64);

        let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected sk_cgroup helper cgroup_skb context to verify");
    }
}

#[test]
fn test_verify_mir_for_probe_context_tc_egress_skb_metadata_helpers_accept_tc_egress() {
    for (helper, extra_args) in [
        (BpfHelper::GetCgroupClassid, vec![]),
        (BpfHelper::GetRouteRealm, vec![]),
        (BpfHelper::SkbCgroupId, vec![]),
        (BpfHelper::SkbAncestorCgroupId, vec![MirValue::Const(0)]),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args: std::iter::once(MirValue::VReg(ctx))
                    .chain(extra_args.into_iter())
                    .collect(),
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:egress");
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected tc-egress skb metadata helper to verify");

        let probe_ctx = ProbeContext::new(EbpfProgramType::TcAction, "demo-action");
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected tc_action skb metadata helper to verify");
    }
}

#[test]
fn test_verify_mir_for_probe_context_skb_cgroup_classid_accepts_tc_ingress() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkbCgroupClassid as u32,
            args: vec![MirValue::VReg(ctx)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected skb_cgroup_classid helper to verify on tc ingress");
}

#[test]
fn test_verify_mir_for_probe_context_lwt_cgroup_metadata_helpers() {
    for helper in [BpfHelper::GetCgroupClassid, BpfHelper::GetRouteRealm] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args: vec![MirValue::VReg(ctx)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        let probe_ctx = ProbeContext::new(EbpfProgramType::LwtOut, "demo-route");
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected lwt cgroup metadata helper to verify");
    }
}

#[test]
fn test_verify_mir_for_probe_context_tc_egress_skb_metadata_helpers_reject_tc_ingress() {
    for (helper, extra_args) in [
        (BpfHelper::GetCgroupClassid, vec![]),
        (BpfHelper::GetRouteRealm, vec![]),
        (BpfHelper::SkbCgroupId, vec![]),
        (BpfHelper::SkbAncestorCgroupId, vec![MirValue::Const(0)]),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args: std::iter::once(MirValue::VReg(ctx))
                    .chain(extra_args.into_iter())
                    .collect(),
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected tc-egress skb metadata helper tc-ingress context error");
        assert!(err.iter().any(|e| {
            e.message
                .contains("is only valid in tc/tcx egress programs")
        }));
    }
}

#[test]
fn test_verify_mir_for_probe_context_tc_egress_skb_metadata_helpers_reject_unsupported_program() {
    for (helper, extra_args) in [
        (BpfHelper::GetCgroupClassid, vec![]),
        (BpfHelper::GetRouteRealm, vec![]),
        (BpfHelper::SkbCgroupClassid, vec![]),
        (BpfHelper::SkbCgroupId, vec![]),
        (BpfHelper::SkbAncestorCgroupId, vec![MirValue::Const(0)]),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args: std::iter::once(MirValue::VReg(ctx))
                    .chain(extra_args.into_iter())
                    .collect(),
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected skb metadata helper unsupported-program context error");
        let expected = match helper {
            BpfHelper::GetCgroupClassid | BpfHelper::GetRouteRealm => {
                "is only valid in tc_action, tc, tcx, netkit, and lwt_* programs"
            }
            _ => "is only valid in tc_action, tc, tcx, and netkit programs",
        };
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "expected error containing {expected:?}, got {err:?}"
        );
    }
}

#[test]
fn test_verify_mir_rejects_subfn_calls_with_more_than_five_args() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    let mut args = Vec::new();
    for i in 0..6 {
        let v = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: v,
            src: MirValue::Const(i),
        });
        args.push(v);
    }
    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst,
        subfn: crate::compiler::mir::SubfunctionId(0),
        args,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected subfunction-arg count error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("at most 5 arguments")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_program_rejects_missing_tail_call_capability() {
    const LIMITED_CAPABILITIES: &[ProgramCapability] = &[ProgramCapability::Emit];

    let limited_program = ProgramTypeInfo {
        supported_capabilities: LIMITED_CAPABILITIES,
        ..*EbpfProgramType::Kprobe.info()
    };
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.block_mut(entry).terminator = MirInst::TailCall {
        prog_map: MapRef {
            name: "dispatch".to_string(),
            kind: MapKind::ProgArray,
        },
        index: MirValue::Const(0),
    };

    let err = verify_mir_for_program(&func, &HashMap::new(), &limited_program)
        .expect_err("expected tail-call capability rejection");
    assert!(
        err.iter().any(|e| e.message.contains("tail calls")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_program_rejects_missing_helper_call_capability() {
    const LIMITED_CAPABILITIES: &[ProgramCapability] = &[ProgramCapability::Emit];

    let limited_program = ProgramTypeInfo {
        supported_capabilities: LIMITED_CAPABILITIES,
        ..*EbpfProgramType::Kprobe.info()
    };
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetCurrentPidTgid as u32,
            args: vec![],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    let err = verify_mir_for_program(&func, &types, &limited_program)
        .expect_err("expected helper-call capability rejection");
    assert!(
        err.iter().any(|e| e.message.contains("helper calls")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_program_redirect_requires_zero_flags_in_xdp() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::Redirect as u32,
            args: vec![MirValue::Const(1), MirValue::Const(1)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected xdp redirect flags error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect' requires arg1 = 0 in xdp programs")
    }));
}

#[test]
fn test_verify_mir_for_program_redirect_allows_non_zero_flags_outside_xdp() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::Redirect as u32,
            args: vec![MirValue::Const(1), MirValue::Const(1)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    verify_mir_for_program(&func, &types, EbpfProgramType::Tc.info())
        .expect("expected tc redirect flags to remain allowed");
}

#[test]
fn test_verify_mir_for_probe_context_sockopt_helpers_reject_invalid_program() {
    for (helper, probe_ctx, expected) in [
        (
            BpfHelper::SetSockOpt,
            ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read"),
            "helper 'bpf_setsockopt' is only valid in sock_ops, cgroup_sock_addr, and cgroup_sockopt programs",
        ),
        (
            BpfHelper::GetSockOpt,
            ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read"),
            "helper 'bpf_getsockopt' is only valid in sock_ops, cgroup_sock_addr, and cgroup_sockopt programs",
        ),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let optval_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args: vec![
                    MirValue::VReg(ctx),
                    MirValue::Const(1),
                    MirValue::Const(2),
                    MirValue::StackSlot(optval_slot),
                    MirValue::Const(16),
                ],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected sockopt helper program-surface error");
        assert!(err.iter().any(|e| e.message.contains(expected)));
    }
}

#[test]
fn test_verify_mir_for_probe_context_sockopt_helpers_accept_supported_socket_contexts() {
    for probe_ctx in [
        ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4"),
        ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get"),
        ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:set"),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let optval_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: BpfHelper::GetSockOpt as u32,
                args: vec![
                    MirValue::VReg(ctx),
                    MirValue::Const(1),
                    MirValue::Const(2),
                    MirValue::StackSlot(optval_slot),
                    MirValue::Const(16),
                ],
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: BpfHelper::SetSockOpt as u32,
                args: vec![
                    MirValue::VReg(ctx),
                    MirValue::Const(1),
                    MirValue::Const(2),
                    MirValue::StackSlot(optval_slot),
                    MirValue::Const(16),
                ],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected sockopt helpers to verify on cgroup_sockopt");
    }
}

fn make_cgroup_retval_verify_call(helper: BpfHelper) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    let args = if matches!(helper, BpfHelper::SetRetval) {
        vec![MirValue::Const(-1)]
    } else {
        Vec::new()
    };
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);
    (func, types)
}

#[test]
fn test_verify_mir_for_probe_context_cgroup_retval_helpers_accept_supported_contexts() {
    for (helper, probe_ctx) in [
        (
            BpfHelper::GetRetval,
            ProbeContext::new(EbpfProgramType::CgroupDevice, "/sys/fs/cgroup"),
        ),
        (
            BpfHelper::SetRetval,
            ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create"),
        ),
        (
            BpfHelper::GetRetval,
            ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get"),
        ),
        (
            BpfHelper::SetRetval,
            ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:sendmsg4"),
        ),
        (
            BpfHelper::GetRetval,
            ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup"),
        ),
    ] {
        let (func, types) = make_cgroup_retval_verify_call(helper);
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected cgroup retval helper to verify");
    }
}

#[test]
fn test_verify_mir_for_probe_context_cgroup_retval_helpers_reject_invalid_contexts() {
    for (helper, probe_ctx, expected) in [
        (
            BpfHelper::GetRetval,
            ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read"),
            "helper 'bpf_get_retval' is only valid in cgroup_device, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, and cgroup_sysctl programs",
        ),
        (
            BpfHelper::SetRetval,
            ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress"),
            "helper 'bpf_set_retval' is only valid in cgroup_device, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, and cgroup_sysctl programs",
        ),
        (
            BpfHelper::GetRetval,
            ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup"),
            "helper 'bpf_get_retval' is only valid in cgroup_device, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, and cgroup_sysctl programs",
        ),
        (
            BpfHelper::SetRetval,
            ProbeContext::new(
                EbpfProgramType::CgroupSockAddr,
                "/sys/fs/cgroup:getsockname4",
            ),
            "helper 'bpf_set_retval' is not valid on cgroup_sock_addr recvmsg/getpeername/getsockname hooks",
        ),
    ] {
        let (func, types) = make_cgroup_retval_verify_call(helper);
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected cgroup retval helper program-surface error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "unexpected errors: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_program_redirect_rejects_non_packet_programs() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::Redirect as u32,
            args: vec![MirValue::Const(1), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Kprobe.info())
        .expect_err("expected redirect helper program-surface error");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "helper 'bpf_redirect' is only valid in xdp, tc_action, tc, tcx, netkit, and lwt_xmit programs",
        )
    }));
}

#[test]
fn test_verify_mir_for_program_redirect_neigh_rejects_non_tc_programs() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::RedirectNeigh as u32,
            args: vec![
                MirValue::Const(1),
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected redirect_neigh helper program-surface error");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "helper 'bpf_redirect_neigh' is only valid in tc_action, tc, tcx, and netkit programs",
        )
    }));
}

#[test]
fn test_verify_mir_for_program_msg_apply_bytes_rejects_non_sk_msg_programs() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::MsgApplyBytes as u32,
            args: vec![MirValue::Const(0), MirValue::Const(1)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Kprobe.info())
        .expect_err("expected sk_msg helper program-surface error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_msg_apply_bytes' is only valid in sk_msg programs")
    }));
}

#[test]
fn test_verify_mir_for_program_socket_map_helpers_reject_invalid_programs() {
    for (helper, expected) in [
        (
            BpfHelper::SockMapUpdate,
            "helper 'bpf_sock_map_update' is only valid in sock_ops programs",
        ),
        (
            BpfHelper::SockHashUpdate,
            "helper 'bpf_sock_hash_update' is only valid in sock_ops programs",
        ),
        (
            BpfHelper::MsgRedirectMap,
            "helper 'bpf_msg_redirect_map' is only valid in sk_msg programs",
        ),
        (
            BpfHelper::MsgRedirectHash,
            "helper 'bpf_msg_redirect_hash' is only valid in sk_msg programs",
        ),
        (
            BpfHelper::SkRedirectMap,
            "helper 'bpf_sk_redirect_map' is only valid in sk_skb and sk_skb_parser programs",
        ),
        (
            BpfHelper::SkRedirectHash,
            "helper 'bpf_sk_redirect_hash' is only valid in sk_skb and sk_skb_parser programs",
        ),
        (
            BpfHelper::SkSelectReuseport,
            "helper 'bpf_sk_select_reuseport' is only valid in sk_reuseport programs",
        ),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let key_slot = func.alloc_stack_slot(4, 4, StackSlotKind::StringBuffer);
        let args = match helper {
            BpfHelper::SockMapUpdate | BpfHelper::SockHashUpdate => vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(key_slot),
                MirValue::Const(0),
            ],
            BpfHelper::MsgRedirectMap | BpfHelper::SkRedirectMap => vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
            BpfHelper::MsgRedirectHash | BpfHelper::SkRedirectHash => vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(key_slot),
                MirValue::Const(0),
            ],
            BpfHelper::SkSelectReuseport => vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(key_slot),
                MirValue::Const(0),
            ],
            _ => unreachable!(),
        };

        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args,
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir_for_program(&func, &types, EbpfProgramType::Kprobe.info())
            .expect_err("expected socket-map helper program-surface error");
        assert!(err.iter().any(|e| e.message.contains(expected)));
    }
}

#[test]
fn test_verify_mir_for_program_socket_map_helpers_accept_supported_programs() {
    for (helper, program_info) in [
        (BpfHelper::SockMapUpdate, EbpfProgramType::SockOps.info()),
        (BpfHelper::SockHashUpdate, EbpfProgramType::SockOps.info()),
        (BpfHelper::MsgRedirectMap, EbpfProgramType::SkMsg.info()),
        (BpfHelper::MsgRedirectHash, EbpfProgramType::SkMsg.info()),
        (BpfHelper::SkRedirectMap, EbpfProgramType::SkSkb.info()),
        (
            BpfHelper::SkRedirectHash,
            EbpfProgramType::SkSkbParser.info(),
        ),
        (
            BpfHelper::SkSelectReuseport,
            EbpfProgramType::SkReuseport.info(),
        ),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let key_slot = func.alloc_stack_slot(4, 4, StackSlotKind::StringBuffer);
        let args = match helper {
            BpfHelper::SockMapUpdate | BpfHelper::SockHashUpdate => vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(key_slot),
                MirValue::Const(0),
            ],
            BpfHelper::MsgRedirectMap | BpfHelper::SkRedirectMap => vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
            BpfHelper::MsgRedirectHash | BpfHelper::SkRedirectHash => vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(key_slot),
                MirValue::Const(0),
            ],
            BpfHelper::SkSelectReuseport => vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(key_slot),
                MirValue::Const(0),
            ],
            _ => unreachable!(),
        };

        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args,
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        verify_mir_for_program(&func, &types, program_info)
            .expect("expected socket-map helper in supported program");
    }
}

#[test]
fn test_verify_mir_for_probe_context_sock_ops_callback_sensitive_helpers_without_static_callback_proof()
 {
    for helper in [
        BpfHelper::SockOpsCbFlagsSet,
        BpfHelper::LoadHdrOpt,
        BpfHelper::StoreHdrOpt,
        BpfHelper::ReserveHdrOpt,
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let args = match helper {
            BpfHelper::SockOpsCbFlagsSet => vec![MirValue::VReg(ctx), MirValue::Const(0)],
            BpfHelper::LoadHdrOpt | BpfHelper::StoreHdrOpt => vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(16),
                MirValue::Const(0),
            ],
            BpfHelper::ReserveHdrOpt => {
                vec![MirValue::VReg(ctx), MirValue::Const(16), MirValue::Const(0)]
            }
            _ => unreachable!(),
        };

        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args,
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected sock_ops callback-sensitive helper to verify");
    }
}

#[test]
fn test_verify_mir_for_program_redirect_map_helper_rejects_invalid_programs() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_redirect_map".to_string(),
            kind: MapKind::DevMap,
        },
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::RedirectMap as u32,
            args: vec![MirValue::VReg(map), MirValue::Const(0), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map,
        MirType::MapRef {
            key_ty: Box::new(MirType::U32),
            val_ty: Box::new(MirType::Unknown),
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Kprobe.info())
        .expect_err("expected redirect_map helper program-surface error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect_map' is only valid in xdp programs")
    }));
}

#[test]
fn test_verify_mir_for_program_redirect_map_helper_accepts_xdp() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_redirect_map".to_string(),
            kind: MapKind::DevMapHash,
        },
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::RedirectMap as u32,
            args: vec![
                MirValue::VReg(map),
                MirValue::Const(7),
                MirValue::Const(0x1b),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map,
        MirType::MapRef {
            key_ty: Box::new(MirType::U32),
            val_ty: Box::new(MirType::Unknown),
        },
    );
    types.insert(dst, MirType::I64);

    verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect("expected redirect_map helper in xdp program");
}

#[test]
fn test_verify_mir_for_program_redirect_map_helper_rejects_invalid_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_redirect_map".to_string(),
            kind: MapKind::DevMapHash,
        },
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::RedirectMap as u32,
            args: vec![MirValue::VReg(map), MirValue::Const(7), MirValue::Const(4)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map,
        MirType::MapRef {
            key_ty: Box::new(MirType::U32),
            val_ty: Box::new(MirType::Unknown),
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected redirect_map helper invalid flags error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect_map' requires arg2 flags")
    }));
}

#[test]
fn test_verify_mir_for_program_perf_event_output_helper_rejects_lsm() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_perf_events".to_string(),
            kind: MapKind::PerfEventArray,
        },
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::PerfEventOutput as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::VReg(map),
                MirValue::Const(0),
                MirValue::StackSlot(data_slot),
                MirValue::Const(8),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        map,
        MirType::MapRef {
            key_ty: Box::new(MirType::U32),
            val_ty: Box::new(MirType::U32),
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Lsm.info())
        .expect_err("expected perf_event_output helper program-surface error");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_perf_event_output' is only valid in cgroup_device, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, cgroup_sysctl, kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf, socket_filter, lwt_*, tc_action, tc, tcx, netkit, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops, and xdp programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_perf_event_output_helper_accepts_lwt() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_perf_events".to_string(),
            kind: MapKind::PerfEventArray,
        },
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::PerfEventOutput as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::VReg(map),
                MirValue::Const(0),
                MirValue::StackSlot(data_slot),
                MirValue::Const(8),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        map,
        MirType::MapRef {
            key_ty: Box::new(MirType::U32),
            val_ty: Box::new(MirType::U32),
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::LwtOut, "demo-route");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected perf_event_output helper in lwt_out program");
}

fn make_perf_event_read_verify_call(
    helper: BpfHelper,
    flags: i64,
    size: i64,
    buf_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_perf_events".to_string(),
            kind: MapKind::PerfEventArray,
        },
    });

    let args = if matches!(helper, BpfHelper::PerfEventRead) {
        vec![MirValue::VReg(map), MirValue::Const(flags)]
    } else {
        let buf_slot = func.alloc_stack_slot(buf_size, 8, StackSlotKind::StringBuffer);
        vec![
            MirValue::VReg(map),
            MirValue::Const(flags),
            MirValue::StackSlot(buf_slot),
            MirValue::Const(size),
        ]
    };

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map,
        MirType::MapRef {
            key_ty: Box::new(MirType::U32),
            val_ty: Box::new(MirType::U32),
        },
    );
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_perf_event_read_helpers() {
    for helper in [BpfHelper::PerfEventRead, BpfHelper::PerfEventReadValue] {
        let (func, types) = make_perf_event_read_verify_call(helper, 0, 24, 24);
        verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
            .expect("expected perf event read helper to verify");
    }
}

#[test]
fn test_verify_mir_perf_event_read_value_requires_exact_size() {
    let (func, types) = make_perf_event_read_verify_call(BpfHelper::PerfEventReadValue, 0, 8, 24);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected perf_event_read_value size error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_perf_event_read_value' requires arg3 = 24")
    }));
}

#[test]
fn test_verify_mir_perf_event_read_value_rejects_small_buffer() {
    let (func, types) = make_perf_event_read_verify_call(BpfHelper::PerfEventReadValue, 0, 24, 8);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected perf_event_read_value buffer bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper perf_event_read_value buf out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_perf_event_read_helpers_reject_invalid_flags() {
    for helper in [BpfHelper::PerfEventRead, BpfHelper::PerfEventReadValue] {
        let (func, types) = make_perf_event_read_verify_call(helper, 0x1_0000_0000, 24, 24);
        let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
            .expect_err("expected perf_event_read flags error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("perf event read helpers require arg1 flags")),
            "unexpected errors for {:?}: {:?}",
            helper,
            err
        );
    }
}

fn make_get_ns_current_pid_tgid_verify_call(
    size: i64,
    buf_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    let nsdata_slot = func.alloc_stack_slot(buf_size, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetNsCurrentPidTgid as u32,
            args: vec![
                MirValue::Const(1),
                MirValue::Const(2),
                MirValue::StackSlot(nsdata_slot),
                MirValue::Const(size),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_get_ns_current_pid_tgid_helper() {
    let (func, types) = make_get_ns_current_pid_tgid_verify_call(8, 8);
    verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect("expected bpf_get_ns_current_pid_tgid helper to verify");
}

#[test]
fn test_verify_mir_get_ns_current_pid_tgid_requires_exact_size() {
    let (func, types) = make_get_ns_current_pid_tgid_verify_call(4, 8);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected bpf_get_ns_current_pid_tgid size error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_get_ns_current_pid_tgid' requires arg3 = 8")
    }));
}

#[test]
fn test_verify_mir_get_ns_current_pid_tgid_rejects_small_buffer() {
    let (func, types) = make_get_ns_current_pid_tgid_verify_call(8, 4);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected bpf_get_ns_current_pid_tgid bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_ns_current_pid_tgid nsdata out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_strtox_verify_call(
    helper: BpfHelper,
    buf_len: i64,
    flags: i64,
    buf_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(buf_size, 8, StackSlotKind::StringBuffer);
    let res_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: vec![
                MirValue::StackSlot(buf_slot),
                MirValue::Const(buf_len),
                MirValue::Const(flags),
                MirValue::StackSlot(res_slot),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    (func, types)
}

fn make_strncmp_verify_call(
    s1_len: i64,
    s1_size: usize,
    s2_on_stack: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    let s1_slot = func.alloc_stack_slot(s1_size, 8, StackSlotKind::StringBuffer);
    let s2 = if s2_on_stack {
        let s2_slot = func.alloc_stack_slot(8, 1, StackSlotKind::StringBuffer);
        MirValue::StackSlot(s2_slot)
    } else {
        let s2 = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadGlobal {
                dst: s2,
                symbol: "__nu_rodata_needle".to_string(),
                ty: MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: 8,
                },
            });
        MirValue::VReg(s2)
    };
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::Strncmp as u32,
            args: vec![MirValue::StackSlot(s1_slot), MirValue::Const(s1_len), s2],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_strtox_helpers() {
    for helper in [BpfHelper::Strtol, BpfHelper::Strtoul] {
        let (func, types) = make_strtox_verify_call(helper, 8, 16, 8);
        verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
            .expect("expected string conversion helper to verify");
    }
}

#[test]
fn test_verify_mir_strncmp_helper_accepts_rodata_s2() {
    let (func, types) = make_strncmp_verify_call(8, 8, false);
    verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect("expected strncmp helper to verify");
}

#[test]
fn test_verify_mir_strncmp_helper_rejects_small_s1_buffer() {
    let (func, types) = make_strncmp_verify_call(16, 8, false);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected strncmp buffer bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper strncmp s1 out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_strncmp_helper_rejects_stack_s2() {
    let (func, types) = make_strncmp_verify_call(8, 8, true);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected strncmp read-only string error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper strncmp s2 expects pointer in [Map]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_strtox_helper_rejects_small_buffer() {
    let (func, types) = make_strtox_verify_call(BpfHelper::Strtol, 16, 0, 8);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected string conversion buffer bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper strtox buf out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_strtox_helper_rejects_invalid_flags() {
    for (helper, flags) in [(BpfHelper::Strtol, 2), (BpfHelper::Strtoul, 32)] {
        let (func, types) = make_strtox_verify_call(helper, 8, flags, 8);
        let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
            .expect_err("expected string conversion flags error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("requires arg2 flags to be one of 0, 8, 10, or 16")),
            "unexpected errors: {:?}",
            err
        );
    }
}

fn make_packet_output_verify_call(
    helper: BpfHelper,
    size: i64,
    data_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let data_slot = func.alloc_stack_slot(data_size, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_packet_events".to_string(),
            kind: MapKind::PerfEventArray,
        },
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::VReg(map),
                MirValue::Const(0),
                MirValue::StackSlot(data_slot),
                MirValue::Const(size),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        map,
        MirType::MapRef {
            key_ty: Box::new(MirType::U32),
            val_ty: Box::new(MirType::U32),
        },
    );
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_for_probe_context_packet_output_helpers_accept_tracing_programs() {
    for (helper, probe_ctx) in [
        (
            BpfHelper::SkbOutput,
            ProbeContext::new(EbpfProgramType::Fentry, "netif_receive_skb"),
        ),
        (
            BpfHelper::XdpOutput,
            ProbeContext::new(EbpfProgramType::Tracepoint, "net:netif_receive_skb"),
        ),
    ] {
        let (func, types) = make_packet_output_verify_call(helper, 8, 8);
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected packet output helper to verify");
    }
}

#[test]
fn test_verify_mir_for_probe_context_packet_output_helper_rejects_packet_program() {
    let (func, types) = make_packet_output_verify_call(BpfHelper::XdpOutput, 8, 8);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_xdp_output to be rejected in xdp program");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_xdp_output' is only valid in kprobe")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_packet_output_helper_rejects_small_data_buffer() {
    let (func, types) = make_packet_output_verify_call(BpfHelper::SkbOutput, 16, 8);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "netif_receive_skb");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_output data bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper packet_output data out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_program_get_stackid_helper_rejects_xdp() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_stacks".to_string(),
            kind: MapKind::StackTrace,
        },
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetStackId as u32,
            args: vec![MirValue::VReg(ctx), MirValue::VReg(map), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        map,
        MirType::MapRef {
            key_ty: Box::new(MirType::U32),
            val_ty: Box::new(MirType::Unknown),
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected get_stackid helper program-surface error");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_get_stackid' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, and tp_btf programs"
    )));
}

#[test]
fn test_verify_mir_for_program_get_stack_helper_rejects_xdp() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetStack as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(32),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected get_stack helper program-surface error");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_get_stack' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, and tp_btf programs"
    )));
}

#[test]
fn test_verify_mir_get_stack_allows_zero_size_buffer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetStack as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(0),
                MirValue::Const(0x09ff),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    verify_mir_for_program(&func, &types, EbpfProgramType::Kprobe.info())
        .expect("expected get_stack zero-size buffer to pass");
}

#[test]
fn test_verify_mir_get_stack_rejects_invalid_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetStack as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(0),
                MirValue::Const(0x0200),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Kprobe.info())
        .expect_err("expected get_stack invalid flags error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("stack-copy helpers require flags")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_get_stack_rejects_small_stack_buffer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetStack as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(64),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Kprobe.info())
        .expect_err("expected get_stack stack buffer bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper get_stack buf out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_get_stack_rejects_negative_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetStack as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(-1),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Kprobe.info())
        .expect_err("expected get_stack negative-size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 67 arg2 must be >= 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_program_probe_read_helper_rejects_xdp() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let dst = func.alloc_vreg();
    let out_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::ProbeRead as u32,
            args: vec![
                MirValue::StackSlot(out_slot),
                MirValue::Const(8),
                MirValue::VReg(ctx),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected probe_read helper program-surface error");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_probe_read' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, lsm, lsm_cgroup, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, and tp_btf programs"
    )));
}

#[test]
fn test_verify_mir_for_program_probe_read_str_helper_accepts_kprobe() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    let out_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::ProbeReadStr as u32,
            args: vec![
                MirValue::StackSlot(out_slot),
                MirValue::Const(16),
                MirValue::StackSlot(src_slot),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    verify_mir_for_program(&func, &types, EbpfProgramType::Kprobe.info())
        .expect("expected probe_read_str helper in kprobe program");
}

#[test]
fn test_verify_mir_for_program_probe_read_str_helper_rejects_xdp() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let dst = func.alloc_vreg();
    let out_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::ProbeReadStr as u32,
            args: vec![
                MirValue::StackSlot(out_slot),
                MirValue::Const(8),
                MirValue::VReg(ctx),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected probe_read_str helper program-surface error");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_probe_read_str' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, lsm, lsm_cgroup, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, and tp_btf programs"
    )));
}

#[test]
fn test_verify_mir_for_program_skb_packet_edit_helpers_reject_invalid_programs() {
    for helper in [
        BpfHelper::SkbStoreBytes,
        BpfHelper::L3CsumReplace,
        BpfHelper::L4CsumReplace,
        BpfHelper::CloneRedirect,
        BpfHelper::GetHashRecalc,
        BpfHelper::SkbChangeTail,
        BpfHelper::SkbPullData,
        BpfHelper::CsumUpdate,
        BpfHelper::CsumLevel,
        BpfHelper::SetHashInvalid,
        BpfHelper::SetHash,
        BpfHelper::SkbChangeHead,
        BpfHelper::SkbVlanPush,
        BpfHelper::SkbVlanPop,
        BpfHelper::SkbAdjustRoom,
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let buf_slot = func.alloc_stack_slot(4, 4, StackSlotKind::StringBuffer);
        let args = match helper {
            BpfHelper::SkbStoreBytes => vec![
                MirValue::Const(0),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(4),
                MirValue::Const(0),
            ],
            BpfHelper::L3CsumReplace | BpfHelper::L4CsumReplace => vec![
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
            BpfHelper::CloneRedirect => vec![MirValue::Const(1), MirValue::Const(0)],
            BpfHelper::GetHashRecalc | BpfHelper::SetHashInvalid => vec![],
            BpfHelper::SetHash => vec![MirValue::Const(0)],
            BpfHelper::SkbChangeTail | BpfHelper::SkbChangeHead => {
                vec![MirValue::Const(64), MirValue::Const(0)]
            }
            BpfHelper::SkbVlanPush => vec![MirValue::Const(0x8100), MirValue::Const(1)],
            BpfHelper::SkbVlanPop => vec![],
            BpfHelper::SkbPullData | BpfHelper::CsumUpdate | BpfHelper::CsumLevel => {
                vec![MirValue::Const(64)]
            }
            BpfHelper::SkbAdjustRoom => {
                vec![MirValue::Const(14), MirValue::Const(0), MirValue::Const(0)]
            }
            _ => unreachable!(),
        };
        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args: std::iter::once(MirValue::VReg(ctx))
                    .chain(args.into_iter())
                    .collect(),
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir_for_program(&func, &types, EbpfProgramType::Kprobe.info())
            .expect_err("expected skb packet-edit helper program-surface error");
        let expected = match helper {
            BpfHelper::GetHashRecalc | BpfHelper::SkbPullData => {
                "is only valid in lwt_*, tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser programs"
            }
            BpfHelper::SkbStoreBytes
            | BpfHelper::L3CsumReplace
            | BpfHelper::L4CsumReplace
            | BpfHelper::CloneRedirect
            | BpfHelper::SkbChangeTail
            | BpfHelper::CsumUpdate
            | BpfHelper::CsumLevel
            | BpfHelper::SetHashInvalid
            | BpfHelper::SkbChangeHead => {
                "is only valid in lwt_xmit, tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser programs"
            }
            _ => "is only valid in tc_action, tc, tcx, netkit, sk_skb, and sk_skb_parser programs",
        };
        assert!(err.iter().any(|e| { e.message.contains(expected) }));
    }
}

#[test]
fn test_verify_mir_for_program_lwt_skb_helpers() {
    for (program_type, helper, args) in [
        (EbpfProgramType::LwtOut, BpfHelper::GetHashRecalc, vec![]),
        (
            EbpfProgramType::LwtOut,
            BpfHelper::SkbPullData,
            vec![MirValue::Const(64)],
        ),
        (
            EbpfProgramType::TcAction,
            BpfHelper::SkbPullData,
            vec![MirValue::Const(64)],
        ),
        (
            EbpfProgramType::LwtXmit,
            BpfHelper::SkbStoreBytes,
            vec![
                MirValue::Const(0),
                MirValue::StackSlot(StackSlotId(0)),
                MirValue::Const(4),
                MirValue::Const(0),
            ],
        ),
        (
            EbpfProgramType::LwtXmit,
            BpfHelper::SkbChangeHead,
            vec![MirValue::Const(14), MirValue::Const(0)],
        ),
        (
            EbpfProgramType::TcAction,
            BpfHelper::SkbChangeHead,
            vec![MirValue::Const(14), MirValue::Const(0)],
        ),
        (
            EbpfProgramType::LwtXmit,
            BpfHelper::CloneRedirect,
            vec![MirValue::Const(1), MirValue::Const(0)],
        ),
        (
            EbpfProgramType::TcAction,
            BpfHelper::SkbAdjustRoom,
            vec![MirValue::Const(14), MirValue::Const(0), MirValue::Const(0)],
        ),
        (EbpfProgramType::LwtXmit, BpfHelper::SetHashInvalid, vec![]),
        (
            EbpfProgramType::LwtXmit,
            BpfHelper::CsumLevel,
            vec![MirValue::Const(0)],
        ),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let buf_slot = func.alloc_stack_slot(4, 4, StackSlotKind::StringBuffer);
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let args = args
            .into_iter()
            .map(|arg| match arg {
                MirValue::StackSlot(StackSlotId(0)) => MirValue::StackSlot(buf_slot),
                other => other,
            })
            .collect::<Vec<_>>();
        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args: std::iter::once(MirValue::VReg(ctx))
                    .chain(args.into_iter())
                    .collect(),
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        verify_mir_for_program(&func, &types, program_type.info())
            .expect("expected lwt skb helper to verify");
    }
}

fn make_skb_ecn_set_ce_verify_call() -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkbEcnSetCe as u32,
            args: vec![MirValue::VReg(ctx)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_for_probe_context_skb_ecn_set_ce_accepts_tc_and_cgroup_skb_programs() {
    for probe_ctx in [
        ProbeContext::new(EbpfProgramType::Tc, "lo:ingress"),
        ProbeContext::new(EbpfProgramType::TcAction, "demo-action"),
        ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup"),
    ] {
        let (func, types) = make_skb_ecn_set_ce_verify_call();
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected bpf_skb_ecn_set_ce helper to verify");
    }
}

#[test]
fn test_verify_mir_for_probe_context_skb_ecn_set_ce_rejects_non_tc_cgroup_skb_program() {
    let (func, types) = make_skb_ecn_set_ce_verify_call();
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_ecn_set_ce to be rejected outside tc/cgroup_skb");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_skb_ecn_set_ce' is only valid in tc_action, tc, tcx, netkit, and cgroup_skb programs"
    )));
}

fn make_skb_change_proto_verify_call(flags: i64) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkbChangeProto as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(0x86dd),
                MirValue::Const(flags),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    (func, types)
}

fn make_skb_change_type_verify_call() -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkbChangeType as u32,
            args: vec![MirValue::VReg(ctx), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_for_probe_context_skb_change_proto_and_type_accept_tc_programs() {
    for (func, types) in [
        make_skb_change_proto_verify_call(0),
        make_skb_change_type_verify_call(),
    ] {
        for probe_ctx in [
            ProbeContext::new(EbpfProgramType::Tc, "lo:ingress"),
            ProbeContext::new(EbpfProgramType::TcAction, "demo-action"),
        ] {
            verify_mir_for_probe_context(&func, &types, &probe_ctx)
                .expect("expected skb change helper to verify");
        }
    }
}

#[test]
fn test_verify_mir_for_probe_context_skb_change_proto_and_type_reject_non_tc_programs() {
    let proto = make_skb_change_proto_verify_call(0);
    let ty = make_skb_change_type_verify_call();
    for (func, types, expected) in [
        (
            proto.0,
            proto.1,
            "helper 'bpf_skb_change_proto' is only valid in tc_action, tc, tcx, and netkit programs",
        ),
        (
            ty.0,
            ty.1,
            "helper 'bpf_skb_change_type' is only valid in tc_action, tc, tcx, and netkit programs",
        ),
    ] {
        let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected skb change helper to be rejected outside tc");
        assert!(err.iter().any(|e| e.message.contains(expected)));
    }
}

#[test]
fn test_verify_mir_for_probe_context_skb_change_proto_requires_zero_flags() {
    let (func, types) = make_skb_change_proto_verify_call(1);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_change_proto flags to require zero");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_skb_change_proto' requires arg2 = 0")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_skb_store_bytes_accepts_in_bounds_source_buffer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let ctx = func.alloc_vreg();
    let len = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(4, 4, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: len,
        src: MirValue::Const(4),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkbStoreBytes as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(0),
                MirValue::StackSlot(buf_slot),
                MirValue::VReg(len),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(len, MirType::I64);
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected skb_store_bytes to accept in-bounds stack buffer");
}

#[test]
fn test_verify_mir_for_probe_context_skb_store_bytes_rejects_out_of_bounds_source_buffer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let ctx = func.alloc_vreg();
    let len = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(2, 2, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: len,
        src: MirValue::Const(4),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkbStoreBytes as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(0),
                MirValue::StackSlot(buf_slot),
                MirValue::VReg(len),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(len, MirType::I64);
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected skb_store_bytes to reject out-of-bounds stack buffer");
    assert!(
        err.iter().any(|e| e.message.contains("out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_skb_store_bytes_rejects_invalid_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(4, 4, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkbStoreBytes as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(0),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(4),
                MirValue::Const(4),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_store_bytes flag validation error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_skb_store_bytes' requires arg4 flags")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_csum_diff_allows_null_zero_side() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let dst = func.alloc_vreg();
    let to_slot = func.alloc_stack_slot(4, 4, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::CsumDiff as u32,
            args: vec![
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::StackSlot(to_slot),
                MirValue::Const(4),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    for probe_ctx in [
        ProbeContext::new(EbpfProgramType::Xdp, "lo"),
        ProbeContext::new(EbpfProgramType::LwtOut, "demo-route"),
    ] {
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected csum_diff to accept null from with zero from_size");
    }
}

#[test]
fn test_verify_mir_read_branch_records_allows_null_zero_buffer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::ReadBranchRecords as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::Const(1),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(
        EbpfProgramType::PerfEvent,
        "hardware:branch-instructions:period=100000",
    );
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected read_branch_records to accept null buffer with zero size");
}

#[test]
fn test_verify_mir_read_branch_records_rejects_null_nonzero_buffer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::ReadBranchRecords as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(0),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(
        EbpfProgramType::PerfEvent,
        "hardware:branch-instructions:period=100000",
    );
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected read_branch_records to reject null buffer with nonzero size");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 119 arg1 requires arg2 = 0 when arg1 is null")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_read_branch_records_rejects_invalid_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf = func.alloc_stack_slot(24, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::ReadBranchRecords as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(buf),
                MirValue::Const(24),
                MirValue::Const(2),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(
        EbpfProgramType::PerfEvent,
        "hardware:branch-instructions:period=100000",
    );
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected read_branch_records to reject invalid flags");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_read_branch_records' requires arg3 flags")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_get_branch_snapshot_verify_call(
    size: i64,
    buf_size: usize,
    flags: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    let entries_slot = func.alloc_stack_slot(buf_size, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetBranchSnapshot as u32,
            args: vec![
                MirValue::StackSlot(entries_slot),
                MirValue::Const(size),
                MirValue::Const(flags),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_get_branch_snapshot_helper() {
    let (func, types) = make_get_branch_snapshot_verify_call(24, 24, 0);
    verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect("expected bpf_get_branch_snapshot helper to verify");
}

#[test]
fn test_verify_mir_get_branch_snapshot_allows_null_zero_buffer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetBranchSnapshot as u32,
            args: vec![MirValue::Const(0), MirValue::Const(0), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect("expected bpf_get_branch_snapshot null query to verify");
}

#[test]
fn test_verify_mir_get_branch_snapshot_rejects_null_nonzero_buffer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetBranchSnapshot as u32,
            args: vec![MirValue::Const(0), MirValue::Const(24), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected bpf_get_branch_snapshot to reject null buffer with nonzero size");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 176 arg0 requires arg1 = 0 when arg0 is null")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_get_branch_snapshot_rejects_small_buffer() {
    let (func, types) = make_get_branch_snapshot_verify_call(24, 8, 0);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected bpf_get_branch_snapshot bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_branch_snapshot entries out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_get_branch_snapshot_requires_zero_flags() {
    let (func, types) = make_get_branch_snapshot_verify_call(24, 24, 1);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected bpf_get_branch_snapshot flags error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_get_branch_snapshot' requires arg2 = 0")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_csum_diff_rejects_null_nonzero_side() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let dst = func.alloc_vreg();
    let to_slot = func.alloc_stack_slot(4, 4, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::CsumDiff as u32,
            args: vec![
                MirValue::Const(0),
                MirValue::Const(4),
                MirValue::StackSlot(to_slot),
                MirValue::Const(4),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected csum_diff to reject null from with nonzero from_size");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 28 arg0 requires arg1 = 0 when arg0 is null")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_csum_diff_rejects_unaligned_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let dst = func.alloc_vreg();
    let from_slot = func.alloc_stack_slot(4, 4, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::CsumDiff as u32,
            args: vec![
                MirValue::StackSlot(from_slot),
                MirValue::Const(2),
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected csum_diff to reject non-word-sized from_size");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_csum_diff' requires arg1 to be a multiple of 4")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_program_packet_byte_helpers_reject_invalid_programs() {
    for (helper, program_info, expected) in [
        (
            BpfHelper::SkbLoadBytes,
            EbpfProgramType::Kprobe.info(),
            "helper 'bpf_skb_load_bytes' is only valid in flow_dissector, socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, sk_reuseport, sk_skb, and sk_skb_parser programs",
        ),
        (
            BpfHelper::SkbLoadBytesRelative,
            EbpfProgramType::SkSkb.info(),
            "helper 'bpf_skb_load_bytes_relative' is only valid in socket_filter, tc_action, tc, tcx, netkit, cgroup_skb, and sk_reuseport programs",
        ),
        (
            BpfHelper::XdpLoadBytes,
            EbpfProgramType::Tc.info(),
            "helper 'bpf_xdp_load_bytes' is only valid in xdp programs",
        ),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let mut args = vec![
            MirValue::VReg(ctx),
            MirValue::Const(0),
            MirValue::StackSlot(buf_slot),
            MirValue::Const(16),
        ];
        if matches!(helper, BpfHelper::SkbLoadBytesRelative) {
            args.push(MirValue::Const(0));
        }
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args,
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir_for_program(&func, &types, program_info)
            .expect_err("expected packet-byte helper program-surface error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "unexpected errors: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_program_packet_byte_helpers_accept_allowed_programs() {
    for (helper, program_info, args_len) in [
        (
            BpfHelper::SkbLoadBytes,
            EbpfProgramType::SkReuseport.info(),
            4,
        ),
        (
            BpfHelper::SkbLoadBytesRelative,
            EbpfProgramType::SkReuseport.info(),
            5,
        ),
        (
            BpfHelper::SkbLoadBytes,
            EbpfProgramType::FlowDissector.info(),
            4,
        ),
        (BpfHelper::SkbLoadBytes, EbpfProgramType::TcAction.info(), 4),
        (
            BpfHelper::SkbLoadBytesRelative,
            EbpfProgramType::TcAction.info(),
            5,
        ),
        (BpfHelper::SkbLoadBytes, EbpfProgramType::LwtOut.info(), 4),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let block = func.block_mut(entry);
        block.instructions.push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
        let mut args = vec![
            MirValue::VReg(ctx),
            MirValue::Const(0),
            MirValue::StackSlot(buf_slot),
            MirValue::Const(16),
        ];
        if args_len == 5 {
            args.push(MirValue::Const(0));
        }
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args,
        });
        block.terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        verify_mir_for_program(&func, &types, program_info).unwrap_or_else(|errs| {
            panic!(
                "expected {} to verify in {}: {:?}",
                helper.name(),
                program_info.canonical_prefix,
                errs
            )
        });
    }
}

#[test]
fn test_verify_mir_for_program_skb_load_bytes_relative_rejects_invalid_start_header() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkbLoadBytesRelative as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(0),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(16),
                MirValue::Const(2),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Tc.info())
        .expect_err("expected skb_load_bytes_relative start_header validation error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_skb_load_bytes_relative' requires arg4 start_header")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_skb_load_bytes_rejects_out_of_bounds_destination_buffer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(2, 2, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkbLoadBytes as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(0),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(4),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected skb_load_bytes to reject out-of-bounds stack buffer");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper skb_load_bytes to out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_program_sysctl_helpers_reject_non_sysctl_programs() {
    for (helper, extra_args) in [
        (
            BpfHelper::SysctlGetName,
            vec![
                MirValue::StackSlot(StackSlotId(0)),
                MirValue::Const(16),
                MirValue::Const(0),
            ],
        ),
        (
            BpfHelper::SysctlGetCurrentValue,
            vec![MirValue::StackSlot(StackSlotId(0)), MirValue::Const(16)],
        ),
        (
            BpfHelper::SysctlGetNewValue,
            vec![MirValue::StackSlot(StackSlotId(0)), MirValue::Const(16)],
        ),
        (
            BpfHelper::SysctlSetNewValue,
            vec![MirValue::StackSlot(StackSlotId(0)), MirValue::Const(16)],
        ),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args: std::iter::once(MirValue::VReg(ctx))
                    .chain(extra_args.into_iter().map(|arg| match arg {
                        MirValue::StackSlot(StackSlotId(0)) => MirValue::StackSlot(buf_slot),
                        other => other,
                    }))
                    .collect(),
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir_for_program(&func, &types, EbpfProgramType::Kprobe.info())
            .expect_err("expected sysctl helper program-surface error");
        assert!(err.iter().any(|e| {
            e.message.contains(&format!(
                "helper '{}' is only valid in cgroup_sysctl programs",
                helper.name()
            ))
        }));
    }
}

fn make_sysctl_get_name_verify_call(flags: i64) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SysctlGetName as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(16),
                MirValue::Const(flags),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);
    (func, types)
}

#[test]
fn test_verify_mir_sysctl_get_name_accepts_base_name_flag() {
    let (func, types) = make_sysctl_get_name_verify_call(1);
    verify_mir_for_program(&func, &types, EbpfProgramType::CgroupSysctl.info())
        .expect("expected sysctl get_name helper to verify");
}

#[test]
fn test_verify_mir_sysctl_get_name_rejects_invalid_flags() {
    let (func, types) = make_sysctl_get_name_verify_call(2);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::CgroupSysctl.info())
        .expect_err("expected sysctl get_name flags error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_sysctl_get_name' requires arg3 flags")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_redirect_neigh_requires_zero_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::RedirectNeigh as u32,
            args: vec![
                MirValue::Const(1),
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::Const(1),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected redirect_neigh flags error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect_neigh' requires arg3 = 0")
    }));
}

#[test]
fn test_verify_mir_helper_redirect_neigh_requires_zero_plen_for_zero_vreg_params() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let params = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: params,
        src: MirValue::Const(0),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::RedirectNeigh as u32,
            args: vec![
                MirValue::Const(1),
                MirValue::VReg(params),
                MirValue::Const(4),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(params, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected redirect_neigh plen error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect_neigh' requires arg2 = 0 when arg1 is null")
    }));
}

#[test]
fn test_verify_mir_helper_redirect_peer_requires_zero_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::RedirectPeer as u32,
            args: vec![MirValue::Const(1), MirValue::Const(1)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected redirect_peer flags error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect_peer' requires arg1 = 0")
    }));
}

#[test]
fn test_verify_mir_helper_store_hdr_opt_requires_zero_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::StoreHdrOpt as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(16),
                MirValue::Const(1),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected store_hdr_opt flags error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_store_hdr_opt' requires arg3 = 0")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_redirect_peer_rejects_tc_egress() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::RedirectPeer as u32,
            args: vec![MirValue::Const(1), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:egress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected redirect_peer tc-egress context error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect_peer' is only valid in tc/tcx ingress programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_redirect_peer_rejects_non_tc_program() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::RedirectPeer as u32,
            args: vec![MirValue::Const(1), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected redirect_peer non-tc program error");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "helper 'bpf_redirect_peer' is only valid in tc_action, tc, tcx, and netkit programs",
        )
    }));
}

#[test]
fn test_verify_mir_for_probe_context_sk_lookup_tcp_rejects_invalid_program() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkLookupTcp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(tuple_slot),
                MirValue::Const(16),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected sk_lookup_tcp helper program-surface error");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_sk_lookup_tcp' is only valid in xdp, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock_addr, and sk_skb programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_sk_lookup_tcp_accepts_xdp() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sock,
            helper: BpfHelper::SkLookupTcp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(tuple_slot),
                MirValue::Const(16),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: sock_non_null,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkRelease as u32,
            args: vec![MirValue::VReg(sock)],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(sock_non_null, MirType::Bool);
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected sk_lookup_tcp xdp context to verify");
}

fn make_socket_lookup_verify_call(
    helper: BpfHelper,
    flags: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(tuple_slot),
                MirValue::Const(16),
                MirValue::Const(0),
                MirValue::Const(flags),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_for_probe_context_socket_lookup_helpers_reject_nonzero_flags() {
    for helper in [
        BpfHelper::SkLookupTcp,
        BpfHelper::SkLookupUdp,
        BpfHelper::SkcLookupTcp,
    ] {
        let (func, types) = make_socket_lookup_verify_call(helper, 1);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected socket lookup flags error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("socket lookup helpers require arg4 flags = 0")),
            "unexpected errors for {:?}: {:?}",
            helper,
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_sk_assign_rejects_tc_egress() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkAssign as u32,
            args: vec![MirValue::VReg(ctx), MirValue::Const(0), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:egress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected sk_assign tc-egress context error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_sk_assign' is only valid in tc/tcx ingress programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_sk_assign_rejects_netkit() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkAssign as u32,
            args: vec![MirValue::VReg(ctx), MirValue::Const(0), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Netkit, "nk0:primary");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected sk_assign netkit context error");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "helper 'bpf_sk_assign' is only valid in tc_action, tc, tcx, and sk_lookup programs",
        )
    }));
}

#[test]
fn test_verify_mir_for_probe_context_sk_assign_requires_zero_flags_in_tc() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkAssign as u32,
            args: vec![MirValue::VReg(ctx), MirValue::Const(0), MirValue::Const(1)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected sk_assign tc flags error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_sk_assign' requires arg2 = 0 in tc programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_sk_assign_accepts_sk_lookup() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkAssign as u32,
            args: vec![MirValue::VReg(ctx), MirValue::Const(0), MirValue::Const(3)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected sk_assign sk_lookup context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_sk_assign_rejects_invalid_sk_lookup_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkAssign as u32,
            args: vec![MirValue::VReg(ctx), MirValue::Const(0), MirValue::Const(4)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected sk_assign invalid sk_lookup flags error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_sk_assign' requires arg2 flags")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_get_listener_sock_rejects_sk_lookup() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: sock,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetListenerSock as u32,
            args: vec![MirValue::VReg(sock)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected get_listener_sock sk_lookup program-surface error");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_get_listener_sock' is only valid in tc_action, tc, tcx, netkit, and cgroup_skb programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_get_listener_sock_accepts_cgroup_skb() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();
    let listener = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sock,
            helper: BpfHelper::SkLookupTcp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(tuple_slot),
                MirValue::Const(16),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: sock_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: listener,
        helper: BpfHelper::GetListenerSock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: cleanup_ret,
        helper: BpfHelper::SkRelease as u32,
        args: vec![MirValue::VReg(sock)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(sock_non_null, MirType::Bool);
    types.insert(
        listener,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cleanup_ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected get_listener_sock cgroup_skb context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_sk_fullsock_rejects_sk_lookup() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: sock,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkFullsock as u32,
            args: vec![MirValue::VReg(sock)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected sk_fullsock sk_lookup program-surface error");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "helper 'bpf_sk_fullsock' is only valid in tc_action, tc, tcx, netkit, and cgroup_skb programs",
        )
    }));
}

#[test]
fn test_verify_mir_for_probe_context_sk_fullsock_accepts_cgroup_skb() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();
    let fullsock = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sock,
            helper: BpfHelper::SkLookupTcp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(tuple_slot),
                MirValue::Const(16),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: sock_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: fullsock,
        helper: BpfHelper::SkFullsock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: cleanup_ret,
        helper: BpfHelper::SkRelease as u32,
        args: vec![MirValue::VReg(sock)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(sock_non_null, MirType::Bool);
    types.insert(
        fullsock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cleanup_ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected sk_fullsock cgroup_skb context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_tcp_sock_rejects_sk_lookup() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: sock,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::TcpSock as u32,
            args: vec![MirValue::VReg(sock)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected tcp_sock sk_lookup program-surface error");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_tcp_sock' is only valid in tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sockopt, and sock_ops programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_tcp_sock_accepts_cgroup_sockopt() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: sock,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: sock_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TcpSock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(ProbeContext::synthetic_socket_type()),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(sock_non_null, MirType::Bool);
    types.insert(dst, MirType::named_kernel_struct_ptr("bpf_sock"));

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected tcp_sock cgroup_sockopt context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_tcp_send_ack_accepts_tcp_congestion_struct_ops() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let tcp_sock = func.alloc_vreg();
    let tcp_sock_non_null = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: tcp_sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(tcp_sock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: tcp_sock_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TcpSendAck as u32,
        args: vec![MirValue::VReg(tcp_sock), MirValue::Const(123)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(tcp_sock, MirType::named_kernel_struct_ptr("tcp_sock"));
    types.insert(tcp_sock_non_null, MirType::Bool);
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new_struct_ops_callback("tcp_congestion_ops", "cong_avoid");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected tcp_send_ack tcp_congestion_ops struct_ops context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_tcp_send_ack_rejects_sched_ext_struct_ops() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let tcp_sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::TcpSendAck as u32,
            args: vec![MirValue::VReg(tcp_sock), MirValue::Const(123)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(tcp_sock, MirType::named_kernel_struct_ptr("tcp_sock"));
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new_struct_ops_callback("sched_ext_ops", "select_cpu");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected tcp_send_ack sched_ext struct_ops program-surface error");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_tcp_send_ack' is only valid in tcp_congestion_ops struct_ops programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_tcp_send_ack_rejects_non_socket_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: task_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: task_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TcpSendAck as u32,
        args: vec![MirValue::VReg(task), MirValue::Const(123)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(task, MirType::named_kernel_struct_ptr("task_struct"));
    types.insert(task_non_null, MirType::Bool);
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new_struct_ops_callback("tcp_congestion_ops", "cong_avoid");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected tcp_send_ack non-socket pointer error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_tcp_send_ack' arg0 expects socket pointer")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_skc_to_tcp_sock_rejects_cgroup_sockopt() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: sock,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkcToTcpSock as u32,
            args: vec![MirValue::VReg(sock)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected skc_to_tcp_sock cgroup_sockopt program-surface error");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_skc_to_tcp_sock' is only valid in xdp, flow_dissector, socket_filter, lwt_*, tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock_addr, fentry, fexit, fmod_ret, tp_btf, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_skc_to_tcp_sock_accepts_sk_lookup() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: sock,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: sock_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkcToTcpSock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(ProbeContext::synthetic_socket_type()),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(sock_non_null, MirType::Bool);
    types.insert(dst, MirType::named_kernel_struct_ptr("bpf_sock"));

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected skc_to_tcp_sock sk_lookup context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_sock_from_file_rejects_kprobe() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let file_check = func.alloc_block();
    let call = func.alloc_block();
    let release_task = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let file = func.alloc_vreg();
    let file_non_null = func.alloc_vreg();
    let sock = func.alloc_vreg();
    let put_ret = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: task_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: task_non_null,
        if_true: file_check,
        if_false: done,
    };

    func.block_mut(file_check)
        .instructions
        .push(MirInst::CallKfunc {
            dst: file,
            kfunc: "bpf_get_task_exe_file".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(file_check)
        .instructions
        .push(MirInst::BinOp {
            dst: file_non_null,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(file),
            rhs: MirValue::Const(0),
        });
    func.block_mut(file_check).terminator = MirInst::Branch {
        cond: file_non_null,
        if_true: call,
        if_false: release_task,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: sock,
        helper: BpfHelper::SockFromFile as u32,
        args: vec![MirValue::VReg(file)],
    });
    func.block_mut(call).instructions.push(MirInst::CallKfunc {
        dst: put_ret,
        kfunc: "bpf_put_file".to_string(),
        btf_id: None,
        args: vec![file],
    });
    func.block_mut(call).instructions.push(MirInst::CallKfunc {
        dst: release_ret,
        kfunc: "bpf_task_release".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };

    func.block_mut(release_task)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release_task).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(task_non_null, MirType::Bool);
    types.insert(
        file,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(file_non_null, MirType::Bool);
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(put_ret, MirType::I64);
    types.insert(release_ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected sock_from_file kprobe program-surface error");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_sock_from_file' is only valid in fentry, fexit, fmod_ret, and tp_btf programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_sock_from_file_accepts_fentry() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let file_check = func.alloc_block();
    let call = func.alloc_block();
    let release_task = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let file = func.alloc_vreg();
    let file_non_null = func.alloc_vreg();
    let sock = func.alloc_vreg();
    let put_ret = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: task_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: task_non_null,
        if_true: file_check,
        if_false: done,
    };

    func.block_mut(file_check)
        .instructions
        .push(MirInst::CallKfunc {
            dst: file,
            kfunc: "bpf_get_task_exe_file".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(file_check)
        .instructions
        .push(MirInst::BinOp {
            dst: file_non_null,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(file),
            rhs: MirValue::Const(0),
        });
    func.block_mut(file_check).terminator = MirInst::Branch {
        cond: file_non_null,
        if_true: call,
        if_false: release_task,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: sock,
        helper: BpfHelper::SockFromFile as u32,
        args: vec![MirValue::VReg(file)],
    });
    func.block_mut(call).instructions.push(MirInst::CallKfunc {
        dst: put_ret,
        kfunc: "bpf_put_file".to_string(),
        btf_id: None,
        args: vec![file],
    });
    func.block_mut(call).instructions.push(MirInst::CallKfunc {
        dst: release_ret,
        kfunc: "bpf_task_release".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };

    func.block_mut(release_task)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release_task).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(task_non_null, MirType::Bool);
    types.insert(
        file,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(file_non_null, MirType::Bool);
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(put_ret, MirType::I64);
    types.insert(release_ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "tcp_connect");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected sock_from_file fentry context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_sock_from_file_accepts_named_file_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let file = func.alloc_vreg();
    let file_non_null = func.alloc_vreg();
    let sock = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: file_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(file),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: file_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: sock,
        helper: BpfHelper::SockFromFile as u32,
        args: vec![MirValue::VReg(file)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(file, MirType::named_kernel_struct_ptr("file"));
    types.insert(file_non_null, MirType::Bool);
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "tcp_connect");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected named file pointer to satisfy sock_from_file");
}

#[test]
fn test_verify_mir_for_probe_context_sock_from_file_rejects_anonymous_kernel_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let file = func.alloc_vreg();
    let file_non_null = func.alloc_vreg();
    let sock = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: file_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(file),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: file_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: sock,
        helper: BpfHelper::SockFromFile as u32,
        args: vec![MirValue::VReg(file)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        file,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(file_non_null, MirType::Bool);
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "tcp_connect");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected anonymous kernel pointer to fail sock_from_file");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_sock_from_file' arg0 expects file pointer")
    }));
}

#[test]
fn test_verify_mir_helper_task_pt_regs_accepts_named_task_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let regs = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: task_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: task_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: regs,
        helper: BpfHelper::TaskPtRegs as u32,
        args: vec![MirValue::VReg(task)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(task, MirType::named_kernel_struct_ptr("task_struct"));
    types.insert(task_non_null, MirType::Bool);
    types.insert(
        regs,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    verify_mir(&func, &types).expect("expected named task pointer to satisfy task_pt_regs");
}

#[test]
fn test_verify_mir_helper_task_pt_regs_accepts_current_task_without_null_check() {
    for helper in [BpfHelper::GetCurrentTask, BpfHelper::GetCurrentTaskBtf] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;
        func.param_count = 1;

        let task = func.alloc_vreg();
        let regs = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: task,
                helper: helper as u32,
                args: vec![],
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: regs,
                helper: BpfHelper::TaskPtRegs as u32,
                args: vec![MirValue::VReg(task)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(task, MirType::named_kernel_struct_ptr("task_struct"));
        types.insert(regs, MirType::named_kernel_struct_ptr("pt_regs"));

        let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "tcp_connect");
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected current task helper return to be non-null");
    }
}

fn make_get_task_stack_verify_call(
    size: i64,
    buf_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(buf_size, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: task,
            helper: BpfHelper::GetCurrentTaskBtf as u32,
            args: vec![],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetTaskStack as u32,
            args: vec![
                MirValue::VReg(task),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(size),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(task, MirType::named_kernel_struct_ptr("task_struct"));
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_helper_get_task_stack_accepts_current_task() {
    let (func, types) = make_get_task_stack_verify_call(24, 24);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "tcp_connect");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected bpf_get_task_stack helper to verify");
}

#[test]
fn test_verify_mir_helper_get_task_stack_rejects_small_buffer() {
    let (func, types) = make_get_task_stack_verify_call(24, 8);
    let err = verify_mir(&func, &types).expect_err("expected get_task_stack bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_task_stack buf out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_get_task_stack_rejects_negative_size() {
    let (func, types) = make_get_task_stack_verify_call(-1, 8);
    let err = verify_mir(&func, &types).expect_err("expected get_task_stack size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 141 arg2 must be >= 0")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_d_path_verify_call(size: i64, buf_size: usize) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let path = func.alloc_vreg();
    let path_non_null = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(buf_size, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: path_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(path),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: path_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::DPath as u32,
        args: vec![
            MirValue::VReg(path),
            MirValue::StackSlot(buf_slot),
            MirValue::Const(size),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        path,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(path_non_null, MirType::Bool);
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_helper_d_path_accepts_kernel_path() {
    let (func, types) = make_d_path_verify_call(16, 16);
    verify_mir(&func, &types).expect("expected bpf_d_path helper to verify");
}

#[test]
fn test_verify_mir_helper_d_path_rejects_small_buffer() {
    let (func, types) = make_d_path_verify_call(16, 8);
    let err = verify_mir(&func, &types).expect_err("expected d_path bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper d_path buf out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_d_path_rejects_negative_size() {
    let (func, types) = make_d_path_verify_call(-1, 8);
    let err = verify_mir(&func, &types).expect_err("expected d_path size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 147 arg2 must be >= 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_d_path_rejects_stack_path() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let path_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::DPath as u32,
            args: vec![
                MirValue::StackSlot(path_slot),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(16),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected d_path path-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper d_path path expects pointer in [Kernel]")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_bprm_opts_set_verify_call(flags: i64) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let bprm = func.alloc_vreg();
    let bprm_non_null = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: bprm_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(bprm),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: bprm_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::BprmOptsSet as u32,
        args: vec![MirValue::VReg(bprm), MirValue::Const(flags)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(bprm, MirType::named_kernel_struct_ptr("linux_binprm"));
    types.insert(bprm_non_null, MirType::Bool);
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_helper_bprm_opts_set_accepts_kernel_bprm() {
    let (func, types) = make_bprm_opts_set_verify_call(1);
    verify_mir(&func, &types).expect("expected bpf_bprm_opts_set helper to verify");
}

#[test]
fn test_verify_mir_helper_bprm_opts_set_rejects_invalid_flags() {
    let (func, types) = make_bprm_opts_set_verify_call(2);
    let err = verify_mir(&func, &types).expect_err("expected bprm opts flags error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_bprm_opts_set' requires arg1 flags")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_bprm_opts_set_rejects_stack_bprm() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let bprm_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::BprmOptsSet as u32,
            args: vec![MirValue::StackSlot(bprm_slot), MirValue::Const(1)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bprm opts pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper bprm_opts_set bprm expects pointer in [Kernel]")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_ima_hash_verify_call(
    helper: BpfHelper,
    object_type_name: &str,
    size: i64,
    buf_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let object = func.alloc_vreg();
    let object_non_null = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(buf_size, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: object_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(object),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: object_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: helper as u32,
        args: vec![
            MirValue::VReg(object),
            MirValue::StackSlot(buf_slot),
            MirValue::Const(size),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(object, MirType::named_kernel_struct_ptr(object_type_name));
    types.insert(object_non_null, MirType::Bool);
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_helper_ima_hash_helpers_accept_typed_args() {
    for (helper, object_type_name) in [
        (BpfHelper::ImaInodeHash, "inode"),
        (BpfHelper::ImaFileHash, "file"),
    ] {
        let (func, types) = make_ima_hash_verify_call(helper, object_type_name, 16, 16);
        verify_mir(&func, &types).expect("expected IMA helper to verify");
    }
}

#[test]
fn test_verify_mir_helper_ima_inode_hash_rejects_small_buffer() {
    let (func, types) = make_ima_hash_verify_call(BpfHelper::ImaInodeHash, "inode", 16, 8);
    let err = verify_mir(&func, &types).expect_err("expected IMA inode bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper ima_inode_hash dst out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ima_file_hash_requires_positive_size() {
    let (func, types) = make_ima_hash_verify_call(BpfHelper::ImaFileHash, "file", 0, 16);
    let err = verify_mir(&func, &types).expect_err("expected IMA file positive-size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 193 arg2 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ima_file_hash_rejects_inode_arg() {
    let (func, types) = make_ima_hash_verify_call(BpfHelper::ImaFileHash, "inode", 16, 16);
    let err = verify_mir(&func, &types).expect_err("expected IMA file ref mismatch");
    assert!(
        err.iter().any(|e| {
            e.message
                .contains("helper 'bpf_ima_file_hash' arg0 expects file pointer")
        }),
        "unexpected errors: {:?}",
        err
    );
}

fn make_copy_from_user_verify_call(
    size: i64,
    buf_size: usize,
    with_task: bool,
    flags: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call_block = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let src = func.alloc_vreg();
    let src_non_null = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let task = with_task.then(|| func.alloc_vreg());
    let buf_slot = func.alloc_stack_slot(buf_size, 8, StackSlotKind::StringBuffer);

    if let Some(task) = task {
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: task,
                helper: BpfHelper::GetCurrentTaskBtf as u32,
                args: vec![],
            });
    }
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: src_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(src),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: src_non_null,
        if_true: call_block,
        if_false: done,
    };

    let args = if let Some(task) = task {
        vec![
            MirValue::StackSlot(buf_slot),
            MirValue::Const(size),
            MirValue::VReg(src),
            MirValue::VReg(task),
            MirValue::Const(flags),
        ]
    } else {
        vec![
            MirValue::StackSlot(buf_slot),
            MirValue::Const(size),
            MirValue::VReg(src),
        ]
    };
    func.block_mut(call_block)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: if with_task {
                BpfHelper::CopyFromUserTask as u32
            } else {
                BpfHelper::CopyFromUser as u32
            },
            args,
        });
    func.block_mut(call_block).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        src,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(src_non_null, MirType::Bool);
    if let Some(task) = task {
        types.insert(task, MirType::named_kernel_struct_ptr("task_struct"));
    }
    types.insert(dst, MirType::I64);

    (func, types)
}

fn make_probe_write_user_verify_call(
    size: i64,
    src_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call_block = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let user_dst = func.alloc_vreg();
    let user_dst_non_null = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let src_slot = func.alloc_stack_slot(src_size, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: user_dst_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(user_dst),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: user_dst_non_null,
        if_true: call_block,
        if_false: done,
    };

    func.block_mut(call_block)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::ProbeWriteUser as u32,
            args: vec![
                MirValue::VReg(user_dst),
                MirValue::StackSlot(src_slot),
                MirValue::Const(size),
            ],
        });
    func.block_mut(call_block).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        user_dst,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(user_dst_non_null, MirType::Bool);
    types.insert(ret, MirType::I64);

    (func, types)
}

fn make_override_return_verify_call(use_stack_ctx: bool) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let ctx_slot = use_stack_ctx.then(|| func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer));

    let block = func.block_mut(entry);
    let ctx_arg = if let Some(ctx_slot) = ctx_slot {
        MirValue::StackSlot(ctx_slot)
    } else {
        block.instructions.push(MirInst::CallHelper {
            dst: ctx,
            helper: BpfHelper::GetCurrentTaskBtf as u32,
            args: vec![],
        });
        MirValue::VReg(ctx)
    };
    block.instructions.push(MirInst::CallHelper {
        dst: ret,
        helper: BpfHelper::OverrideReturn as u32,
        args: vec![ctx_arg, MirValue::Const(-1)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ret, MirType::I64);
    (func, types)
}

#[test]
fn test_verify_mir_helper_copy_from_user_accepts_user_src() {
    let (func, types) = make_copy_from_user_verify_call(16, 16, false, 0);
    verify_mir(&func, &types).expect("expected bpf_copy_from_user helper to verify");
}

#[test]
fn test_verify_mir_helper_copy_from_user_task_accepts_task_arg() {
    let (func, types) = make_copy_from_user_verify_call(16, 16, true, 0);
    verify_mir(&func, &types).expect("expected bpf_copy_from_user_task helper to verify");
}

#[test]
fn test_verify_mir_helper_probe_write_user_accepts_user_dst() {
    let (func, types) = make_probe_write_user_verify_call(16, 16);
    verify_mir(&func, &types).expect("expected bpf_probe_write_user helper to verify");
}

#[test]
fn test_verify_mir_helper_override_return_accepts_ctx() {
    let (func, types) = make_override_return_verify_call(false);
    verify_mir(&func, &types).expect("expected bpf_override_return helper to verify");
}

#[test]
fn test_verify_mir_helper_copy_from_user_rejects_small_buffer() {
    let (func, types) = make_copy_from_user_verify_call(16, 8, false, 0);
    let err = verify_mir(&func, &types).expect_err("expected copy_from_user bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper copy_from_user dst out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_override_return_rejects_stack_ctx() {
    let (func, types) = make_override_return_verify_call(true);
    let err = verify_mir(&func, &types).expect_err("expected override_return ctx error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper override_return ctx expects pointer in [Kernel]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_probe_write_user_rejects_small_source_buffer() {
    let (func, types) = make_probe_write_user_verify_call(16, 8);
    let err = verify_mir(&func, &types).expect_err("expected probe_write_user bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper probe_write_user src out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_probe_write_user_rejects_stack_dst() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::ProbeWriteUser as u32,
            args: vec![
                MirValue::StackSlot(dst_slot),
                MirValue::StackSlot(src_slot),
                MirValue::Const(8),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected probe_write_user dst error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper probe_write_user dst expects pointer in [User]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_copy_from_user_task_rejects_nonzero_flags() {
    let (func, types) = make_copy_from_user_verify_call(16, 16, true, 1);
    let err = verify_mir(&func, &types).expect_err("expected copy_from_user_task flags error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_copy_from_user_task' requires arg4 = 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_copy_from_user_task_rejects_cgroup_task_argument() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let cgroup_guard = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let id = func.alloc_vreg();
    let src = func.alloc_vreg();
    let src_non_null = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let cgroup_non_null = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: id,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![id],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: src_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(src),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: src_non_null,
        if_true: cgroup_guard,
        if_false: done,
    };

    func.block_mut(cgroup_guard)
        .instructions
        .push(MirInst::BinOp {
            dst: cgroup_non_null,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(cgroup),
            rhs: MirValue::Const(0),
        });
    func.block_mut(cgroup_guard).terminator = MirInst::Branch {
        cond: cgroup_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::CopyFromUserTask as u32,
        args: vec![
            MirValue::StackSlot(buf_slot),
            MirValue::Const(16),
            MirValue::VReg(src),
            MirValue::VReg(cgroup),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).instructions.push(MirInst::CallKfunc {
        dst: cleanup_ret,
        kfunc: "bpf_cgroup_release".to_string(),
        btf_id: None,
        args: vec![cgroup],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(id, MirType::I64);
    types.insert(
        src,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(src_non_null, MirType::Bool);
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cgroup_non_null, MirType::Bool);
    types.insert(dst, MirType::I64);
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected copy_from_user_task ref error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 191 arg3 expects task reference, got cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_task_pt_regs_rejects_anonymous_kernel_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let regs = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: task_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: task_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: regs,
        helper: BpfHelper::TaskPtRegs as u32,
        args: vec![MirValue::VReg(task)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(task_non_null, MirType::Bool);
    types.insert(
        regs,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types)
        .expect_err("expected anonymous kernel pointer to fail task_pt_regs");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_task_pt_regs' arg0 expects task pointer")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_task_storage_get_rejects_xdp() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let storage = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: task_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: task_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: storage,
        helper: BpfHelper::TaskStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(task),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(task_non_null, MirType::Bool);
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected task_storage_get xdp program-surface error");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_task_storage_get' is only valid in kprobe, kretprobe, kprobe.multi, kretprobe.multi, ksyscall, kretsyscall, uprobe, uretprobe, uprobe.multi, uretprobe.multi, perf_event, raw_tracepoint, raw_tracepoint.w, tracepoint, fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_task_storage_get_accepts_kretprobe() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let storage = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: task_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: task_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: storage,
        helper: BpfHelper::TaskStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(task),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).instructions.push(MirInst::CallKfunc {
        dst: cleanup_ret,
        kfunc: "bpf_task_release".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(task_non_null, MirType::Bool);
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(cleanup_ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kretprobe, "do_sys_openat2");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected task_storage_get kretprobe context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_inode_storage_get_rejects_kprobe() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let inode = func.alloc_vreg();
    let storage = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: inode,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: storage,
            helper: BpfHelper::InodeStorageGet as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::VReg(inode),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        inode,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected inode_storage_get kprobe program-surface error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_inode_storage_get' is only valid in lsm and lsm_cgroup programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_sk_storage_get_rejects_xdp() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let sk = func.alloc_vreg();
    let sk_non_null = func.alloc_vreg();
    let storage = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: sk_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sk),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: sk_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: storage,
        helper: BpfHelper::SkStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(sk),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(sk, MirType::named_kernel_struct_ptr("bpf_sock"));
    types.insert(sk_non_null, MirType::Bool);
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected sk_storage_get xdp program-surface error");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_sk_storage_get' is only valid in tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_sk_storage_get_accepts_cgroup_sock() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let sk = func.alloc_vreg();
    let sk_non_null = func.alloc_vreg();
    let storage = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: sk,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: sk_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sk),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: sk_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: storage,
        helper: BpfHelper::SkStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(sk),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(sk, MirType::named_kernel_struct_ptr("bpf_sock"));
    types.insert(sk_non_null, MirType::Bool);
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected sk_storage_get cgroup_sock context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_sk_storage_delete_rejects_cgroup_sock() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let sk = func.alloc_vreg();
    let sk_non_null = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: sk,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: sk_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sk),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: sk_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: ret,
        helper: BpfHelper::SkStorageDelete as u32,
        args: vec![MirValue::StackSlot(map_slot), MirValue::VReg(sk)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(sk, MirType::named_kernel_struct_ptr("bpf_sock"));
    types.insert(sk_non_null, MirType::Bool);
    types.insert(ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected sk_storage_delete cgroup_sock program-surface error");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_sk_storage_delete' is only valid in tc_action, tc, tcx, netkit, cgroup_skb, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, fmod_ret, tp_btf, lsm, and lsm_cgroup programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_sk_storage_delete_accepts_cgroup_sockopt() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let sk = func.alloc_vreg();
    let sk_non_null = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: sk,
            field: CtxField::Socket,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: sk_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sk),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: sk_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: ret,
        helper: BpfHelper::SkStorageDelete as u32,
        args: vec![MirValue::StackSlot(map_slot), MirValue::VReg(sk)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(sk, MirType::named_kernel_struct_ptr("bpf_sock"));
    types.insert(sk_non_null, MirType::Bool);
    types.insert(ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected sk_storage_delete cgroup_sockopt context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_redirect_peer_accepts_tc_ingress() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::RedirectPeer as u32,
            args: vec![MirValue::Const(1), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected redirect_peer tc-ingress context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_xdp_adjust_meta_invalidates_prior_packet_pointers() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let load = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let data = func.alloc_vreg();
    let access_end = func.alloc_vreg();
    let data_end = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: access_end,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(data),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data_end,
            field: CtxField::DataEnd,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Le,
        lhs: MirValue::VReg(access_end),
        rhs: MirValue::VReg(data_end),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: load,
        if_false: done,
    };

    func.block_mut(load)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(load).instructions.push(MirInst::CallHelper {
        dst: helper_ret,
        helper: BpfHelper::XdpAdjustMeta as u32,
        args: vec![MirValue::VReg(ctx), MirValue::Const(0)],
    });
    func.block_mut(load).instructions.push(MirInst::Load {
        dst,
        ptr: data,
        offset: 0,
        ty: MirType::U8,
    });
    func.block_mut(load).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let packet_ptr = MirType::Ptr {
        pointee: Box::new(MirType::U8),
        address_space: AddressSpace::Packet,
    };
    let mut types = HashMap::new();
    types.insert(data, packet_ptr.clone());
    types.insert(access_end, packet_ptr.clone());
    types.insert(data_end, packet_ptr);
    types.insert(cond, MirType::Bool);
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(helper_ret, MirType::I64);
    types.insert(dst, MirType::U8);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected stale packet pointer load to fail after xdp_adjust_meta");
    assert!(
        err.iter()
            .any(|e| e.message.contains("load requires pointer type")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_xdp_adjust_meta_allows_reloaded_packet_pointers() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let load = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let stale_data = func.alloc_vreg();
    let stale_data_end = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let data = func.alloc_vreg();
    let access_end = func.alloc_vreg();
    let data_end = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: stale_data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: stale_data_end,
            field: CtxField::DataEnd,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::XdpAdjustMeta as u32,
            args: vec![MirValue::VReg(ctx), MirValue::Const(0)],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: access_end,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(data),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data_end,
            field: CtxField::DataEnd,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Le,
        lhs: MirValue::VReg(access_end),
        rhs: MirValue::VReg(data_end),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: load,
        if_false: done,
    };

    func.block_mut(load).instructions.push(MirInst::Load {
        dst,
        ptr: data,
        offset: 0,
        ty: MirType::U8,
    });
    func.block_mut(load).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let packet_ptr = MirType::Ptr {
        pointee: Box::new(MirType::U8),
        address_space: AddressSpace::Packet,
    };
    let mut types = HashMap::new();
    types.insert(stale_data, packet_ptr.clone());
    types.insert(stale_data_end, packet_ptr.clone());
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(helper_ret, MirType::I64);
    types.insert(data, packet_ptr.clone());
    types.insert(access_end, packet_ptr.clone());
    types.insert(data_end, packet_ptr);
    types.insert(cond, MirType::Bool);
    types.insert(dst, MirType::U8);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected reloaded packet pointers to verify after xdp_adjust_meta");
}

#[test]
fn test_verify_mir_for_probe_context_skb_change_head_requires_zero_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkbChangeHead as u32,
            args: vec![MirValue::VReg(ctx), MirValue::Const(14), MirValue::Const(1)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_change_head flags to require zero");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_skb_change_head' requires arg2 = 0")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_skb_set_tstamp_rejects_non_tc_program() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkbSetTstamp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(123),
                MirValue::Const(1),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_set_tstamp to be rejected outside tc_action/tc");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "helper 'bpf_skb_set_tstamp' is only valid in tc_action, tc, tcx, and netkit programs",
        )
    }));
}

#[test]
fn test_verify_mir_helper_skb_set_tstamp_requires_zero_tstamp_for_unspec_type() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkbSetTstamp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(123),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected unspec tstamp type to require zero timestamp");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_skb_set_tstamp' requires arg1 = 0 when arg2 is 0")
    }));
}

#[test]
fn test_verify_mir_helper_skb_set_tstamp_rejects_invalid_tstamp_type() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkbSetTstamp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(123),
                MirValue::Const(2),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected invalid tstamp type error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_skb_set_tstamp' requires arg2")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_skb_set_tstamp_accepts_tc_program() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkbSetTstamp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(123),
                MirValue::Const(1),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected tc bpf_skb_set_tstamp helper to verify");

    let probe_ctx = ProbeContext::new(EbpfProgramType::TcAction, "demo-action");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected tc_action bpf_skb_set_tstamp helper to verify");
}

fn make_check_mtu_verify_call(
    flags: i64,
    mtu_len_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let mtu_len = func.alloc_stack_slot(mtu_len_size, mtu_len_size, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::CheckMtu as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(0),
                MirValue::StackSlot(mtu_len),
                MirValue::Const(0),
                MirValue::Const(flags),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_for_probe_context_check_mtu_accepts_xdp_and_tc_programs() {
    for probe_ctx in [
        ProbeContext::new(EbpfProgramType::Xdp, "lo"),
        ProbeContext::new(EbpfProgramType::Tc, "lo:ingress"),
        ProbeContext::new(EbpfProgramType::TcAction, "demo-action"),
    ] {
        let (func, types) = make_check_mtu_verify_call(0, 4);
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected bpf_check_mtu helper to verify");
    }
}

#[test]
fn test_verify_mir_for_probe_context_check_mtu_rejects_non_xdp_tc_program() {
    let (func, types) = make_check_mtu_verify_call(0, 4);
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_check_mtu to be rejected outside xdp/tc");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "helper 'bpf_check_mtu' is only valid in xdp, tc_action, tc, tcx, and netkit programs",
        )
    }));
}

#[test]
fn test_verify_mir_for_probe_context_check_mtu_requires_zero_flags_in_xdp() {
    let (func, types) = make_check_mtu_verify_call(1, 4);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected xdp bpf_check_mtu flags to require zero");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_check_mtu' requires arg4 = 0 in xdp programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_check_mtu_requires_four_byte_mtu_len_pointer() {
    let (func, types) = make_check_mtu_verify_call(0, 2);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_check_mtu mtu_len pointer bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper check_mtu mtu_len out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_fib_lookup_verify_call(
    plen: i64,
    params_size: usize,
    flags: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let params = func.alloc_stack_slot(params_size, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::FibLookup as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(params),
                MirValue::Const(plen),
                MirValue::Const(flags),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_for_probe_context_fib_lookup_accepts_xdp_and_tc_programs() {
    for probe_ctx in [
        ProbeContext::new(EbpfProgramType::Xdp, "lo"),
        ProbeContext::new(EbpfProgramType::Tc, "lo:ingress"),
        ProbeContext::new(EbpfProgramType::TcAction, "demo-action"),
    ] {
        let (func, types) = make_fib_lookup_verify_call(64, 64, 0);
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected bpf_fib_lookup helper to verify");
    }
}

#[test]
fn test_verify_mir_for_probe_context_fib_lookup_rejects_non_xdp_tc_program() {
    let (func, types) = make_fib_lookup_verify_call(64, 64, 0);
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_fib_lookup to be rejected outside xdp/tc");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "helper 'bpf_fib_lookup' is only valid in xdp, tc_action, tc, tcx, and netkit programs",
        )
    }));
}

#[test]
fn test_verify_mir_for_probe_context_fib_lookup_rejects_small_params_buffer() {
    let (func, types) = make_fib_lookup_verify_call(64, 8, 0);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_fib_lookup params buffer bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper fib_lookup params out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_fib_lookup_rejects_invalid_flags() {
    let (func, types) = make_fib_lookup_verify_call(64, 64, 0x40);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_fib_lookup flags error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_fib_lookup' requires arg3 flags")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_skb_tunnel_verify_call(
    helper: BpfHelper,
    size: i64,
    buffer_size: usize,
    flags: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buffer = func.alloc_stack_slot(buffer_size, 8, StackSlotKind::StringBuffer);
    let args = if matches!(
        helper,
        BpfHelper::SkbGetTunnelKey | BpfHelper::SkbSetTunnelKey
    ) {
        vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(buffer),
            MirValue::Const(size),
            MirValue::Const(flags),
        ]
    } else {
        vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(buffer),
            MirValue::Const(size),
        ]
    };
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_for_probe_context_skb_tunnel_helpers_accept_tc_and_lwt_xmit_programs() {
    for helper in [
        BpfHelper::SkbGetTunnelKey,
        BpfHelper::SkbSetTunnelKey,
        BpfHelper::SkbGetTunnelOpt,
        BpfHelper::SkbSetTunnelOpt,
    ] {
        for probe_ctx in [
            ProbeContext::new(EbpfProgramType::Tc, "lo:ingress"),
            ProbeContext::new(EbpfProgramType::TcAction, "demo-action"),
            ProbeContext::new(EbpfProgramType::LwtXmit, "lwt-xmit"),
        ] {
            let (func, types) = make_skb_tunnel_verify_call(helper, 16, 16, 0);
            verify_mir_for_probe_context(&func, &types, &probe_ctx)
                .expect("expected skb tunnel helper to verify");
        }
    }
}

#[test]
fn test_verify_mir_for_probe_context_skb_tunnel_helpers_reject_non_tc_lwt_xmit_program() {
    let (func, types) = make_skb_tunnel_verify_call(BpfHelper::SkbSetTunnelKey, 16, 16, 0);
    let probe_ctx = ProbeContext::new(EbpfProgramType::LwtOut, "lwt-out");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected skb tunnel helper to be rejected outside tc/lwt_xmit");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_skb_set_tunnel_key' is only valid in tc_action, tc, tcx, netkit, and lwt_xmit programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_skb_tunnel_helper_rejects_small_buffer() {
    let (func, types) = make_skb_tunnel_verify_call(BpfHelper::SkbGetTunnelOpt, 16, 8, 0);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected skb tunnel buffer bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper skb_tunnel buffer out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_skb_tunnel_key_helpers_reject_invalid_flags() {
    for (helper, flags, expected) in [
        (
            BpfHelper::SkbGetTunnelKey,
            2,
            "helper 'bpf_skb_get_tunnel_key' requires arg3 flags",
        ),
        (
            BpfHelper::SkbSetTunnelKey,
            32,
            "helper 'bpf_skb_set_tunnel_key' requires arg3 flags",
        ),
    ] {
        let (func, types) = make_skb_tunnel_verify_call(helper, 16, 16, flags);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected skb tunnel flag validation error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

fn make_skb_get_xfrm_state_verify_call(
    flags: i64,
    size: i64,
    buffer_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let xfrm_state = func.alloc_stack_slot(buffer_size, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkbGetXfrmState as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(0),
                MirValue::StackSlot(xfrm_state),
                MirValue::Const(size),
                MirValue::Const(flags),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_for_probe_context_skb_get_xfrm_state_accepts_tc_programs() {
    for probe_ctx in [
        ProbeContext::new(EbpfProgramType::Tc, "lo:ingress"),
        ProbeContext::new(EbpfProgramType::TcAction, "demo-action"),
    ] {
        let (func, types) = make_skb_get_xfrm_state_verify_call(0, 16, 16);
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected bpf_skb_get_xfrm_state helper to verify");
    }
}

#[test]
fn test_verify_mir_for_probe_context_skb_get_xfrm_state_rejects_non_tc_program() {
    let (func, types) = make_skb_get_xfrm_state_verify_call(0, 16, 16);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_get_xfrm_state to be rejected outside tc");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_skb_get_xfrm_state' is only valid in tc_action, tc, tcx, and netkit programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_skb_get_xfrm_state_requires_zero_flags() {
    let (func, types) = make_skb_get_xfrm_state_verify_call(1, 16, 16);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_get_xfrm_state flags to require zero");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_skb_get_xfrm_state' requires arg4 = 0")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_skb_get_xfrm_state_rejects_small_buffer() {
    let (func, types) = make_skb_get_xfrm_state_verify_call(0, 16, 8);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_get_xfrm_state buffer bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper skb_get_xfrm_state xfrm_state out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_lwt_buffer_verify_call(
    helper: BpfHelper,
    size: i64,
    buffer_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buffer = func.alloc_stack_slot(buffer_size, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(0),
                MirValue::StackSlot(buffer),
                MirValue::Const(size),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    (func, types)
}

fn make_lwt_seg6_adjust_srh_verify_call() -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::LwtSeg6AdjustSrh as u32,
            args: vec![MirValue::VReg(ctx), MirValue::Const(0), MirValue::Const(4)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_for_probe_context_lwt_push_encap_accepts_lwt_in_and_xmit_programs() {
    for probe_ctx in [
        ProbeContext::new(EbpfProgramType::LwtIn, "demo-route"),
        ProbeContext::new(EbpfProgramType::LwtXmit, "demo-route"),
    ] {
        let (func, types) = make_lwt_buffer_verify_call(BpfHelper::LwtPushEncap, 16, 16);
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected bpf_lwt_push_encap helper to verify");
    }
}

#[test]
fn test_verify_mir_for_probe_context_lwt_push_encap_rejects_non_lwt_in_xmit_program() {
    let (func, types) = make_lwt_buffer_verify_call(BpfHelper::LwtPushEncap, 16, 16);
    let probe_ctx = ProbeContext::new(EbpfProgramType::LwtOut, "demo-route");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_lwt_push_encap to be rejected outside lwt_in/xmit");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_lwt_push_encap' is only valid in lwt_in and lwt_xmit programs"))
    );
}

#[test]
fn test_verify_mir_for_probe_context_lwt_seg6_helpers_accept_lwt_seg6local_programs() {
    for (func, types) in [
        make_lwt_buffer_verify_call(BpfHelper::LwtSeg6StoreBytes, 16, 16),
        make_lwt_buffer_verify_call(BpfHelper::LwtSeg6Action, 16, 16),
        make_lwt_seg6_adjust_srh_verify_call(),
    ] {
        let probe_ctx = ProbeContext::new(EbpfProgramType::LwtSeg6Local, "demo-route");
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected lwt seg6 helper to verify");
    }
}

#[test]
fn test_verify_mir_for_probe_context_lwt_seg6_helpers_reject_non_lwt_seg6local_program() {
    let (func, types) = make_lwt_buffer_verify_call(BpfHelper::LwtSeg6Action, 16, 16);
    let probe_ctx = ProbeContext::new(EbpfProgramType::LwtXmit, "demo-route");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_lwt_seg6_action to be rejected outside lwt_seg6local");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_lwt_seg6_action' is only valid in lwt_seg6local programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_lwt_buffer_helper_rejects_small_buffer() {
    let (func, types) = make_lwt_buffer_verify_call(BpfHelper::LwtSeg6StoreBytes, 16, 8);
    let probe_ctx = ProbeContext::new(EbpfProgramType::LwtSeg6Local, "demo-route");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected lwt helper buffer bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper lwt buffer out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_skb_pull_data_invalidates_prior_packet_pointers() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let load = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let data = func.alloc_vreg();
    let access_end = func.alloc_vreg();
    let data_end = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: access_end,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(data),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data_end,
            field: CtxField::DataEnd,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Le,
        lhs: MirValue::VReg(access_end),
        rhs: MirValue::VReg(data_end),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: load,
        if_false: done,
    };

    func.block_mut(load)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(load).instructions.push(MirInst::CallHelper {
        dst: helper_ret,
        helper: BpfHelper::SkbPullData as u32,
        args: vec![MirValue::VReg(ctx), MirValue::Const(1)],
    });
    func.block_mut(load).instructions.push(MirInst::Load {
        dst,
        ptr: data,
        offset: 0,
        ty: MirType::U8,
    });
    func.block_mut(load).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let packet_ptr = MirType::Ptr {
        pointee: Box::new(MirType::U8),
        address_space: AddressSpace::Packet,
    };
    let mut types = HashMap::new();
    types.insert(data, packet_ptr.clone());
    types.insert(access_end, packet_ptr.clone());
    types.insert(data_end, packet_ptr);
    types.insert(cond, MirType::Bool);
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(helper_ret, MirType::I64);
    types.insert(dst, MirType::U8);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected stale packet pointer load to fail after skb_pull_data");
    assert!(
        err.iter()
            .any(|e| e.message.contains("load requires pointer type")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_skb_pull_data_allows_reloaded_packet_pointers() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let load = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let stale_data = func.alloc_vreg();
    let stale_data_end = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let data = func.alloc_vreg();
    let access_end = func.alloc_vreg();
    let data_end = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: stale_data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: stale_data_end,
            field: CtxField::DataEnd,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::SkbPullData as u32,
            args: vec![MirValue::VReg(ctx), MirValue::Const(1)],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: access_end,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(data),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data_end,
            field: CtxField::DataEnd,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Le,
        lhs: MirValue::VReg(access_end),
        rhs: MirValue::VReg(data_end),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: load,
        if_false: done,
    };

    func.block_mut(load).instructions.push(MirInst::Load {
        dst,
        ptr: data,
        offset: 0,
        ty: MirType::U8,
    });
    func.block_mut(load).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let packet_ptr = MirType::Ptr {
        pointee: Box::new(MirType::U8),
        address_space: AddressSpace::Packet,
    };
    let mut types = HashMap::new();
    types.insert(stale_data, packet_ptr.clone());
    types.insert(stale_data_end, packet_ptr.clone());
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(helper_ret, MirType::I64);
    types.insert(data, packet_ptr.clone());
    types.insert(access_end, packet_ptr.clone());
    types.insert(data_end, packet_ptr);
    types.insert(cond, MirType::Bool);
    types.insert(dst, MirType::U8);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected reloaded packet pointers to verify after skb_pull_data");
}

#[test]
fn test_verify_mir_for_probe_context_msg_pull_data_invalidates_prior_packet_pointers() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let load = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let data = func.alloc_vreg();
    let access_end = func.alloc_vreg();
    let data_end = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: access_end,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(data),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data_end,
            field: CtxField::DataEnd,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Le,
        lhs: MirValue::VReg(access_end),
        rhs: MirValue::VReg(data_end),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: load,
        if_false: done,
    };

    func.block_mut(load)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(load).instructions.push(MirInst::CallHelper {
        dst: helper_ret,
        helper: BpfHelper::MsgPullData as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::Const(0),
            MirValue::Const(1),
            MirValue::Const(0),
        ],
    });
    func.block_mut(load).instructions.push(MirInst::Load {
        dst,
        ptr: data,
        offset: 0,
        ty: MirType::U8,
    });
    func.block_mut(load).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let packet_ptr = MirType::Ptr {
        pointee: Box::new(MirType::U8),
        address_space: AddressSpace::Packet,
    };
    let mut types = HashMap::new();
    types.insert(data, packet_ptr.clone());
    types.insert(access_end, packet_ptr.clone());
    types.insert(data_end, packet_ptr);
    types.insert(cond, MirType::Bool);
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(helper_ret, MirType::I64);
    types.insert(dst, MirType::U8);

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected stale packet pointer load to fail after msg_pull_data");
    assert!(
        err.iter()
            .any(|e| e.message.contains("load requires pointer type")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_msg_pull_data_verify_call(flags: i64) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::MsgPullData as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(0),
                MirValue::Const(8),
                MirValue::Const(flags),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_for_probe_context_msg_pull_data_rejects_nonzero_flags() {
    let (func, types) = make_msg_pull_data_verify_call(1);
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_msg_pull_data flags error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_msg_pull_data' requires arg3 = 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_msg_pull_data_allows_reloaded_packet_pointers() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let load = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let stale_data = func.alloc_vreg();
    let stale_data_end = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let data = func.alloc_vreg();
    let access_end = func.alloc_vreg();
    let data_end = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: stale_data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: stale_data_end,
            field: CtxField::DataEnd,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::MsgPullData as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(0),
                MirValue::Const(1),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: access_end,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(data),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data_end,
            field: CtxField::DataEnd,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Le,
        lhs: MirValue::VReg(access_end),
        rhs: MirValue::VReg(data_end),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: load,
        if_false: done,
    };

    func.block_mut(load).instructions.push(MirInst::Load {
        dst,
        ptr: data,
        offset: 0,
        ty: MirType::U8,
    });
    func.block_mut(load).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let packet_ptr = MirType::Ptr {
        pointee: Box::new(MirType::U8),
        address_space: AddressSpace::Packet,
    };
    let mut types = HashMap::new();
    types.insert(stale_data, packet_ptr.clone());
    types.insert(stale_data_end, packet_ptr.clone());
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(helper_ret, MirType::I64);
    types.insert(data, packet_ptr.clone());
    types.insert(access_end, packet_ptr.clone());
    types.insert(data_end, packet_ptr);
    types.insert(cond, MirType::Bool);
    types.insert(dst, MirType::U8);

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected reloaded packet pointers to verify after msg_pull_data");
}

#[test]
fn test_verify_mir_subfn_return_arg_summary_preserves_null_checked_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let use_value = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;
    func.vreg_count = 3;

    let cond = VReg(1);
    let ret = VReg(2);

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(VReg(0)),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: use_value,
        if_false: done,
    };

    func.block_mut(use_value)
        .instructions
        .push(MirInst::CallSubfn {
            dst: ret,
            subfn: crate::compiler::mir::SubfunctionId(0),
            args: vec![VReg(0)],
        });
    func.block_mut(use_value)
        .instructions
        .push(MirInst::EmitEvent {
            data: ret,
            size: 16,
        });
    func.block_mut(use_value).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let path_ty = MirType::Ptr {
        pointee: Box::new(MirType::Struct {
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
                    ty: MirType::U64,
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        }),
        address_space: AddressSpace::Map,
    };
    let mut types = HashMap::new();
    types.insert(VReg(0), path_ty.clone());
    types.insert(ret, path_ty);

    let summaries = HashMap::from([(
        crate::compiler::mir::SubfunctionId(0),
        SubfunctionReturnSummary::ReturnsArg(0),
    )]);
    verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect("expected null-checked arg-returning subfunction to preserve pointer safety");
}

#[test]
fn test_helper_map_lookup_requires_null_check() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let load_dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::StackSlot(key_slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::VReg(map), MirValue::VReg(key)],
        });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst: load_dst,
        ptr: dst,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(load_dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper null-check error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("may dereference null"))
    );
}

#[test]
fn test_helper_map_lookup_null_check_via_copied_cond_ok() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let load_block = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let cond0 = func.alloc_vreg();
    let cond1 = func.alloc_vreg();
    let load_dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::StackSlot(key_slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ptr,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::VReg(map), MirValue::VReg(key)],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond0,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cond1,
        src: MirValue::VReg(cond0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cond1,
        if_true: load_block,
        if_false: done,
    };

    func.block_mut(load_block).instructions.push(MirInst::Load {
        dst: load_dst,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(load_block).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(load_dst, MirType::I64);

    verify_mir(&func, &types).expect("expected copied null-check guard to pass");
}

#[test]
fn test_helper_map_lookup_rejects_out_of_bounds_key_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key_base = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key_base,
        src: MirValue::StackSlot(key_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: key,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(key_base),
        rhs: MirValue::Const(8),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::VReg(map), MirValue::VReg(key)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper key bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper map_lookup key out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_lookup_percpu_rejects_out_of_bounds_key_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key_base = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key_base,
        src: MirValue::StackSlot(key_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: key,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(key_base),
        rhs: MirValue::Const(8),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::MapLookupPercpuElem as u32,
            args: vec![MirValue::VReg(map), MirValue::VReg(key), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper key bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper map_lookup key out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_lookup_rejects_user_map_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(map),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 1, // bpf_map_lookup_elem(map, key)
        args: vec![MirValue::VReg(map), MirValue::StackSlot(key_slot)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper map pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper map_lookup map expects pointer in [Stack]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_update_rejects_map_lookup_value_as_map_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let lookup = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let update_ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: lookup,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(lookup),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: update_ret,
        helper: 2, // bpf_map_update_elem(map, key, value, flags)
        args: vec![
            MirValue::VReg(lookup),
            MirValue::StackSlot(key_slot),
            MirValue::StackSlot(value_slot),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        lookup,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(update_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected map-value pointer map-arg rejection");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper map_update map expects pointer in [Stack]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_update_rejects_invalid_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let update_ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: update_ret,
            helper: BpfHelper::MapUpdateElem as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(key_slot),
                MirValue::StackSlot(value_slot),
                MirValue::Const(3),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(update_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected map update invalid flags error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_map_update_elem' requires arg3 flags")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_queue_rejects_map_lookup_value_as_map_arg() {
    let helpers = [
        (
            BpfHelper::MapPushElem,
            "helper map_push map expects pointer in [Stack]",
        ),
        (
            BpfHelper::MapPopElem,
            "helper map_pop map expects pointer in [Stack]",
        ),
        (
            BpfHelper::MapPeekElem,
            "helper map_peek map expects pointer in [Stack]",
        ),
    ];

    for (helper, needle) in helpers {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let call = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let lookup = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let helper_ret = func.alloc_vreg();

        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: lookup,
                helper: BpfHelper::MapLookupElem as u32,
                args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
            });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(lookup),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: call,
            if_false: done,
        };

        func.block_mut(call).instructions.push(MirInst::CallHelper {
            dst: helper_ret,
            helper: helper as u32,
            args: match helper {
                BpfHelper::MapPushElem => vec![
                    MirValue::VReg(lookup),
                    MirValue::StackSlot(value_slot),
                    MirValue::Const(0),
                ],
                BpfHelper::MapPopElem | BpfHelper::MapPeekElem => {
                    vec![MirValue::VReg(lookup), MirValue::StackSlot(value_slot)]
                }
                _ => unreachable!(),
            },
        });
        func.block_mut(call).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            lookup,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Map,
            },
        );
        types.insert(helper_ret, MirType::I64);

        let err =
            verify_mir(&func, &types).expect_err("expected map queue helper map-arg rejection");
        assert!(
            err.iter().any(|e| e.message.contains(needle)),
            "unexpected errors for helper {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_helper_map_push_rejects_invalid_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let helper_ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::MapPushElem as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(value_slot),
                MirValue::Const(1),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(helper_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected map push invalid flags error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_map_push_elem' requires arg2 flags")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_queue_rejects_non_pointer_value_arg() {
    let helpers = [
        (BpfHelper::MapPushElem, 87u32),
        (BpfHelper::MapPopElem, 88u32),
        (BpfHelper::MapPeekElem, 89u32),
    ];

    for (helper, helper_id) in helpers {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let helper_ret = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: helper_ret,
                helper: helper as u32,
                args: match helper {
                    BpfHelper::MapPushElem => vec![
                        MirValue::StackSlot(map_slot),
                        MirValue::Const(0),
                        MirValue::Const(0),
                    ],
                    BpfHelper::MapPopElem | BpfHelper::MapPeekElem => {
                        vec![MirValue::StackSlot(map_slot), MirValue::Const(0)]
                    }
                    _ => unreachable!(),
                },
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(helper_ret, MirType::I64);

        let err =
            verify_mir(&func, &types).expect_err("expected map queue helper value-arg rejection");
        assert!(
            err.iter().any(|e| e
                .message
                .contains(&format!("helper {} arg1 expects pointer", helper_id))),
            "unexpected errors for helper {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_helper_ringbuf_query_rejects_map_lookup_value_as_map_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let lookup = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let query_ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: lookup,
            helper: BpfHelper::MapLookupElem as u32,
            args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(lookup),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: query_ret,
        helper: BpfHelper::RingbufQuery as u32,
        args: vec![MirValue::VReg(lookup), MirValue::Const(0)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        lookup,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(query_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected ringbuf_query map-arg rejection");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper ringbuf_query map expects pointer in [Stack]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_tcp_check_syncookie_rejects_non_positive_lengths() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let kptr = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: kptr,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: syncookie_ret,
            helper: BpfHelper::TcpCheckSyncookie as u32,
            args: vec![
                MirValue::VReg(kptr),
                MirValue::VReg(kptr),
                MirValue::Const(0),
                MirValue::VReg(kptr),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        kptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(syncookie_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected tcp_check_syncookie size errors");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 100 arg2 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 100 arg4 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_tcp_gen_syncookie_rejects_non_positive_lengths() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let kptr = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: kptr,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: syncookie_ret,
            helper: BpfHelper::TcpGenSyncookie as u32,
            args: vec![
                MirValue::VReg(kptr),
                MirValue::VReg(kptr),
                MirValue::Const(0),
                MirValue::VReg(kptr),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        kptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(syncookie_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected tcp_gen_syncookie size errors");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 110 arg2 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 110 arg4 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_tcp_gen_syncookie_rejects_non_kernel_sk_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let sk_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let pid = func.alloc_vreg();
    let kptr = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: kptr,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: syncookie_ret,
            helper: BpfHelper::TcpGenSyncookie as u32,
            args: vec![
                MirValue::StackSlot(sk_slot),
                MirValue::VReg(kptr),
                MirValue::Const(20),
                MirValue::VReg(kptr),
                MirValue::Const(20),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        kptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(syncookie_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected tcp_gen_syncookie pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper tcp_gen_syncookie sk expects pointer in [Kernel], got stack slot")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_tcp_check_syncookie_rejects_kprobe() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::TcpCheckSyncookie as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::VReg(ctx),
                MirValue::Const(20),
                MirValue::VReg(ctx),
                MirValue::Const(20),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected tcp_check_syncookie kprobe program-surface error");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "helper 'bpf_tcp_check_syncookie' is only valid in xdp, tc_action, tc, tcx, and netkit programs",
        )
    }));
}

#[test]
fn test_verify_mir_for_probe_context_tcp_check_syncookie_accepts_xdp() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sock,
            helper: BpfHelper::SkLookupTcp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(tuple_slot),
                MirValue::Const(16),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: sock_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: syncookie_ret,
        helper: BpfHelper::TcpCheckSyncookie as u32,
        args: vec![
            MirValue::VReg(sock),
            MirValue::VReg(sock),
            MirValue::Const(20),
            MirValue::VReg(sock),
            MirValue::Const(20),
        ],
    });
    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: cleanup_ret,
        helper: BpfHelper::SkRelease as u32,
        args: vec![MirValue::VReg(sock)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(sock_non_null, MirType::Bool);
    types.insert(syncookie_ret, MirType::I64);
    types.insert(cleanup_ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected tcp_check_syncookie xdp context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_tcp_gen_syncookie_accepts_tc() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sock,
            helper: BpfHelper::SkLookupTcp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(tuple_slot),
                MirValue::Const(16),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: sock_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: syncookie_ret,
        helper: BpfHelper::TcpGenSyncookie as u32,
        args: vec![
            MirValue::VReg(sock),
            MirValue::VReg(sock),
            MirValue::Const(20),
            MirValue::VReg(sock),
            MirValue::Const(20),
        ],
    });
    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: cleanup_ret,
        helper: BpfHelper::SkRelease as u32,
        args: vec![MirValue::VReg(sock)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(sock_non_null, MirType::Bool);
    types.insert(syncookie_ret, MirType::I64);
    types.insert(cleanup_ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected tcp_gen_syncookie tc context to verify");
}

#[test]
fn test_helper_tcp_raw_syncookie_checks_stack_header_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ip_slot = func.alloc_stack_slot(20, 8, StackSlotKind::StringBuffer);
    let th_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::TcpRawGenSyncookieIpv4 as u32,
            args: vec![
                MirValue::StackSlot(ip_slot),
                MirValue::StackSlot(th_slot),
                MirValue::Const(20),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected raw syncookie bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper tcp_raw_gen_syncookie_ipv4 th out of bounds")
            || e.message
                .contains("helper tcp_raw_gen_syncookie_ipv4 th requires 20 bytes")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_tcp_raw_syncookie_accepts_xdp() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ip_slot = func.alloc_stack_slot(40, 8, StackSlotKind::StringBuffer);
    let th_slot = func.alloc_stack_slot(20, 8, StackSlotKind::StringBuffer);
    let ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::TcpRawCheckSyncookieIpv6 as u32,
            args: vec![MirValue::StackSlot(ip_slot), MirValue::StackSlot(th_slot)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected raw syncookie xdp context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_tcp_raw_syncookie_rejects_kprobe() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ip_slot = func.alloc_stack_slot(20, 8, StackSlotKind::StringBuffer);
    let th_slot = func.alloc_stack_slot(20, 8, StackSlotKind::StringBuffer);
    let ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::TcpRawCheckSyncookieIpv4 as u32,
            args: vec![MirValue::StackSlot(ip_slot), MirValue::StackSlot(th_slot)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected raw syncookie kprobe program-surface error");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "helper 'bpf_tcp_raw_check_syncookie_ipv4' is only valid in xdp, tc_action, tc, tcx, and netkit programs",
        )
    }));
}

#[test]
fn test_helper_sk_storage_get_allows_null_init_value() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let sk = func.alloc_vreg();
    let sk_non_null = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let storage = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: sk_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sk),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: sk_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: storage,
        helper: BpfHelper::SkStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(sk),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(sk, MirType::named_kernel_struct_ptr("bpf_sock"));
    types.insert(sk_non_null, MirType::Bool);
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    verify_mir(&func, &types).expect("expected sk_storage_get null init value to verify");
}

#[test]
fn test_helper_storage_get_rejects_invalid_flags() {
    for (helper, object_ty) in [
        (
            BpfHelper::SkStorageGet,
            MirType::named_kernel_struct_ptr("bpf_sock"),
        ),
        (
            BpfHelper::TaskStorageGet,
            MirType::named_kernel_struct_ptr("task_struct"),
        ),
        (
            BpfHelper::InodeStorageGet,
            MirType::named_kernel_struct_ptr("inode"),
        ),
        (
            BpfHelper::CgrpStorageGet,
            MirType::named_kernel_struct_ptr("cgroup"),
        ),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let object = func.alloc_vreg();
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args: vec![
                    MirValue::StackSlot(map_slot),
                    MirValue::VReg(object),
                    MirValue::Const(0),
                    MirValue::Const(2),
                ],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(object, object_ty);
        types.insert(
            dst,
            MirType::Ptr {
                pointee: Box::new(MirType::Unknown),
                address_space: AddressSpace::Map,
            },
        );

        let err =
            verify_mir(&func, &types).expect_err("expected storage_get flag validation error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("storage get helpers require arg3 flags")),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_helper_sk_storage_get_rejects_anonymous_kernel_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let sk = func.alloc_vreg();
    let sk_non_null = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let storage = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: sk_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sk),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: sk_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: storage,
        helper: BpfHelper::SkStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(sk),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        sk,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(sk_non_null, MirType::Bool);
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    let err = verify_mir(&func, &types)
        .expect_err("expected anonymous kernel pointer to fail sk_storage_get");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_sk_storage_get' arg1 expects socket pointer")
    }));
}

#[test]
fn test_helper_sk_storage_get_rejects_map_lookup_value_as_map_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let check_sk = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let map_val = func.alloc_vreg();
    let sk = func.alloc_vreg();
    let map_non_null = func.alloc_vreg();
    let sk_non_null = func.alloc_vreg();
    let storage = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: map_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(map_val),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: map_non_null,
        if_true: check_sk,
        if_false: done,
    };

    func.block_mut(check_sk).instructions.push(MirInst::BinOp {
        dst: sk_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sk),
        rhs: MirValue::Const(0),
    });
    func.block_mut(check_sk).terminator = MirInst::Branch {
        cond: sk_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: storage,
        helper: BpfHelper::SkStorageGet as u32,
        args: vec![
            MirValue::VReg(map_val),
            MirValue::VReg(sk),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map_val,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(
        sk,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(map_non_null, MirType::Bool);
    types.insert(sk_non_null, MirType::Bool);
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected sk_storage_get map-arg rejection");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper sk_storage_get map expects pointer in [Stack]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_sk_storage_get_rejects_non_kernel_sk_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sk_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let storage = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: storage,
            helper: BpfHelper::SkStorageGet as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(sk_slot),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected sk_storage_get sk pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper sk_storage_get sk expects pointer in [Kernel], got stack slot")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_sk_storage_delete_rejects_non_kernel_sk_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sk_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::SkStorageDelete as u32,
            args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(sk_slot)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected sk_storage_delete sk pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper sk_storage_delete sk expects pointer in [Kernel], got stack slot")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_sk_assign_allows_null_sk_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let ctx_non_null = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ctx_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: ctx_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: ret,
        helper: BpfHelper::SkAssign as u32,
        args: vec![MirValue::VReg(ctx), MirValue::Const(0), MirValue::Const(0)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(ctx_non_null, MirType::Bool);
    types.insert(ret, MirType::I64);

    verify_mir(&func, &types).expect("expected sk_assign null sk to verify");
}

#[test]
fn test_helper_sk_assign_rejects_non_kernel_ctx_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sk = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: sk,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::SkAssign as u32,
            args: vec![
                MirValue::StackSlot(ctx_slot),
                MirValue::VReg(sk),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        sk,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(pid, MirType::I64);
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected sk_assign ctx pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper sk_assign ctx expects pointer in [Kernel], got stack slot")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_sk_assign_rejects_non_kernel_sk_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let sk_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let ret = func.alloc_vreg();
    let pid = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ctx,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::SkAssign as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(sk_slot),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(pid, MirType::I64);
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected sk_assign sk pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper sk_assign sk expects pointer in [Kernel], got stack slot")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_task_storage_get_allows_null_init_value() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let storage = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: task_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: task_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: storage,
        helper: BpfHelper::TaskStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(task),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(task, MirType::named_kernel_struct_ptr("task_struct"));
    types.insert(task_non_null, MirType::Bool);
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    verify_mir(&func, &types).expect("expected task_storage_get null init value to verify");
}

#[test]
fn test_helper_task_storage_get_rejects_anonymous_kernel_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let storage = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: task_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: task_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: storage,
        helper: BpfHelper::TaskStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(task),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(task_non_null, MirType::Bool);
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    let err = verify_mir(&func, &types)
        .expect_err("expected anonymous kernel pointer to fail task_storage_get");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_task_storage_get' arg1 expects task pointer")
    }));
}

#[test]
fn test_helper_task_storage_get_rejects_map_lookup_value_as_map_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let check_task = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let map_val = func.alloc_vreg();
    let task = func.alloc_vreg();
    let map_non_null = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let storage = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: map_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(map_val),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: map_non_null,
        if_true: check_task,
        if_false: done,
    };

    func.block_mut(check_task)
        .instructions
        .push(MirInst::BinOp {
            dst: task_non_null,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(task),
            rhs: MirValue::Const(0),
        });
    func.block_mut(check_task).terminator = MirInst::Branch {
        cond: task_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: storage,
        helper: BpfHelper::TaskStorageGet as u32,
        args: vec![
            MirValue::VReg(map_val),
            MirValue::VReg(task),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map_val,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(map_non_null, MirType::Bool);
    types.insert(task_non_null, MirType::Bool);
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected task_storage_get map-arg rejection");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper task_storage_get map expects pointer in [Stack]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_task_storage_get_rejects_non_kernel_task_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let task_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let storage = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: storage,
            helper: BpfHelper::TaskStorageGet as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(task_slot),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    let err =
        verify_mir(&func, &types).expect_err("expected task_storage_get task pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper task_storage_get task expects pointer in [Kernel], got stack slot")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_task_storage_delete_rejects_non_kernel_task_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let task_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::TaskStorageDelete as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(task_slot),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected task_storage_delete task pointer-kind error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper task_storage_delete task expects pointer in [Kernel], got stack slot"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_inode_storage_get_allows_null_init_value() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let inode = func.alloc_vreg();
    let inode_non_null = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let storage = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: inode_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(inode),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: inode_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: storage,
        helper: BpfHelper::InodeStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(inode),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(inode, MirType::named_kernel_struct_ptr("inode"));
    types.insert(inode_non_null, MirType::Bool);
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    verify_mir(&func, &types).expect("expected inode_storage_get null init value to verify");
}

#[test]
fn test_helper_inode_storage_get_rejects_anonymous_kernel_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let inode = func.alloc_vreg();
    let inode_non_null = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let storage = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: inode_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(inode),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: inode_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: storage,
        helper: BpfHelper::InodeStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(inode),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        inode,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(inode_non_null, MirType::Bool);
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    let err = verify_mir(&func, &types)
        .expect_err("expected anonymous kernel pointer to fail inode_storage_get");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_inode_storage_get' arg1 expects inode pointer")
    }));
}

#[test]
fn test_helper_inode_storage_get_rejects_map_lookup_value_as_map_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let check_inode = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let map_val = func.alloc_vreg();
    let inode = func.alloc_vreg();
    let map_non_null = func.alloc_vreg();
    let inode_non_null = func.alloc_vreg();
    let storage = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: map_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(map_val),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: map_non_null,
        if_true: check_inode,
        if_false: done,
    };

    func.block_mut(check_inode)
        .instructions
        .push(MirInst::BinOp {
            dst: inode_non_null,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(inode),
            rhs: MirValue::Const(0),
        });
    func.block_mut(check_inode).terminator = MirInst::Branch {
        cond: inode_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: storage,
        helper: BpfHelper::InodeStorageGet as u32,
        args: vec![
            MirValue::VReg(map_val),
            MirValue::VReg(inode),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map_val,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(
        inode,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(map_non_null, MirType::Bool);
    types.insert(inode_non_null, MirType::Bool);
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected inode_storage_get map-arg rejection");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper inode_storage_get map expects pointer in [Stack]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_inode_storage_get_rejects_non_kernel_inode_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let inode_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let storage = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: storage,
            helper: BpfHelper::InodeStorageGet as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(inode_slot),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    let err =
        verify_mir(&func, &types).expect_err("expected inode_storage_get inode pointer-kind error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper inode_storage_get inode expects pointer in [Kernel], got stack slot"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_inode_storage_delete_rejects_non_kernel_inode_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let inode_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::InodeStorageDelete as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(inode_slot),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected inode_storage_delete inode pointer-kind error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper inode_storage_delete inode expects pointer in [Kernel], got stack slot"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_cgrp_storage_get_allows_null_cgroup_and_init_value() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let storage = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: storage,
            helper: BpfHelper::CgrpStorageGet as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    verify_mir(&func, &types).expect("expected cgrp_storage_get null cgroup to verify");
}

#[test]
fn test_helper_cgrp_storage_get_allows_maybe_null_cgroup_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let cgroup = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let storage = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: storage,
            helper: BpfHelper::CgrpStorageGet as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::VReg(cgroup),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cgroup, MirType::named_kernel_struct_ptr("cgroup"));
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    verify_mir(&func, &types).expect("expected maybe-null cgroup pointer to verify");
}

#[test]
fn test_helper_cgrp_storage_get_rejects_anonymous_kernel_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let cgroup = func.alloc_vreg();
    let cgroup_non_null = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let storage = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cgroup_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(cgroup),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cgroup_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: storage,
        helper: BpfHelper::CgrpStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(cgroup),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cgroup_non_null, MirType::Bool);
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );

    let err = verify_mir(&func, &types)
        .expect_err("expected anonymous kernel pointer to fail cgrp_storage_get");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_cgrp_storage_get' arg1 expects cgroup pointer")
    }));
}

#[test]
fn test_helper_cgrp_storage_delete_allows_null_cgroup() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::CgrpStorageDelete as u32,
            args: vec![MirValue::StackSlot(map_slot), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ret, MirType::I64);

    verify_mir(&func, &types).expect("expected cgrp_storage_delete null cgroup to verify");
}

#[test]
fn test_helper_cgrp_storage_delete_rejects_anonymous_kernel_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let cgroup = func.alloc_vreg();
    let cgroup_non_null = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cgroup_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(cgroup),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cgroup_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: ret,
        helper: BpfHelper::CgrpStorageDelete as u32,
        args: vec![MirValue::StackSlot(map_slot), MirValue::VReg(cgroup)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cgroup_non_null, MirType::Bool);
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected anonymous kernel pointer to fail cgrp_storage_delete");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_cgrp_storage_delete' arg1 expects cgroup pointer")
    }));
}

#[test]
fn test_helper_ringbuf_reserve_submit_releases_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let submit = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let record = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let submit_ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: record,
            helper: 131, // bpf_ringbuf_reserve(map, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(record),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: submit,
        if_false: done,
    };

    func.block_mut(submit)
        .instructions
        .push(MirInst::CallHelper {
            dst: submit_ret,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
    func.block_mut(submit).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(submit_ret, MirType::I64);
    verify_mir(&func, &types).expect("expected ringbuf reference to be released");
}

#[test]
fn test_helper_ringbuf_reserve_leak_is_rejected() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let leak = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let record = func.alloc_vreg();
    let cond = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: record,
            helper: 131, // bpf_ringbuf_reserve(map, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(record),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: leak,
        if_false: done,
    };

    func.block_mut(leak).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected leak error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased ringbuf record reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_submit_requires_ringbuf_record_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::StackSlot(slot), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected ringbuf pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 132 arg0 expects ringbuf record pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_submit_discard_reject_invalid_flags() {
    for helper in [BpfHelper::RingbufSubmit, BpfHelper::RingbufDiscard] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let record = func.alloc_vreg();
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: record,
                helper: BpfHelper::RingbufReserve as u32,
                args: vec![
                    MirValue::StackSlot(map_slot),
                    MirValue::Const(8),
                    MirValue::Const(0),
                ],
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args: vec![MirValue::VReg(record), MirValue::Const(4)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);
        let err = verify_mir(&func, &types).expect_err("expected ringbuf flag validation error");
        assert!(
            err.iter().any(|e| e.message.contains(match helper {
                BpfHelper::RingbufSubmit => "helper 'bpf_ringbuf_submit' requires arg1 flags",
                BpfHelper::RingbufDiscard => "helper 'bpf_ringbuf_discard' requires arg1 flags",
                _ => unreachable!(),
            })),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_helper_ringbuf_submit_rejects_double_release() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let submit = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let record = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let submit_ret0 = func.alloc_vreg();
    let submit_ret1 = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: record,
            helper: 131, // bpf_ringbuf_reserve(map, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(record),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: submit,
        if_false: done,
    };

    func.block_mut(submit)
        .instructions
        .push(MirInst::CallHelper {
            dst: submit_ret0,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
    func.block_mut(submit)
        .instructions
        .push(MirInst::CallHelper {
            dst: submit_ret1,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
    func.block_mut(submit).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(submit_ret0, MirType::I64);
    types.insert(submit_ret1, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected double-release error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 132 arg0 expects pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_submit_invalidates_record_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let submit = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let record = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let submit_ret = func.alloc_vreg();
    let load_dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: record,
            helper: 131, // bpf_ringbuf_reserve(map, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(record),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: submit,
        if_false: done,
    };

    func.block_mut(submit)
        .instructions
        .push(MirInst::CallHelper {
            dst: submit_ret,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
    func.block_mut(submit).instructions.push(MirInst::Load {
        dst: load_dst,
        ptr: record,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(submit).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(submit_ret, MirType::I64);
    types.insert(load_dst, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected use-after-release error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("load requires pointer type")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_perf_event_output_rejects_user_ctx_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 25, // bpf_perf_event_output(ctx, map, flags, data, size)
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(map_slot),
            MirValue::Const(0),
            MirValue::StackSlot(data_slot),
            MirValue::Const(8),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper ctx pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper perf_event_output ctx expects pointer in [Kernel]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_get_stackid_rejects_user_ctx_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 27, // bpf_get_stackid(ctx, map, flags)
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(map_slot),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper ctx pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_stackid ctx expects pointer in [Kernel]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_get_stack_rejects_user_ctx_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetStack as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(buf_slot),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper ctx pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_stack ctx expects pointer in [Kernel]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_tail_call_rejects_user_ctx_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 12, // bpf_tail_call(ctx, prog_array_map, index)
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(map_slot),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper ctx pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper tail_call ctx expects pointer in [Kernel]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_tail_call_rejects_pointer_index() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let index_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).terminator = MirInst::TailCall {
        prog_map: MapRef {
            name: "jumps".to_string(),
            kind: MapKind::ProgArray,
        },
        index: MirValue::StackSlot(index_slot),
    };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected tail-call index error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("tail_call index expects scalar")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_tail_call_rejects_non_prog_array_map_kind() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    func.block_mut(entry).terminator = MirInst::TailCall {
        prog_map: MapRef {
            name: "not_prog_array".to_string(),
            kind: MapKind::Hash,
        },
        index: MirValue::Const(0),
    };

    let err =
        verify_mir(&func, &HashMap::new()).expect_err("expected non-ProgArray tail_call error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("tail_call requires ProgArray map")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_get_current_comm_requires_positive_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let buf = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 16, // bpf_get_current_comm(buf, size)
            args: vec![MirValue::StackSlot(buf), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected non-positive size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 16 arg1 must be > 0"))
    );
}

#[test]
fn test_helper_get_current_comm_checks_dst_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let buf = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 16, // bpf_get_current_comm(buf, size)
            args: vec![MirValue::StackSlot(buf), MirValue::Const(16)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper dst bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_current_comm dst out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_trace_printk_requires_positive_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let fmt = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 6, // bpf_trace_printk(fmt, fmt_size, ...)
            args: vec![MirValue::StackSlot(fmt), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected non-positive size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 6 arg1 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_trace_printk_checks_fmt_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let fmt = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 6, // bpf_trace_printk(fmt, fmt_size, ...)
            args: vec![MirValue::StackSlot(fmt), MirValue::Const(16)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper fmt bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper trace_printk fmt out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_trace_printk_rejects_user_fmt_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let fmt = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(fmt),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 6, // bpf_trace_printk(fmt, fmt_size, ...)
        args: vec![MirValue::VReg(fmt), MirValue::Const(8)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        fmt,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper fmt pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper trace_printk fmt expects pointer in [Stack, Map]")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_trace_vprintk_verify_call(
    fmt_size: i64,
    fmt_slot_size: usize,
    data_len: i64,
    data_slot_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let fmt = func.alloc_stack_slot(fmt_slot_size, 8, StackSlotKind::StringBuffer);
    let data = func.alloc_stack_slot(data_slot_size, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::TraceVPrintk as u32,
            args: vec![
                MirValue::StackSlot(fmt),
                MirValue::Const(fmt_size),
                MirValue::StackSlot(data),
                MirValue::Const(data_len),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_helper_trace_vprintk_verifies() {
    let (func, types) = make_trace_vprintk_verify_call(8, 8, 16, 16);
    verify_mir(&func, &types).expect("expected trace_vprintk helper to verify");
}

#[test]
fn test_helper_trace_vprintk_checks_data_bounds() {
    let (func, types) = make_trace_vprintk_verify_call(8, 8, 16, 8);
    let err = verify_mir(&func, &types).expect_err("expected trace_vprintk data bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper trace_vprintk data out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_trace_vprintk_rejects_invalid_data_len() {
    let (func, types) = make_trace_vprintk_verify_call(8, 8, 10, 16);
    let err = verify_mir(&func, &types).expect_err("expected trace_vprintk data-len error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_trace_vprintk' requires arg3 to be a multiple of 8")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_get_current_comm_variable_size_range_checks_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let size = func.alloc_vreg();
    func.param_count = 1;
    let ge_one = func.alloc_vreg();
    let le_sixteen = func.alloc_vreg();
    let buf = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ge_one,
        op: BinOpKind::Ge,
        lhs: MirValue::VReg(size),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: ge_one,
        if_true: check_upper,
        if_false: done,
    };

    func.block_mut(check_upper)
        .instructions
        .push(MirInst::BinOp {
            dst: le_sixteen,
            op: BinOpKind::Le,
            lhs: MirValue::VReg(size),
            rhs: MirValue::Const(16),
        });
    func.block_mut(check_upper).terminator = MirInst::Branch {
        cond: le_sixteen,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 16, // bpf_get_current_comm(buf, size)
        args: vec![MirValue::StackSlot(buf), MirValue::VReg(size)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };

    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper dst bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_current_comm dst out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_sysctl_get_current_value_accepts_cgroup_sysctl_context() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SysctlGetCurrentValue as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(16),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected sysctl get_current_value helper to verify on cgroup_sysctl");
}

#[test]
fn test_verify_mir_helper_sysctl_get_current_value_rejects_small_stack_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SysctlGetCurrentValue as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(16),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected sysctl get_current_value helper bounds error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper sysctl_get_current_value buf out of bounds")
    }));
}

#[test]
fn test_helper_get_current_comm_variable_size_range_within_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let size = func.alloc_vreg();
    func.param_count = 1;
    let ge_one = func.alloc_vreg();
    let le_eight = func.alloc_vreg();
    let buf = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ge_one,
        op: BinOpKind::Ge,
        lhs: MirValue::VReg(size),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: ge_one,
        if_true: check_upper,
        if_false: done,
    };

    func.block_mut(check_upper)
        .instructions
        .push(MirInst::BinOp {
            dst: le_eight,
            op: BinOpKind::Le,
            lhs: MirValue::VReg(size),
            rhs: MirValue::Const(8),
        });
    func.block_mut(check_upper).terminator = MirInst::Branch {
        cond: le_eight,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 16, // bpf_get_current_comm(buf, size)
        args: vec![MirValue::StackSlot(buf), MirValue::VReg(size)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };

    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected bounded helper size range to pass");
}

#[test]
fn test_helper_probe_read_user_str_rejects_stack_src() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 114, // bpf_probe_read_user_str(dst, size, unsafe_ptr)
            args: vec![
                MirValue::StackSlot(dst_slot),
                MirValue::Const(8),
                MirValue::StackSlot(src_slot),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected user source pointer error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper probe_read src expects pointer in [User]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_probe_read_user_rejects_stack_src() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::ProbeReadUser as u32,
            args: vec![
                MirValue::StackSlot(dst_slot),
                MirValue::Const(8),
                MirValue::StackSlot(src_slot),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected user source pointer error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper probe_read src expects pointer in [User]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_output_checks_data_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 130, // bpf_ringbuf_output(map, data, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(data_slot),
                MirValue::Const(16),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper data bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper ringbuf_output data out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_rejects_invalid_flags() {
    let cases = [
        (
            BpfHelper::RingbufOutput,
            "helper 'bpf_ringbuf_output' requires arg3 flags",
        ),
        (
            BpfHelper::RingbufReserve,
            "helper 'bpf_ringbuf_reserve' requires arg2 flags",
        ),
        (
            BpfHelper::RingbufQuery,
            "helper 'bpf_ringbuf_query' requires arg1 flags",
        ),
    ];

    for (helper, expected) in cases {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();
        let args = match helper {
            BpfHelper::RingbufOutput => vec![
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(data_slot),
                MirValue::Const(8),
                MirValue::Const(4),
            ],
            BpfHelper::RingbufReserve => vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(1),
            ],
            BpfHelper::RingbufQuery => vec![MirValue::StackSlot(map_slot), MirValue::Const(4)],
            _ => unreachable!(),
        };

        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args,
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);
        let err = verify_mir(&func, &types).expect_err("expected ringbuf flag validation error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_helper_map_update_rejects_user_key_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call_block = func.alloc_block();
    let exit_block = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(key),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call_block,
        if_false: exit_block,
    };

    func.block_mut(call_block)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 2, // bpf_map_update_elem(map, key, value, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::VReg(key),
                MirValue::StackSlot(value_slot),
                MirValue::Const(0),
            ],
        });
    func.block_mut(call_block).terminator = MirInst::Return { val: None };

    func.block_mut(exit_block).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        key,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected map key pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper map_update key expects pointer in [Stack, Map]")),
        "unexpected errors: {:?}",
        err
    );
}
