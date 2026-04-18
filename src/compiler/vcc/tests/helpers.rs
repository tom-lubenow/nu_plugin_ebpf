use super::*;
use crate::compiler::mir::StructField;
use crate::compiler::subfn_summaries::SubfunctionReturnSummary;
use crate::compiler::{EbpfProgramType, MapRef, ProbeContext, ProgramCapability, ProgramTypeInfo};

const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: i64 = 4;
const BPF_SOCK_OPS_HDR_OPT_LEN_CB: i64 = 14;
const BPF_SOCK_OPS_WRITE_HDR_OPT_CB: i64 = 15;
const BPF_SOCK_OPS_TSTAMP_SCHED_CB: i64 = 16;

#[test]
fn test_verify_mir_helper_map_lookup_rejects_out_of_bounds_key_pointer() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ringbuf_output_checks_data_bounds() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ringbuf_reserve_vreg_size_positive_required() {
    let (mut func, entry) = new_mir_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(0),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 131, // bpf_ringbuf_reserve(map, size, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::VReg(size),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper size error");
    assert!(
        err.iter()
            .any(|e| e.kind == VccErrorKind::UnsupportedInstruction),
        "expected helper size error, got {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 131 arg1 must be > 0")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ringbuf_reserve_submit_ok() {
    let (mut func, entry) = new_mir_function();
    let submit = func.alloc_block();
    let done = func.alloc_block();
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
    verify_mir(&func, &types).expect("expected ringbuf submit flow to pass");
}

#[test]
fn test_verify_mir_accepts_helper_context_argument_from_ctx_pointer_load() {
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
        "helper 'bpf_get_socket_cookie' is only valid in fentry, fexit, tp_btf, socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, sock_ops, sk_skb, and sk_skb_parser programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_get_socket_cookie_accepts_socket_filter() {
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
        let (mut func, entry) = new_mir_function();
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
        let (mut func, entry) = new_mir_function();
        let call = func.alloc_block();
        let done = func.alloc_block();
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
fn test_verify_mir_for_program_rejects_missing_tail_call_capability() {
    const LIMITED_CAPABILITIES: &[ProgramCapability] = &[ProgramCapability::Emit];

    let limited_program = ProgramTypeInfo {
        supported_capabilities: LIMITED_CAPABILITIES,
        ..*EbpfProgramType::Kprobe.info()
    };
    let (mut func, entry) = new_mir_function();

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
fn test_verify_mir_for_program_redirect_requires_zero_flags_in_xdp() {
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
fn test_verify_mir_for_program_redirect_rejects_non_packet_programs() {
    let (mut func, entry) = new_mir_function();
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
        e.message
            .contains("helper 'bpf_redirect' is only valid in xdp and tc programs")
    }));
}

#[test]
fn test_verify_mir_for_program_redirect_neigh_rejects_non_tc_programs() {
    let (mut func, entry) = new_mir_function();
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
        e.message
            .contains("helper 'bpf_redirect_neigh' is only valid in tc programs")
    }));
}

#[test]
fn test_verify_mir_for_program_msg_apply_bytes_rejects_non_sk_msg_programs() {
    let (mut func, entry) = new_mir_function();
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
        let (mut func, entry) = new_mir_function();
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

#[test]
fn test_verify_mir_for_program_sockopt_helpers_reject_invalid_program_or_attach() {
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
        (
            BpfHelper::SetSockOpt,
            ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:bind4"),
            "helper 'bpf_setsockopt' is only valid on cgroup_sock_addr connect4/connect6 hooks",
        ),
        (
            BpfHelper::GetSockOpt,
            ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:bind4"),
            "helper 'bpf_getsockopt' is only valid on cgroup_sock_addr connect4/connect6 hooks",
        ),
    ] {
        let (mut func, entry) = new_mir_function();
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
fn test_verify_mir_for_program_bind_helper_rejects_invalid_program_or_attach() {
    for (probe_ctx, expected) in [
        (
            ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read"),
            "helper 'bpf_bind' is only valid in cgroup_sock_addr programs",
        ),
        (
            ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:bind4"),
            "helper 'bpf_bind' is only valid on cgroup_sock_addr connect4/connect6 hooks",
        ),
    ] {
        let (mut func, entry) = new_mir_function();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let addr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

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
                helper: BpfHelper::Bind as u32,
                args: vec![
                    MirValue::VReg(ctx),
                    MirValue::StackSlot(addr_slot),
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
            .expect_err("expected bind helper program-surface error");
        assert!(err.iter().any(|e| e.message.contains(expected)));
    }
}

#[test]
fn test_verify_mir_for_program_sock_ops_cb_flags_set_rejects_invalid_program() {
    let (mut func, entry) = new_mir_function();
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
            helper: BpfHelper::SockOpsCbFlagsSet as u32,
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

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected sock_ops_cb_flags_set helper program-surface error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_sock_ops_cb_flags_set' is only valid in sock_ops programs")
    }));
}

#[test]
fn test_verify_mir_for_program_sock_ops_hdr_opt_helpers_reject_invalid_program() {
    for helper in [
        BpfHelper::LoadHdrOpt,
        BpfHelper::StoreHdrOpt,
        BpfHelper::ReserveHdrOpt,
    ] {
        let (mut func, entry) = new_mir_function();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let args = match helper {
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

        let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected sock_ops hdr-opt helper program-surface error");
        assert!(err.iter().any(|e| e.message.contains(&format!(
            "helper '{}' is only valid in sock_ops programs",
            helper.name()
        ))));
    }
}

#[test]
fn test_verify_mir_for_probe_context_socket_map_helpers_reject_invalid_programs() {
    for (helper, program_type, spec, expected) in [
        (
            BpfHelper::SockMapUpdate,
            EbpfProgramType::Kprobe,
            "ksys_read",
            "helper 'bpf_sock_map_update' is only valid in sock_ops programs",
        ),
        (
            BpfHelper::SockHashUpdate,
            EbpfProgramType::Kprobe,
            "ksys_read",
            "helper 'bpf_sock_hash_update' is only valid in sock_ops programs",
        ),
        (
            BpfHelper::MsgRedirectMap,
            EbpfProgramType::Tc,
            "lo:ingress",
            "helper 'bpf_msg_redirect_map' is only valid in sk_msg programs",
        ),
        (
            BpfHelper::MsgRedirectHash,
            EbpfProgramType::Tc,
            "lo:ingress",
            "helper 'bpf_msg_redirect_hash' is only valid in sk_msg programs",
        ),
        (
            BpfHelper::SkRedirectMap,
            EbpfProgramType::Kprobe,
            "ksys_read",
            "helper 'bpf_sk_redirect_map' is only valid in sk_skb and sk_skb_parser programs",
        ),
        (
            BpfHelper::SkRedirectHash,
            EbpfProgramType::Kprobe,
            "ksys_read",
            "helper 'bpf_sk_redirect_hash' is only valid in sk_skb and sk_skb_parser programs",
        ),
    ] {
        let (mut func, entry) = new_mir_function();
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

        let probe_ctx = ProbeContext::new(program_type, spec);
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected socket-map helper program-surface error");
        assert!(err.iter().any(|e| e.message.contains(expected)));
    }
}

#[test]
fn test_verify_mir_for_probe_context_skb_packet_edit_helpers_reject_invalid_programs() {
    for helper in [
        BpfHelper::SkbStoreBytes,
        BpfHelper::L3CsumReplace,
        BpfHelper::L4CsumReplace,
        BpfHelper::GetHashRecalc,
        BpfHelper::SkbChangeTail,
        BpfHelper::SkbPullData,
        BpfHelper::CsumUpdate,
        BpfHelper::SetHashInvalid,
        BpfHelper::SkbChangeHead,
        BpfHelper::SkbAdjustRoom,
    ] {
        let (mut func, entry) = new_mir_function();
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
            BpfHelper::GetHashRecalc | BpfHelper::SetHashInvalid => vec![],
            BpfHelper::SkbChangeTail | BpfHelper::SkbChangeHead => {
                vec![MirValue::Const(64), MirValue::Const(0)]
            }
            BpfHelper::SkbPullData | BpfHelper::CsumUpdate => vec![MirValue::Const(64)],
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

        let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected skb packet-edit helper program-surface error");
        assert!(err.iter().any(|e| {
            e.message.contains(&format!(
                "helper '{}' is only valid in tc, sk_skb, and sk_skb_parser programs",
                helper.name()
            ))
        }));
    }
}

#[test]
fn test_verify_mir_for_probe_context_skb_store_bytes_accepts_in_bounds_source_buffer() {
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
fn test_verify_mir_helper_sock_map_update_rejects_out_of_bounds_key_pointer() {
    let (mut func, entry) = new_mir_function();
    let ctx = func.alloc_vreg();
    let key_base = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(4, 4, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key_base,
        src: MirValue::StackSlot(key_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: key,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(key_base),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SockMapUpdate as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::VReg(key),
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

    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected socket-map key bounds error");
    assert!(
        err.iter().any(|e| {
            e.kind == VccErrorKind::PointerBounds
                && e.message.contains("pointer access out of bounds")
        }),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_socket_map_helpers_accept_supported_contexts() {
    for (helper, probe_ctx) in [
        (
            BpfHelper::SockMapUpdate,
            ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup"),
        ),
        (
            BpfHelper::SockHashUpdate,
            ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup"),
        ),
        (
            BpfHelper::MsgRedirectMap,
            ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap"),
        ),
        (
            BpfHelper::MsgRedirectHash,
            ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap"),
        ),
        (
            BpfHelper::SkRedirectMap,
            ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap"),
        ),
        (
            BpfHelper::SkRedirectHash,
            ProbeContext::new(EbpfProgramType::SkSkbParser, "/sys/fs/bpf/demo_sockmap"),
        ),
    ] {
        let (mut func, entry) = new_mir_function();
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

        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected socket-map helper to verify in supported context");
    }
}

#[test]
fn test_verify_mir_helper_redirect_map_rejects_invalid_programs() {
    let (mut func, entry) = new_mir_function();
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

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected redirect_map helper program-surface error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect_map' is only valid in xdp programs")
    }));
}

#[test]
fn test_verify_mir_helper_redirect_map_accepts_xdp() {
    let (mut func, entry) = new_mir_function();
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
            args: vec![MirValue::VReg(map), MirValue::Const(7), MirValue::Const(0)],
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

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected redirect_map helper to verify in xdp");
}

#[test]
fn test_verify_mir_helper_redirect_neigh_requires_zero_flags() {
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
fn test_verify_mir_for_probe_context_redirect_peer_rejects_tc_egress() {
    let (mut func, entry) = new_mir_function();
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
            .contains("helper 'bpf_redirect_peer' is only valid in tc ingress programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_redirect_peer_rejects_non_tc_program() {
    let (mut func, entry) = new_mir_function();
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
        e.message
            .contains("helper 'bpf_redirect_peer' is only valid in tc programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_sk_lookup_tcp_rejects_invalid_program() {
    let (mut func, entry) = new_mir_function();
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
        "helper 'bpf_sk_lookup_tcp' is only valid in xdp, tc, cgroup_skb, cgroup_sock_addr, and sk_skb programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_sk_lookup_tcp_accepts_xdp() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();
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

#[test]
fn test_verify_mir_for_probe_context_sk_assign_rejects_tc_egress() {
    let (mut func, entry) = new_mir_function();
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
            .contains("helper 'bpf_sk_assign' is only valid in tc ingress programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_sk_assign_requires_zero_flags_in_tc() {
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected sk_assign sk_lookup context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_get_listener_sock_rejects_sk_lookup() {
    let (mut func, entry) = new_mir_function();
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
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_get_listener_sock' is only valid in tc and cgroup_skb programs"
        ))
    );
}

#[test]
fn test_verify_mir_for_probe_context_get_listener_sock_accepts_cgroup_skb() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
    let (mut func, entry) = new_mir_function();
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
        e.message
            .contains("helper 'bpf_sk_fullsock' is only valid in tc and cgroup_skb programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_sk_fullsock_accepts_cgroup_skb() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
    let (mut func, entry) = new_mir_function();
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
        "helper 'bpf_tcp_sock' is only valid in tc, cgroup_skb, cgroup_sockopt, and sock_ops programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_tcp_sock_accepts_cgroup_sockopt() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
fn test_verify_mir_for_probe_context_skc_to_tcp_sock_rejects_cgroup_sockopt() {
    let (mut func, entry) = new_mir_function();
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
        "helper 'bpf_skc_to_tcp_sock' is only valid in fentry, fexit, tp_btf, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_skc_to_tcp_sock_accepts_sk_lookup() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
    let (mut func, entry) = new_mir_function();
    let file_check = func.alloc_block();
    let call = func.alloc_block();
    let release_task = func.alloc_block();
    let done = func.alloc_block();
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
        "helper 'bpf_sock_from_file' is only valid in fentry, fexit, and tp_btf programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_sock_from_file_accepts_fentry() {
    let (mut func, entry) = new_mir_function();
    let file_check = func.alloc_block();
    let call = func.alloc_block();
    let release_task = func.alloc_block();
    let done = func.alloc_block();
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
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
fn test_verify_mir_for_probe_context_task_storage_get_rejects_xdp() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
        "helper 'bpf_task_storage_get' is only valid in kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, tp_btf, and lsm programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_task_storage_get_accepts_kretprobe() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
    let (mut func, entry) = new_mir_function();
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
            .contains("helper 'bpf_inode_storage_get' is only valid in lsm programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_sk_storage_get_rejects_xdp() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
        "helper 'bpf_sk_storage_get' is only valid in tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, tp_btf, and lsm programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_sk_storage_get_accepts_cgroup_sock() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
        "helper 'bpf_sk_storage_delete' is only valid in tc, cgroup_skb, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, tp_btf, and lsm programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_sk_storage_delete_accepts_cgroup_sockopt() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
    let load = func.alloc_block();
    let done = func.alloc_block();

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
        err.iter().any(|e| e.kind == VccErrorKind::InvalidLoadStore
            && e.message.contains("load requires pointer operand")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_xdp_adjust_meta_allows_reloaded_packet_pointers() {
    let (mut func, entry) = new_mir_function();
    let load = func.alloc_block();
    let done = func.alloc_block();

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
    let (mut func, entry) = new_mir_function();
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
    let (mut func, entry) = new_mir_function();
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
        .expect_err("expected bpf_skb_set_tstamp to be rejected outside tc");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_skb_set_tstamp' is only valid in tc programs")
    }));
}

#[test]
fn test_verify_mir_helper_skb_set_tstamp_requires_zero_tstamp_for_unspec_type() {
    let (mut func, entry) = new_mir_function();
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
fn test_verify_mir_for_probe_context_skb_set_tstamp_accepts_tc_program() {
    let (mut func, entry) = new_mir_function();
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
}

#[test]
fn test_verify_mir_for_probe_context_skb_pull_data_invalidates_prior_packet_pointers() {
    let (mut func, entry) = new_mir_function();
    let load = func.alloc_block();
    let done = func.alloc_block();

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
        err.iter().any(|e| e.kind == VccErrorKind::InvalidLoadStore
            && e.message.contains("load requires pointer operand")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_skb_pull_data_allows_reloaded_packet_pointers() {
    let (mut func, entry) = new_mir_function();
    let load = func.alloc_block();
    let done = func.alloc_block();

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
    let (mut func, entry) = new_mir_function();
    let load = func.alloc_block();
    let done = func.alloc_block();

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
        err.iter().any(|e| e.kind == VccErrorKind::InvalidLoadStore
            && e.message.contains("load requires pointer operand")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_msg_pull_data_allows_reloaded_packet_pointers() {
    let (mut func, entry) = new_mir_function();
    let load = func.alloc_block();
    let done = func.alloc_block();

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
fn test_verify_mir_helper_ringbuf_reserve_submit_ok_with_eq_null_branch() {
    let (mut func, entry) = new_mir_function();
    let submit = func.alloc_block();
    let done = func.alloc_block();
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
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(record),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: done,
        if_false: submit,
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
    verify_mir(&func, &types).expect("expected ringbuf submit flow to pass");
}

#[test]
fn test_verify_mir_helper_ringbuf_reserve_without_release_rejected() {
    let (mut func, entry) = new_mir_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let record = func.alloc_vreg();

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
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new())
        .expect_err("expected leak error for unreleased ringbuf record");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased ringbuf record reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ringbuf_submit_requires_null_check() {
    let (mut func, entry) = new_mir_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let record = func.alloc_vreg();
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
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: submit_ret,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(submit_ret, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected missing null-check error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("may dereference null pointer")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ringbuf_submit_rejects_double_release() {
    let (mut func, entry) = new_mir_function();
    let submit = func.alloc_block();
    let done = func.alloc_block();
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
        err.iter().any(|e| {
            e.message.contains("ringbuf record already released")
                || e.message
                    .contains("ringbuf release requires pointer operand")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ringbuf_submit_invalidates_record_pointer() {
    let (mut func, entry) = new_mir_function();
    let submit = func.alloc_block();
    let done = func.alloc_block();
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
            .any(|e| e.message.contains("load requires pointer operand")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ringbuf_submit_rejects_map_lookup_pointer() {
    let (mut func, entry) = new_mir_function();
    let submit = func.alloc_block();
    let done = func.alloc_block();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let submit_ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ptr,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr),
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
            args: vec![MirValue::VReg(ptr), MirValue::Const(0)],
        });
    func.block_mut(submit).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(submit_ret, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected ringbuf pointer provenance error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("expects ringbuf record pointer, got Map")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ringbuf_submit_rejects_stack_pointer() {
    let (mut func, entry) = new_mir_function();
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
    let err = verify_mir(&func, &types).expect_err("expected ringbuf pointer provenance error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("expects ringbuf record pointer, got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_perf_event_output_rejects_user_ctx_pointer() {
    let (mut func, entry) = new_mir_function();
    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
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
    func.block_mut(entry).terminator = MirInst::Return { val: None };

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
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper perf_event_output ctx expects pointer in [Kernel]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_perf_event_output_variable_size_range_checks_bounds() {
    let (mut func, entry) = new_mir_function();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let ctx = func.alloc_vreg();
    let size = func.alloc_vreg();
    func.param_count = 2;
    let ge_one = func.alloc_vreg();
    let le_sixteen = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
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
        helper: 25, // bpf_perf_event_output(ctx, map, flags, data, size)
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(map_slot),
            MirValue::Const(0),
            MirValue::StackSlot(data_slot),
            MirValue::VReg(size),
        ],
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
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper perf_event_output data out of bounds")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_perf_event_output_variable_size_range_within_bounds() {
    let (mut func, entry) = new_mir_function();
    let check_ctx = func.alloc_block();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let ctx = func.alloc_vreg();
    let size = func.alloc_vreg();
    func.param_count = 2;
    let ctx_non_null = func.alloc_vreg();
    let ge_one = func.alloc_vreg();
    let le_eight = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ctx_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: ctx_non_null,
        if_true: check_ctx,
        if_false: done,
    };

    func.block_mut(check_ctx).instructions.push(MirInst::BinOp {
        dst: ge_one,
        op: BinOpKind::Ge,
        lhs: MirValue::VReg(size),
        rhs: MirValue::Const(1),
    });
    func.block_mut(check_ctx).terminator = MirInst::Branch {
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
        helper: 25, // bpf_perf_event_output(ctx, map, flags, data, size)
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(map_slot),
            MirValue::Const(0),
            MirValue::StackSlot(data_slot),
            MirValue::VReg(size),
        ],
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
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected bounded helper size range to pass");
}

#[test]
fn test_verify_mir_helper_get_stackid_rejects_user_ctx_pointer() {
    let (mut func, entry) = new_mir_function();
    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 27, // bpf_get_stackid(ctx, map, flags)
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

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
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_stackid ctx expects pointer in [Kernel]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_tail_call_rejects_user_ctx_pointer() {
    let (mut func, entry) = new_mir_function();
    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 12, // bpf_tail_call(ctx, prog_array_map, index)
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

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
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper tail_call ctx expects pointer in [Kernel]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_tail_call_rejects_pointer_index() {
    let (mut func, entry) = new_mir_function();
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
            .any(|e| matches!(e.kind, VccErrorKind::TypeMismatch { .. })),
        "expected type mismatch error, got {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("expected scalar value")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_tail_call_rejects_non_prog_array_map_kind() {
    let (mut func, entry) = new_mir_function();
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
            .any(|e| e.kind == VccErrorKind::UnsupportedInstruction
                && e.message.contains("tail_call requires ProgArray map")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_get_current_comm_positive_size_required() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    let buf = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

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

    let err = verify_mir(&func, &types).expect_err("expected helper size error");
    assert!(
        err.iter()
            .any(|e| e.kind == VccErrorKind::UnsupportedInstruction),
        "expected helper size error, got {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 16 arg1 must be > 0")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_get_current_comm_bounds() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    let buf = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

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

    let err = verify_mir(&func, &types).expect_err("expected helper bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_trace_printk_positive_size_required() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    let fmt = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

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

    let err = verify_mir(&func, &types).expect_err("expected helper size error");
    assert!(
        err.iter()
            .any(|e| e.kind == VccErrorKind::UnsupportedInstruction),
        "expected helper size error, got {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 6 arg1 must be > 0")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_trace_printk_bounds() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    let fmt = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

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

    let err = verify_mir(&func, &types).expect_err("expected helper bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_trace_printk_rejects_user_fmt_pointer() {
    let (mut func, entry) = new_mir_function();
    let fmt = func.alloc_vreg();
    func.param_count = 1;
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 6, // bpf_trace_printk(fmt, fmt_size, ...)
            args: vec![MirValue::VReg(fmt), MirValue::Const(8)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

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
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper trace_printk fmt expects pointer in [Stack, Map]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_get_current_comm_variable_size_range_checks_bounds() {
    let (mut func, entry) = new_mir_function();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();

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

    let err = verify_mir(&func, &types).expect_err("expected helper bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_current_comm dst out of bounds")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_get_current_comm_variable_size_range_within_bounds() {
    let (mut func, entry) = new_mir_function();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();

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
fn test_verify_mir_helper_probe_read_variable_size_range_checks_bounds() {
    let (mut func, entry) = new_mir_function();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let size = func.alloc_vreg();
    func.param_count = 1;
    let ge_one = func.alloc_vreg();
    let le_sixteen = func.alloc_vreg();
    let dst_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
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
        helper: 4, // bpf_probe_read(dst, size, src)
        args: vec![
            MirValue::StackSlot(dst_slot),
            MirValue::VReg(size),
            MirValue::StackSlot(src_slot),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper dst bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper probe_read dst out of bounds")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_probe_read_variable_size_range_within_bounds() {
    let (mut func, entry) = new_mir_function();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let size = func.alloc_vreg();
    func.param_count = 1;
    let ge_one = func.alloc_vreg();
    let le_eight = func.alloc_vreg();
    let dst_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
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
        helper: 4, // bpf_probe_read(dst, size, src)
        args: vec![
            MirValue::StackSlot(dst_slot),
            MirValue::VReg(size),
            MirValue::StackSlot(src_slot),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);
    verify_mir(&func, &types).expect("expected bounded helper size range to pass");
}

#[test]
fn test_verify_mir_helper_probe_read_user_str_rejects_stack_src() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

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

    let err = verify_mir(&func, &types).expect_err("expected helper source space error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper probe_read src expects pointer in [User]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_probe_read_user_rejects_stack_src() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

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

    let err = verify_mir(&func, &types).expect_err("expected helper source space error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper probe_read src expects pointer in [User]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_map_update_rejects_user_key() {
    let (mut func, entry) = new_mir_function();
    let key = func.alloc_vreg();
    func.param_count = 1;
    let dst = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let val_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 2, // bpf_map_update_elem(map, key, value, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::VReg(key),
                MirValue::StackSlot(val_slot),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        key,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper key space error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper map_update key expects pointer in [Stack, Map]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_map_queue_rejects_map_lookup_value_as_map_arg() {
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
        let (mut func, entry) = new_mir_function();
        let call = func.alloc_block();
        let done = func.alloc_block();

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
        types.insert(cond, MirType::Bool);
        types.insert(helper_ret, MirType::I64);

        let err =
            verify_mir(&func, &types).expect_err("expected map queue helper map-arg rejection");
        assert!(
            err.iter().any(|e| e.message.contains(needle)),
            "unexpected error messages for helper {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_helper_map_queue_rejects_non_pointer_value_arg() {
    let helpers = [
        (BpfHelper::MapPushElem, 87u32),
        (BpfHelper::MapPopElem, 88u32),
        (BpfHelper::MapPeekElem, 89u32),
    ];

    for (helper, helper_id) in helpers {
        let (mut func, entry) = new_mir_function();
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

        let err = verify_mir(&func, &types)
            .expect_err("expected map queue helper value-pointer argument rejection");
        assert!(
            err.iter().any(|e| e
                .message
                .contains(&format!("helper {} arg1 expects pointer value", helper_id))),
            "unexpected error messages for helper {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_helper_ringbuf_query_rejects_map_lookup_value_as_map_arg() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

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
    types.insert(cond, MirType::Bool);
    types.insert(query_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected ringbuf_query map-arg rejection");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper ringbuf_query map expects pointer in [Stack]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_tcp_check_syncookie_rejects_non_positive_lengths() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_tcp_gen_syncookie_rejects_non_positive_lengths() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_tcp_check_syncookie_rejects_kprobe() {
    let (mut func, entry) = new_mir_function();
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
        e.message
            .contains("helper 'bpf_tcp_check_syncookie' is only valid in xdp and tc programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_tcp_check_syncookie_accepts_xdp() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
fn test_verify_mir_helper_sk_storage_get_allows_null_init_value() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
fn test_verify_mir_helper_sk_storage_get_rejects_anonymous_kernel_pointer() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
fn test_verify_mir_helper_sk_storage_get_rejects_map_pointer_arg() {
    let (mut func, entry) = new_mir_function();
    let check_sk = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_sk_storage_get_rejects_non_kernel_sk_pointer() {
    let (mut func, entry) = new_mir_function();
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
            .contains("helper sk_storage_get sk expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_sk_storage_delete_rejects_non_kernel_sk_pointer() {
    let (mut func, entry) = new_mir_function();
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
            .contains("helper sk_storage_delete sk expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_sk_assign_allows_null_sk_arg() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let ctx = func.alloc_vreg();
    let ctx_non_null = func.alloc_vreg();
    let ret = func.alloc_vreg();

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
fn test_verify_mir_helper_sk_assign_rejects_non_kernel_ctx_pointer() {
    let (mut func, entry) = new_mir_function();
    let ctx_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let pid = func.alloc_vreg();
    let sk = func.alloc_vreg();
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
    types.insert(pid, MirType::I64);
    types.insert(
        sk,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected sk_assign ctx pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper sk_assign ctx expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_sk_assign_rejects_non_kernel_sk_pointer() {
    let (mut func, entry) = new_mir_function();
    let sk_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let pid = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let ret = func.alloc_vreg();

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
    types.insert(pid, MirType::I64);
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected sk_assign sk pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper sk_assign sk expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_task_storage_get_allows_null_init_value() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
fn test_verify_mir_helper_task_storage_get_rejects_anonymous_kernel_pointer() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
fn test_verify_mir_helper_task_storage_get_rejects_map_pointer_arg() {
    let (mut func, entry) = new_mir_function();
    let check_task = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_task_storage_get_rejects_non_kernel_task_pointer() {
    let (mut func, entry) = new_mir_function();
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
            .contains("helper task_storage_get task expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_task_storage_delete_rejects_non_kernel_task_pointer() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| e
            .message
            .contains("helper task_storage_delete task expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_inode_storage_get_allows_null_init_value() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
fn test_verify_mir_helper_inode_storage_get_rejects_anonymous_kernel_pointer() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
fn test_verify_mir_helper_inode_storage_get_rejects_map_pointer_arg() {
    let (mut func, entry) = new_mir_function();
    let check_inode = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_inode_storage_get_rejects_non_kernel_inode_pointer() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| e
            .message
            .contains("helper inode_storage_get inode expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_inode_storage_delete_rejects_non_kernel_inode_pointer() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| e
            .message
            .contains("helper inode_storage_delete inode expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_unknown_helper_rejects_more_than_five_args() {
    let (mut func, entry) = new_mir_function();
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
            .any(|e| e.kind == VccErrorKind::UnsupportedInstruction
                && e.message.contains("at most 5 arguments")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_rejects_more_than_five_params() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 6;
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected param-count error");
    assert!(
        err.iter()
            .any(|e| e.kind == VccErrorKind::UnsupportedInstruction
                && e.message.contains("at most 5 arguments")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_rejects_subfn_calls_with_more_than_five_args() {
    let (mut func, entry) = new_mir_function();
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
            .any(|e| e.kind == VccErrorKind::UnsupportedInstruction
                && e.message.contains("at most 5 arguments")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_subfn_return_arg_summary_preserves_null_checked_pointer() {
    let (mut func, entry) = new_mir_function();
    let use_value = func.alloc_block();
    let done = func.alloc_block();
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
fn test_verify_mir_helper_kptr_xchg_allows_null_const_arg1() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let dst_ptr = func.alloc_vreg();
    let dst_non_null = func.alloc_vreg();
    let swapped = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: dst_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(dst_ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: dst_non_null,
        if_true: call,
        if_false: done,
    };
    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: swapped,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::Const(0)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(dst_non_null, MirType::Bool);
    types.insert(
        swapped,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    verify_mir(&func, &types).expect("expected kptr_xchg null-pointer arg acceptance");
}

#[test]
fn test_verify_mir_helper_kptr_xchg_rejects_non_null_scalar_arg1() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let dst_ptr = func.alloc_vreg();
    let dst_non_null = func.alloc_vreg();
    let swapped = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: dst_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(dst_ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: dst_non_null,
        if_true: call,
        if_false: done,
    };
    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: swapped,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::Const(1)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(dst_non_null, MirType::Bool);
    types.insert(
        swapped,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected helper pointer-arg rejection");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 194 arg1 expects pointer value")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_kptr_xchg_allows_zero_vreg_arg1() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let dst_ptr = func.alloc_vreg();
    let dst_non_null = func.alloc_vreg();
    let zero = func.alloc_vreg();
    let swapped = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: zero,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: dst_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(dst_ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: dst_non_null,
        if_true: call,
        if_false: done,
    };
    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: swapped,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::VReg(zero)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(dst_non_null, MirType::Bool);
    types.insert(zero, MirType::I64);
    types.insert(
        swapped,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    verify_mir(&func, &types).expect("expected kptr_xchg known-zero vreg arg acceptance");
}

#[test]
fn test_verify_mir_helper_kptr_xchg_rejects_non_zero_vreg_arg1() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let dst_ptr = func.alloc_vreg();
    let dst_non_null = func.alloc_vreg();
    let one = func.alloc_vreg();
    let swapped = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: one,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: dst_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(dst_ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: dst_non_null,
        if_true: call,
        if_false: done,
    };
    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: swapped,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::VReg(one)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(dst_non_null, MirType::Bool);
    types.insert(one, MirType::I64);
    types.insert(
        swapped,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err =
        verify_mir(&func, &types).expect_err("expected non-zero kptr_xchg vreg arg rejection");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 194 arg1 expects null (0) or pointer value")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_kptr_xchg_rejects_non_map_dst_arg0() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let dst_ptr = func.alloc_vreg();
    let swapped = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: swapped,
            helper: BpfHelper::KptrXchg as u32,
            args: vec![MirValue::VReg(dst_ptr), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        swapped,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err =
        verify_mir(&func, &types).expect_err("expected kptr_xchg map-pointer destination error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper kptr_xchg dst expects pointer in [Map]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_kptr_xchg_transfers_reference_and_releases_old_value() {
    let (mut func, entry) = new_mir_function();
    let acquire = func.alloc_block();
    let swap = func.alloc_block();
    let release_old = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let dst_ptr = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let dst_non_null = func.alloc_vreg();
    let swapped = func.alloc_vreg();
    let swapped_non_null = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: dst_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(dst_ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: dst_non_null,
        if_true: acquire,
        if_false: done,
    };

    func.block_mut(acquire).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(acquire)
        .instructions
        .push(MirInst::CallKfunc {
            dst: task,
            kfunc: "bpf_task_from_pid".to_string(),
            btf_id: None,
            args: vec![pid],
        });
    func.block_mut(acquire).instructions.push(MirInst::BinOp {
        dst: task_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(acquire).terminator = MirInst::Branch {
        cond: task_non_null,
        if_true: swap,
        if_false: done,
    };

    func.block_mut(swap).instructions.push(MirInst::CallHelper {
        dst: swapped,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::VReg(task)],
    });
    func.block_mut(swap).instructions.push(MirInst::BinOp {
        dst: swapped_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(swapped),
        rhs: MirValue::Const(0),
    });
    func.block_mut(swap).terminator = MirInst::Branch {
        cond: swapped_non_null,
        if_true: release_old,
        if_false: done,
    };

    func.block_mut(release_old)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![swapped],
        });
    func.block_mut(release_old).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(task_non_null, MirType::Bool);
    types.insert(dst_non_null, MirType::Bool);
    types.insert(
        swapped,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(swapped_non_null, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected kptr_xchg transfer/release semantics");
}

#[test]
fn test_verify_mir_helper_sk_lookup_release_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let lookup = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let ctx = func.alloc_vreg();
    let ctx_non_null = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ctx_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: ctx_non_null,
        if_true: lookup,
        if_false: done,
    };

    func.block_mut(lookup)
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
    func.block_mut(lookup).instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(lookup).terminator = MirInst::Branch {
        cond: sock_non_null,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallHelper {
            dst: release_ret,
            helper: BpfHelper::SkRelease as u32,
            args: vec![MirValue::VReg(sock)],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
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
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(sock_non_null, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected sk_lookup/sk_release socket lifetime to verify");
}

#[test]
fn test_verify_mir_helper_sk_release_rejects_non_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let bad_release_ret = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallHelper {
            dst: bad_release_ret,
            helper: BpfHelper::SkRelease as u32,
            args: vec![MirValue::VReg(task)],
        });
    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: cleanup_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
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
    types.insert(bad_release_ret, MirType::I64);
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected sk_release ref-kind mismatch");
    assert!(
        err.iter().any(|e| {
            e.message
                .contains("kfunc arg0 expects socket reference, got task reference")
                || e.message
                    .contains("kfunc release expects socket reference, got task reference")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_sk_fullsock_rejects_non_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let fullsock = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        dst: fullsock,
        helper: BpfHelper::SkFullsock as u32,
        args: vec![MirValue::VReg(task)],
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
        fullsock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected sk_fullsock ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 95 arg0 expects socket reference, got task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_tcp_sock_rejects_non_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let tcp_sock = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        dst: tcp_sock,
        helper: BpfHelper::TcpSock as u32,
        args: vec![MirValue::VReg(task)],
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
        tcp_sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected tcp_sock ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 96 arg0 expects socket reference, got task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_skc_to_tcp_sock_rejects_non_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let tcp_sock = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        dst: tcp_sock,
        helper: BpfHelper::SkcToTcpSock as u32,
        args: vec![MirValue::VReg(task)],
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
        tcp_sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected skc_to_tcp_sock ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 137 arg0 expects socket reference, got task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_skc_to_tcp6_sock_rejects_non_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let tcp_sock = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        dst: tcp_sock,
        helper: BpfHelper::SkcToTcp6Sock as u32,
        args: vec![MirValue::VReg(task)],
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
        tcp_sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected skc_to_tcp6_sock ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 136 arg0 expects socket reference, got task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_tcp_check_syncookie_rejects_non_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        dst: syncookie_ret,
        helper: BpfHelper::TcpCheckSyncookie as u32,
        args: vec![
            MirValue::VReg(task),
            MirValue::VReg(task),
            MirValue::Const(20),
            MirValue::VReg(task),
            MirValue::Const(20),
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
    types.insert(syncookie_ret, MirType::I64);
    types.insert(cleanup_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected tcp_check_syncookie ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 100 arg0 expects socket reference, got task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_tcp_gen_syncookie_rejects_non_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        dst: syncookie_ret,
        helper: BpfHelper::TcpGenSyncookie as u32,
        args: vec![
            MirValue::VReg(task),
            MirValue::VReg(task),
            MirValue::Const(20),
            MirValue::VReg(task),
            MirValue::Const(20),
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
    types.insert(syncookie_ret, MirType::I64);
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected tcp_gen_syncookie ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 110 arg0 expects socket reference, got task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_sk_assign_rejects_non_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let assign_ret = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        dst: assign_ret,
        helper: BpfHelper::SkAssign as u32,
        args: vec![
            MirValue::VReg(task),
            MirValue::VReg(task),
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
    types.insert(assign_ret, MirType::I64);
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected sk_assign ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 124 arg1 expects socket reference, got task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_sock_from_file_rejects_non_file_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let sock = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        dst: sock,
        helper: BpfHelper::SockFromFile as u32,
        args: vec![MirValue::VReg(task)],
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
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected sock_from_file ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 162 arg0 expects file reference, got task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_task_pt_regs_rejects_non_task_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let id = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let cgroup_non_null = func.alloc_vreg();
    let regs = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        dst: regs,
        helper: BpfHelper::TaskPtRegs as u32,
        args: vec![MirValue::VReg(cgroup)],
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
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cgroup_non_null, MirType::Bool);
    types.insert(
        regs,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected task_pt_regs ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 175 arg0 expects task reference, got cgroup reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_task_pt_regs_requires_null_check_for_tracked_task_reference() {
    let (mut func, entry) = new_mir_function();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let regs = func.alloc_vreg();

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
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: regs,
            helper: BpfHelper::TaskPtRegs as u32,
            args: vec![MirValue::VReg(task)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        regs,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected task_pt_regs null-check error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 175 arg0 may dereference null pointer")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_task_storage_get_rejects_non_task_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let id = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let cgroup_non_null = func.alloc_vreg();
    let storage = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        helper: BpfHelper::TaskStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(cgroup),
            MirValue::Const(0),
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
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected task_storage_get ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 156 arg1 expects task reference, got cgroup reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_task_storage_delete_rejects_non_task_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let id = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let cgroup_non_null = func.alloc_vreg();
    let delete_ret = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        dst: delete_ret,
        helper: BpfHelper::TaskStorageDelete as u32,
        args: vec![MirValue::StackSlot(map_slot), MirValue::VReg(cgroup)],
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
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cgroup_non_null, MirType::Bool);
    types.insert(delete_ret, MirType::I64);
    types.insert(cleanup_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected task_storage_delete ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 157 arg1 expects task reference, got cgroup reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_inode_storage_get_rejects_non_inode_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let storage = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        helper: BpfHelper::InodeStorageGet as u32,
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

    let err = verify_mir(&func, &types).expect_err("expected inode_storage_get ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 145 arg1 expects inode reference, got task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_inode_storage_delete_rejects_non_inode_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let delete_ret = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        dst: delete_ret,
        helper: BpfHelper::InodeStorageDelete as u32,
        args: vec![MirValue::StackSlot(map_slot), MirValue::VReg(task)],
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
    types.insert(delete_ret, MirType::I64);
    types.insert(cleanup_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected inode_storage_delete ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 146 arg1 expects inode reference, got task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_additional_skc_casts_reject_non_socket_reference() {
    let helpers = [
        (BpfHelper::SkcToTcpTimewaitSock, 138u32),
        (BpfHelper::SkcToTcpRequestSock, 139u32),
        (BpfHelper::SkcToUdp6Sock, 140u32),
        (BpfHelper::SkcToUnixSock, 178u32),
    ];

    for (helper, helper_id) in helpers {
        let (mut func, entry) = new_mir_function();
        let call = func.alloc_block();
        let done = func.alloc_block();

        let pid = func.alloc_vreg();
        let task = func.alloc_vreg();
        let task_non_null = func.alloc_vreg();
        let casted = func.alloc_vreg();
        let cleanup_ret = func.alloc_vreg();

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
            dst: casted,
            helper: helper as u32,
            args: vec![MirValue::VReg(task)],
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
            casted,
            MirType::Ptr {
                pointee: Box::new(MirType::Unknown),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(cleanup_ret, MirType::I64);

        let err = verify_mir(&func, &types)
            .expect_err("expected additional skc cast helper ref-kind mismatch");
        assert!(
            err.iter().any(|e| e.message.contains(&format!(
                "helper {} arg0 expects socket reference, got task reference",
                helper_id
            ))),
            "unexpected error messages for helper {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_helper_get_listener_sock_rejects_non_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let listener = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        dst: listener,
        helper: BpfHelper::GetListenerSock as u32,
        args: vec![MirValue::VReg(task)],
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
        listener,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected get_listener_sock ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 98 arg0 expects socket reference, got task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_get_listener_sock_rejects_non_kernel_pointer() {
    let (mut func, entry) = new_mir_function();

    let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let listener = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: listener,
            helper: BpfHelper::GetListenerSock as u32,
            args: vec![MirValue::StackSlot(sock_slot)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        listener,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected get_listener_sock pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_listener_sock sk expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_sk_fullsock_rejects_non_kernel_pointer() {
    let (mut func, entry) = new_mir_function();

    let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let fullsock = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: fullsock,
            helper: BpfHelper::SkFullsock as u32,
            args: vec![MirValue::StackSlot(sock_slot)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        fullsock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected sk_fullsock pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper sk_fullsock sk expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_tcp_sock_rejects_non_kernel_pointer() {
    let (mut func, entry) = new_mir_function();

    let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let tcp_sock = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: tcp_sock,
            helper: BpfHelper::TcpSock as u32,
            args: vec![MirValue::StackSlot(sock_slot)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        tcp_sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected tcp_sock pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper tcp_sock sk expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_skc_to_tcp_sock_rejects_non_kernel_pointer() {
    let (mut func, entry) = new_mir_function();

    let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let tcp_sock = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: tcp_sock,
            helper: BpfHelper::SkcToTcpSock as u32,
            args: vec![MirValue::StackSlot(sock_slot)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        tcp_sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected skc_to_tcp_sock pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper skc_to_tcp_sock sk expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_skc_to_tcp6_sock_rejects_non_kernel_pointer() {
    let (mut func, entry) = new_mir_function();

    let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let tcp_sock = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: tcp_sock,
            helper: BpfHelper::SkcToTcp6Sock as u32,
            args: vec![MirValue::StackSlot(sock_slot)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        tcp_sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected skc_to_tcp6_sock pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper skc_to_tcp6_sock sk expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_tcp_check_syncookie_rejects_non_kernel_sk_pointer() {
    let (mut func, entry) = new_mir_function();
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
            helper: BpfHelper::TcpCheckSyncookie as u32,
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

    let err =
        verify_mir(&func, &types).expect_err("expected tcp_check_syncookie pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper tcp_check_syncookie sk expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_tcp_gen_syncookie_rejects_non_kernel_sk_pointer() {
    let (mut func, entry) = new_mir_function();
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
            .contains("helper tcp_gen_syncookie sk expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_sock_from_file_rejects_non_kernel_pointer() {
    let (mut func, entry) = new_mir_function();

    let file_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sock,
            helper: BpfHelper::SockFromFile as u32,
            args: vec![MirValue::StackSlot(file_slot)],
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

    let err = verify_mir(&func, &types).expect_err("expected sock_from_file pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper sock_from_file file expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_task_pt_regs_rejects_non_kernel_pointer() {
    let (mut func, entry) = new_mir_function();

    let task_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let regs = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: regs,
            helper: BpfHelper::TaskPtRegs as u32,
            args: vec![MirValue::StackSlot(task_slot)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        regs,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected task_pt_regs pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper task_pt_regs task expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_task_pt_regs_accepts_named_task_pointer() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
fn test_verify_mir_helper_task_pt_regs_rejects_anonymous_kernel_pointer() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
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
fn test_verify_mir_helper_sysctl_get_current_value_accepts_cgroup_sysctl_context() {
    let (mut func, entry) = new_mir_function();

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
fn test_verify_mir_helper_sysctl_write_helpers_reject_read_context() {
    for helper in [BpfHelper::SysctlGetNewValue, BpfHelper::SysctlSetNewValue] {
        let (mut func, entry) = new_mir_function();
        let guarded = func.alloc_block();
        let done = func.alloc_block();
        let write = func.alloc_vreg();
        let is_read = func.alloc_vreg();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: write,
                field: CtxField::SysctlWrite,
                slot: None,
            });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: is_read,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(write),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond: is_read,
            if_true: guarded,
            if_false: done,
        };

        func.block_mut(guarded)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(guarded)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args: vec![
                    MirValue::VReg(ctx),
                    MirValue::StackSlot(buf_slot),
                    MirValue::Const(16),
                ],
            });
        func.block_mut(guarded).terminator = MirInst::Jump { target: done };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(write, MirType::U32);
        types.insert(is_read, MirType::Bool);
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected sysctl write-mode helper guard error");
        assert!(err.iter().any(|e| {
            e.message.contains(&format!(
                "helper '{}' on cgroup_sysctl requires proving ctx.write == 1 before use",
                helper.name()
            ))
        }));
    }
}

#[test]
fn test_verify_mir_helper_sysctl_write_helpers_accept_write_context() {
    for helper in [BpfHelper::SysctlGetNewValue, BpfHelper::SysctlSetNewValue] {
        let (mut func, entry) = new_mir_function();
        let guarded = func.alloc_block();
        let done = func.alloc_block();
        let write = func.alloc_vreg();
        let is_write = func.alloc_vreg();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: write,
                field: CtxField::SysctlWrite,
                slot: None,
            });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: is_write,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(write),
            rhs: MirValue::Const(1),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond: is_write,
            if_true: guarded,
            if_false: done,
        };

        func.block_mut(guarded)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(guarded)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args: vec![
                    MirValue::VReg(ctx),
                    MirValue::StackSlot(buf_slot),
                    MirValue::Const(16),
                ],
            });
        func.block_mut(guarded).terminator = MirInst::Jump { target: done };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(write, MirType::U32);
        types.insert(is_write, MirType::Bool);
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
            .expect("expected guarded sysctl write-mode helper to verify");
    }
}

#[test]
fn test_verify_mir_helper_sysctl_get_current_value_rejects_small_stack_slot() {
    let (mut func, entry) = new_mir_function();

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
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_getsockopt_accepts_cgroup_sock_addr_connect_context() {
    for probe_ctx in [
        ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4"),
        ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get"),
    ] {
        let (mut func, entry) = new_mir_function();

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
            .expect("expected getsockopt helper to verify on supported socket-option contexts");
    }
}

#[test]
fn test_verify_mir_helper_setsockopt_accepts_supported_socket_option_contexts() {
    for probe_ctx in [
        ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4"),
        ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:set"),
    ] {
        let (mut func, entry) = new_mir_function();

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
            .expect("expected setsockopt helper to verify on supported socket-option contexts");
    }
}

#[test]
fn test_verify_mir_helper_bind_accepts_cgroup_sock_addr_connect_context() {
    let (mut func, entry) = new_mir_function();

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let addr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
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
            helper: BpfHelper::Bind as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(addr_slot),
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

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected bind helper to verify on cgroup_sock_addr connect");
}

#[test]
fn test_verify_mir_helper_sock_ops_cb_flags_set_accepts_sock_ops_context_when_guarded() {
    let (mut func, entry) = new_mir_function();
    let guarded = func.alloc_block();
    let done = func.alloc_block();
    let op = func.alloc_vreg();
    let matches = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: op,
            field: CtxField::SockOp,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: matches,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(op),
        rhs: MirValue::Const(BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: matches,
        if_true: guarded,
        if_false: done,
    };
    func.block_mut(guarded)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(guarded)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SockOpsCbFlagsSet as u32,
            args: vec![MirValue::VReg(ctx), MirValue::Const(0)],
        });
    func.block_mut(guarded).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(op, MirType::I32);
    types.insert(matches, MirType::Bool);
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
        .expect("expected guarded sock_ops_cb_flags_set helper to verify on sock_ops");
}

#[test]
fn test_verify_mir_helper_sock_ops_hdr_opt_helpers_accept_sock_ops_context_when_guarded() {
    for (helper, callback_op) in [
        (BpfHelper::LoadHdrOpt, BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB),
        (BpfHelper::StoreHdrOpt, BPF_SOCK_OPS_WRITE_HDR_OPT_CB),
        (BpfHelper::ReserveHdrOpt, BPF_SOCK_OPS_HDR_OPT_LEN_CB),
    ] {
        let (mut func, entry) = new_mir_function();
        let guarded = func.alloc_block();
        let done = func.alloc_block();
        let op = func.alloc_vreg();
        let matches = func.alloc_vreg();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let args = match helper {
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
                dst: op,
                field: CtxField::SockOp,
                slot: None,
            });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: matches,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(op),
            rhs: MirValue::Const(callback_op),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond: matches,
            if_true: guarded,
            if_false: done,
        };
        func.block_mut(guarded)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(guarded)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args,
            });
        func.block_mut(guarded).terminator = MirInst::Jump { target: done };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(op, MirType::I32);
        types.insert(matches, MirType::Bool);
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
            .expect("expected guarded sock_ops hdr-opt helpers to verify on sock_ops");
    }
}

#[test]
fn test_verify_mir_helper_sock_ops_callback_guards_reject_unsupported_callbacks() {
    for (helper, callback_op, expected) in [
        (
            BpfHelper::SockOpsCbFlagsSet,
            BPF_SOCK_OPS_TSTAMP_SCHED_CB,
            "helper 'bpf_sock_ops_cb_flags_set' on sock_ops requires proving ctx.op <= BPF_SOCK_OPS_WRITE_HDR_OPT_CB before use",
        ),
        (
            BpfHelper::LoadHdrOpt,
            BPF_SOCK_OPS_TSTAMP_SCHED_CB,
            "helper 'bpf_load_hdr_opt' on sock_ops requires proving ctx.op <= BPF_SOCK_OPS_WRITE_HDR_OPT_CB before use",
        ),
        (
            BpfHelper::StoreHdrOpt,
            BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,
            "helper 'bpf_store_hdr_opt' on sock_ops requires proving ctx.op == BPF_SOCK_OPS_WRITE_HDR_OPT_CB before use",
        ),
        (
            BpfHelper::ReserveHdrOpt,
            BPF_SOCK_OPS_WRITE_HDR_OPT_CB,
            "helper 'bpf_reserve_hdr_opt' on sock_ops requires proving ctx.op == BPF_SOCK_OPS_HDR_OPT_LEN_CB before use",
        ),
    ] {
        let (mut func, entry) = new_mir_function();
        let guarded = func.alloc_block();
        let done = func.alloc_block();
        let op = func.alloc_vreg();
        let matches = func.alloc_vreg();
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
                dst: op,
                field: CtxField::SockOp,
                slot: None,
            });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: matches,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(op),
            rhs: MirValue::Const(callback_op),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond: matches,
            if_true: guarded,
            if_false: done,
        };

        func.block_mut(guarded)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(guarded)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args,
            });
        func.block_mut(guarded).terminator = MirInst::Jump { target: done };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(op, MirType::I32);
        types.insert(matches, MirType::Bool);
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        );
        types.insert(dst, MirType::I64);

        let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected sock_ops helper callback guard to reject helper");
        assert!(err.iter().any(|e| e.message.contains(expected)));
    }
}

#[test]
fn test_verify_mir_helper_sock_ops_callback_guards_accept_supported_callbacks() {
    for (helper, callback_op) in [
        (
            BpfHelper::SockOpsCbFlagsSet,
            BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,
        ),
        (BpfHelper::LoadHdrOpt, BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB),
        (BpfHelper::StoreHdrOpt, BPF_SOCK_OPS_WRITE_HDR_OPT_CB),
        (BpfHelper::ReserveHdrOpt, BPF_SOCK_OPS_HDR_OPT_LEN_CB),
    ] {
        let (mut func, entry) = new_mir_function();
        let guarded = func.alloc_block();
        let done = func.alloc_block();
        let op = func.alloc_vreg();
        let matches = func.alloc_vreg();
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
                dst: op,
                field: CtxField::SockOp,
                slot: None,
            });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: matches,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(op),
            rhs: MirValue::Const(callback_op),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond: matches,
            if_true: guarded,
            if_false: done,
        };

        func.block_mut(guarded)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(guarded)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args,
            });
        func.block_mut(guarded).terminator = MirInst::Jump { target: done };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(op, MirType::I32);
        types.insert(matches, MirType::Bool);
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
            .expect("expected supported sock_ops helper callback to verify");
    }
}

#[test]
fn test_verify_mir_helper_additional_skc_casts_reject_non_kernel_pointer() {
    let helpers = [
        (
            BpfHelper::SkcToTcpTimewaitSock,
            "helper skc_to_tcp_timewait_sock sk expects pointer in [Kernel], got Stack",
        ),
        (
            BpfHelper::SkcToTcpRequestSock,
            "helper skc_to_tcp_request_sock sk expects pointer in [Kernel], got Stack",
        ),
        (
            BpfHelper::SkcToUdp6Sock,
            "helper skc_to_udp6_sock sk expects pointer in [Kernel], got Stack",
        ),
        (
            BpfHelper::SkcToUnixSock,
            "helper skc_to_unix_sock sk expects pointer in [Kernel], got Stack",
        ),
    ];

    for (helper, needle) in helpers {
        let (mut func, entry) = new_mir_function();
        let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let casted = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: casted,
                helper: helper as u32,
                args: vec![MirValue::StackSlot(sock_slot)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            casted,
            MirType::Ptr {
                pointee: Box::new(MirType::Unknown),
                address_space: AddressSpace::Kernel,
            },
        );

        let err = verify_mir(&func, &types)
            .expect_err("expected additional skc cast helper pointer-kind error");
        assert!(
            err.iter().any(|e| e.message.contains(needle)),
            "unexpected error messages for helper {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_helper_sk_lookup_leak_is_rejected() {
    let (mut func, entry) = new_mir_function();
    let leak = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let ctx = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sock,
            helper: BpfHelper::SkLookupUdp as u32,
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
        if_true: leak,
        if_false: done,
    };

    func.block_mut(leak).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
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

    let err = verify_mir(&func, &types).expect_err("expected leaked socket reference error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("unreleased kfunc reference at function exit")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_skc_lookup_release_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let lookup = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let ctx = func.alloc_vreg();
    let ctx_non_null = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ctx_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: ctx_non_null,
        if_true: lookup,
        if_false: done,
    };

    func.block_mut(lookup)
        .instructions
        .push(MirInst::CallHelper {
            dst: sock,
            helper: BpfHelper::SkcLookupTcp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(tuple_slot),
                MirValue::Const(16),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(lookup).instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(lookup).terminator = MirInst::Branch {
        cond: sock_non_null,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallHelper {
            dst: release_ret,
            helper: BpfHelper::SkRelease as u32,
            args: vec![MirValue::VReg(sock)],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
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
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(sock_non_null, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected skc_lookup/sk_release socket lifetime to verify");
}
