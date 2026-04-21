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

fn packet_u8_ptr() -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::U8),
        address_space: AddressSpace::Packet,
    }
}

const BPF_SOCK_OPS_RTO_CB: i64 = 8;
const BPF_SOCK_OPS_PARSE_HDR_OPT_CB: i64 = 13;
const BPF_SOCK_OPS_HDR_OPT_LEN_CB: i64 = 14;
const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: i64 = 4;

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
#[cfg(target_arch = "x86_64")]
fn test_verify_mir_for_probe_context_allows_perf_event_specific_field_loads() {
    let (mut func, entry) = new_mir_function();
    let sample_period = func.alloc_vreg();
    let addr = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: sample_period,
            field: CtxField::PerfSamplePeriod,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: addr,
            field: CtxField::PerfAddr,
            slot: None,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(sample_period, MirType::U64);
    types.insert(addr, MirType::U64);

    let probe_ctx = ProbeContext::new(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
    );
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected perf_event-specific ctx fields to verify");
}

#[test]
fn test_verify_mir_for_probe_context_allows_perf_event_helper_field_loads() {
    let (mut func, entry) = new_mir_function();
    let mut types = HashMap::new();

    for field in [
        CtxField::PerfCounter,
        CtxField::PerfEnabled,
        CtxField::PerfRunning,
    ] {
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst,
                field,
                slot: None,
            });
        types.insert(dst, MirType::U64);
    }
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(
        EbpfProgramType::PerfEvent,
        "software:cpu-clock:period=100000",
    );
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected perf_event helper ctx fields to verify");
}

#[test]
fn test_verify_mir_for_probe_context_allows_arg_count_field_load() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst,
            field: CtxField::ArgCount,
            slot: None,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::U64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_sys_openat2");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected fentry ctx.arg_count field to verify");
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
fn test_verify_mir_for_probe_context_rejects_unguarded_sock_ops_packet_len_load() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst,
            field: CtxField::PacketLen,
            slot: None,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::U32);

    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected unguarded sock_ops packet_len load to be rejected");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "ctx.packet_len on sock_ops requires proving a packet-aware ctx.op callback before use",
        )
    }));
}

#[test]
fn test_verify_mir_for_probe_context_accepts_guarded_sock_ops_packet_len_load() {
    let (mut func, entry) = new_mir_function();
    let guarded = func.alloc_block();
    let done = func.alloc_block();
    let op = func.alloc_vreg();
    let matches = func.alloc_vreg();
    let len = func.alloc_vreg();

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
            dst: len,
            field: CtxField::PacketLen,
            slot: None,
        });
    func.block_mut(guarded).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(op, MirType::I32);
    types.insert(matches, MirType::Bool);
    types.insert(len, MirType::U32);

    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected guarded sock_ops packet_len load to verify");
}

#[test]
fn test_verify_mir_for_probe_context_rejects_sock_ops_data_load_for_non_packet_callback() {
    let (mut func, entry) = new_mir_function();
    let guarded = func.alloc_block();
    let done = func.alloc_block();
    let op = func.alloc_vreg();
    let matches = func.alloc_vreg();
    let data = func.alloc_vreg();

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
        rhs: MirValue::Const(BPF_SOCK_OPS_RTO_CB),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
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

    let mut types = HashMap::new();
    types.insert(op, MirType::I32);
    types.insert(matches, MirType::Bool);
    types.insert(data, packet_u8_ptr());

    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected non-packet sock_ops callback to reject ctx.data");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "ctx.data on sock_ops requires proving a packet-aware ctx.op callback before use",
        )
    }));
}

#[test]
fn test_verify_mir_for_probe_context_accepts_sock_ops_data_load_for_parse_hdr_opt() {
    let (mut func, entry) = new_mir_function();
    let guarded = func.alloc_block();
    let done = func.alloc_block();
    let op = func.alloc_vreg();
    let matches = func.alloc_vreg();
    let data = func.alloc_vreg();

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
        rhs: MirValue::Const(BPF_SOCK_OPS_PARSE_HDR_OPT_CB),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
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

    let mut types = HashMap::new();
    types.insert(op, MirType::I32);
    types.insert(matches, MirType::Bool);
    types.insert(data, packet_u8_ptr());

    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected parse_hdr_opt sock_ops callback to allow ctx.data");
}

#[test]
fn test_verify_mir_for_probe_context_accepts_cgroup_skb_direct_socket_fields() {
    let (mut func, entry) = new_mir_function();
    let family = func.alloc_vreg();
    let remote_port = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: family,
            field: CtxField::Family,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: remote_port,
            field: CtxField::RemotePort,
            slot: None,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(family, MirType::U32);
    types.insert(remote_port, MirType::U32);

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected cgroup_skb direct socket fields to verify");
}

#[test]
fn test_verify_mir_for_probe_context_accepts_cgroup_sock_state_field() {
    let (mut func, entry) = new_mir_function();
    let state = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: state,
            field: CtxField::SockState,
            slot: None,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(state, MirType::U32);

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected cgroup_sock ctx.state to verify");
}

#[test]
fn test_verify_mir_for_probe_context_accepts_cgroup_sock_direct_tuple_fields() {
    let (mut func, entry) = new_mir_function();
    let remote_port = func.alloc_vreg();
    let local_port = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: remote_port,
            field: CtxField::RemotePort,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: local_port,
            field: CtxField::LocalPort,
            slot: None,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(remote_port, MirType::U32);
    types.insert(local_port, MirType::U32);

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected cgroup_sock direct tuple fields to verify");
}

#[test]
fn test_verify_mir_for_probe_context_accepts_cgroup_sock_rx_queue_mapping_field() {
    let (mut func, entry) = new_mir_function();
    let rx_queue_mapping = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: rx_queue_mapping,
            field: CtxField::SockRxQueueMapping,
            slot: None,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(rx_queue_mapping, MirType::I32);

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected cgroup_sock ctx.rx_queue_mapping to verify");
}

#[test]
fn test_verify_mir_for_probe_context_accepts_sock_ops_tcp_flags_on_hdr_opt_len() {
    let (mut func, entry) = new_mir_function();
    let guarded = func.alloc_block();
    let done = func.alloc_block();
    let op = func.alloc_vreg();
    let matches = func.alloc_vreg();
    let flags = func.alloc_vreg();

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
        rhs: MirValue::Const(BPF_SOCK_OPS_HDR_OPT_LEN_CB),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
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

    let mut types = HashMap::new();
    types.insert(op, MirType::I32);
    types.insert(matches, MirType::Bool);
    types.insert(flags, MirType::U32);

    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected hdr_opt_len sock_ops callback to allow skb_tcp_flags");
}

#[test]
fn test_verify_mir_for_probe_context_task_is_non_null_task_pointer() {
    let (mut func, entry) = new_mir_function();
    let task = func.alloc_vreg();
    let regs = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: task,
            field: CtxField::Task,
            slot: None,
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
        .expect("expected ctx.task to satisfy task helpers without a null check");
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
fn test_verify_mir_for_probe_context_accepts_sock_ops_sk_txhash_store() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SockOpsSkTxhash,
            val: MirValue::Const(7),
            ty: MirType::U32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect("expected sock_ops sk_txhash store to be accepted");
}

#[test]
fn test_verify_mir_for_probe_context_accepts_cgroup_sock_mark_store_on_sock_create() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::CgroupSockMark,
            val: MirValue::Const(7),
            ty: MirType::U32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");
    verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect("expected cgroup_sock mark store to be accepted on sock_create");
}

#[test]
fn test_verify_mir_for_probe_context_accepts_skb_tstamp_store_on_tc() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbTstamp,
            val: MirValue::Const(123),
            ty: MirType::U64,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "tc:lo:ingress");
    verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect("expected skb tstamp store to be accepted on tc");
}

#[test]
fn test_verify_mir_for_probe_context_accepts_skb_tstamp_store_on_cgroup_skb_egress() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbTstamp,
            val: MirValue::Const(123),
            ty: MirType::U64,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:egress");
    verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect("expected skb tstamp store to be accepted on cgroup_skb egress");
}

#[test]
fn test_verify_mir_for_probe_context_accepts_skb_mark_store_on_tc() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbMark,
            val: MirValue::Const(123),
            ty: MirType::U32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "tc:lo:ingress");
    verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect("expected skb mark store to be accepted on tc");
}

#[test]
fn test_verify_mir_for_probe_context_accepts_skb_mark_store_on_cgroup_skb() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbMark,
            val: MirValue::Const(123),
            ty: MirType::U32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect("expected skb mark store to be accepted on cgroup_skb");
}

#[test]
fn test_verify_mir_for_probe_context_accepts_skb_cb_store_on_tc() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbCbWord(2),
            val: MirValue::Const(123),
            ty: MirType::U32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "tc:lo:ingress");
    verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect("expected skb cb store to be accepted on tc");
}

#[test]
fn test_verify_mir_for_probe_context_accepts_skb_cb_store_on_socket_filter() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbCbWord(0),
            val: MirValue::Const(123),
            ty: MirType::U32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect("expected skb cb store to be accepted on socket_filter");
}

#[test]
fn test_verify_mir_for_probe_context_accepts_skb_priority_store_on_sk_skb_parser() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbPriority,
            val: MirValue::Const(123),
            ty: MirType::U32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkbParser, "/sys/fs/bpf/demo_sockmap");
    verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect("expected skb priority store to be accepted on sk_skb_parser");
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
fn test_verify_mir_for_probe_context_rejects_skb_tstamp_store_on_non_skb_program() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbTstamp,
            val: MirValue::Const(123),
            ty: MirType::U64,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let err = verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect_err("expected skb tstamp store to be rejected outside skb-backed programs");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "ctx.tstamp is only available on socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
        )
    }));
}

#[test]
fn test_verify_mir_for_probe_context_rejects_skb_tstamp_store_on_socket_filter() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbTstamp,
            val: MirValue::Const(123),
            ty: MirType::U64,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let err = verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect_err("expected skb tstamp store to be rejected on socket_filter");
    assert!(err.iter().any(|e| {
        e.message
            .contains("ctx.tstamp is only available on tc and cgroup_skb programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_rejects_skb_tstamp_store_on_cgroup_skb_ingress() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbTstamp,
            val: MirValue::Const(123),
            ty: MirType::U64,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    let err = verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect_err("expected skb tstamp store to be rejected on cgroup_skb ingress");
    assert!(err.iter().any(|e| {
        e.message
            .contains("ctx.tstamp is only writable on tc and cgroup_skb:egress programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_rejects_skb_mark_store_on_socket_filter() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbMark,
            val: MirValue::Const(123),
            ty: MirType::U32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let err = verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect_err("expected skb mark store to be rejected on socket_filter");
    assert!(err.iter().any(|e| {
        e.message
            .contains("ctx.mark is only writable on tc and cgroup_skb programs")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_rejects_cgroup_sock_mark_store_on_post_bind() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::CgroupSockMark,
            val: MirValue::Const(7),
            ty: MirType::U32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");
    let err = verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect_err("expected cgroup_sock mark store to be rejected on post_bind4");
    assert!(err.iter().any(|e| {
        e.message
            .contains("ctx.mark is only writable on cgroup_sock sock_create/sock_release hooks")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_rejects_skb_tc_index_store_on_socket_filter() {
    let (mut func, entry) = new_mir_function();
    func.block_mut(entry)
        .instructions
        .push(MirInst::StoreCtxField {
            target: CtxStoreTarget::SkbTcIndex,
            val: MirValue::Const(123),
            ty: MirType::U32,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let err = verify_mir_for_probe_context(&func, &HashMap::new(), &probe_ctx)
        .expect_err("expected skb tc_index store to be rejected on socket_filter");
    assert!(err.iter().any(|e| {
        e.message
            .contains("ctx.tc_index is only writable on tc, sk_skb, and sk_skb_parser programs")
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
            "ctx.msg_src_ip4 is only available on cgroup_sock_addr sendmsg4/sendmsg6 hooks",
        )
    }));
}
