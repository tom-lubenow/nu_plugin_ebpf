use super::*;
use crate::compiler::EbpfProgramType;
use crate::compiler::MapRef;

const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: i64 = 4;
const BPF_SOCK_OPS_HDR_OPT_LEN_CB: i64 = 14;
const BPF_SOCK_OPS_WRITE_HDR_OPT_CB: i64 = 15;

fn assert_bpf_tcp_sock_ptr(ty: Option<&MirType>) {
    let Some(MirType::Ptr {
        pointee,
        address_space,
    }) = ty
    else {
        panic!("expected bpf_tcp_sock kernel pointer, got {ty:?}");
    };
    assert_eq!(*address_space, AddressSpace::Kernel);

    let MirType::Struct {
        name: Some(name),
        fields,
        ..
    } = pointee.as_ref()
    else {
        panic!("expected bpf_tcp_sock struct pointee, got {pointee:?}");
    };
    assert_eq!(name, "bpf_tcp_sock");

    let snd_cwnd = fields
        .iter()
        .find(|field| field.name == "snd_cwnd")
        .expect("expected bpf_tcp_sock.snd_cwnd field");
    assert_eq!(snd_cwnd.ty, MirType::U32);
    assert_eq!(snd_cwnd.offset, 0);

    let bytes_acked = fields
        .iter()
        .find(|field| field.name == "bytes_acked")
        .expect("expected bpf_tcp_sock.bytes_acked field");
    assert_eq!(bytes_acked.ty, MirType::U64);
    assert_eq!(bytes_acked.offset, 88);
}

#[test]
fn test_subfn_polymorphic_id() {
    let mut subfn = MirFunction::with_name("id");
    subfn.param_count = 1;
    let entry = subfn.alloc_block();
    subfn.entry = entry;
    let arg = VReg(0);
    subfn.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(arg)),
    };

    let mut main_func = MirFunction::new();
    let main_entry = main_func.alloc_block();
    main_func.entry = main_entry;

    let int_arg = main_func.alloc_vreg();
    let comm_arg = main_func.alloc_vreg();
    let out_int = main_func.alloc_vreg();
    let out_comm = main_func.alloc_vreg();

    let block = main_func.block_mut(main_entry);
    block.instructions.push(MirInst::Copy {
        dst: int_arg,
        src: MirValue::Const(42),
    });
    block.instructions.push(MirInst::LoadCtxField {
        dst: comm_arg,
        field: CtxField::Comm,
        slot: None,
    });
    block.instructions.push(MirInst::CallSubfn {
        dst: out_int,
        subfn: SubfunctionId(0),
        args: vec![int_arg],
    });
    block.instructions.push(MirInst::CallSubfn {
        dst: out_comm,
        subfn: SubfunctionId(0),
        args: vec![comm_arg],
    });
    block.terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let subfn_schemes = infer_subfunction_schemes(&[subfn], None).unwrap();
    let mut ti =
        TypeInference::new_with_env(None, Some(&subfn_schemes), Some(HMType::I64), None, None);
    let types = ti.infer(&main_func).unwrap();

    assert_eq!(types.get(&out_int), Some(&MirType::I64));
    match types.get(&out_comm) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Stack);
        }
        other => panic!("Expected stack pointer type, got {:?}", other),
    }
}

#[test]
fn test_subfn_scheme_inference_uses_parameter_hints() {
    let mut subfn = MirFunction::with_name("read_param");
    subfn.param_count = 1;
    let entry = subfn.alloc_block();
    subfn.entry = entry;
    let _param = subfn.alloc_vreg();
    let out = subfn.alloc_vreg();
    let scratch = subfn.alloc_stack_slot(8, 8, StackSlotKind::Local);
    subfn
        .block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: out,
            helper: BpfHelper::ProbeReadKernel as u32,
            args: vec![
                MirValue::StackSlot(scratch),
                MirValue::Const(8),
                MirValue::VReg(VReg(0)),
            ],
        });
    subfn.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let hints = vec![HashMap::from([(
        VReg(0),
        MirType::Ptr {
            pointee: Box::new(MirType::U64),
            address_space: AddressSpace::Kernel,
        },
    )])];
    let stack_hints = vec![HashMap::new()];
    let subfn_schemes =
        infer_subfunction_schemes_with_hints(&[subfn], None, Some(&hints), Some(&stack_hints))
            .expect("expected subfunction scheme inference to accept parameter pointer hints");

    assert!(subfn_schemes.contains_key(&SubfunctionId(0)));
}

#[test]
fn test_type_error_helper_arg_limit() {
    let mut func = make_test_function();
    let mut args = Vec::new();
    for n in 0..6 {
        let v = func.alloc_vreg();
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::Copy {
            dst: v,
            src: MirValue::Const(n),
        });
        args.push(MirValue::VReg(v));
    }
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: 14,
        args,
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected helper arg-limit type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("expects 0..=0 arguments"))
    );
}

#[test]
fn test_type_error_helper_pointer_argument_required() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: 16, // bpf_get_current_comm(buf, size)
        args: vec![MirValue::Const(0), MirValue::Const(16)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected pointer-argument helper type error");
    assert!(errs.iter().any(|e| e.message.contains("expects pointer")));
}

#[test]
fn test_infer_helper_ctx_argument_from_context_pointer_load() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetSocketCookie as u32,
        args: vec![MirValue::VReg(ctx)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected helper ctx argument from LoadCtxField::Context to infer");

    match types.get(&ctx) {
        Some(MirType::Ptr {
            pointee,
            address_space,
        }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
            assert_eq!(pointee.as_ref(), &MirType::U8);
        }
        other => panic!("expected kernel context pointer type, got {:?}", other),
    }
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_infer_helper_ctx_argument_from_context_pointer_copy() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let ctx_copy = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::Copy {
        dst: ctx_copy,
        src: MirValue::VReg(ctx),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetSocketCookie as u32,
        args: vec![MirValue::VReg(ctx_copy)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected copied raw ctx pointer to satisfy helper context argument");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_type_error_get_socket_cookie_helper_rejects_sk_lookup_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetSocketCookie as u32,
        args: vec![MirValue::VReg(ctx)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_get_socket_cookie to be rejected on sk_lookup");
    assert!(errs.iter().any(|e| e.message.contains(
        "helper 'bpf_get_socket_cookie' is only valid in fentry, fexit, tp_btf, socket_filter, tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, sock_ops, sk_skb, and sk_skb_parser programs"
    )));
}

#[test]
fn test_type_error_get_socket_cookie_helper_rejects_fentry_context_pointer() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetSocketCookie as u32,
        args: vec![MirValue::VReg(ctx)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "tcp_connect");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected fentry raw ctx pointer to be rejected for bpf_get_socket_cookie");
    assert!(errs.iter().any(|e| e.message.contains(
        "helper 'bpf_get_socket_cookie' arg0 expects socket pointer in fentry programs"
    )));
}

#[test]
fn test_infer_get_socket_cookie_helper_accepts_fentry_const_zero() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetSocketCookie as u32,
        args: vec![MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "tcp_connect");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected null literal to satisfy tracing get_socket_cookie");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_type_error_get_socket_cookie_helper_rejects_socket_filter_const_zero() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetSocketCookie as u32,
        args: vec![MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected socket_filter get_socket_cookie(0) to be rejected");
    assert!(errs.iter().any(|e| e.message.contains(
        "helper 'bpf_get_socket_cookie' arg0 expects raw ctx pointer in socket_filter programs"
    )));
}

#[test]
fn test_type_error_get_socket_cookie_helper_rejects_offset_context_pointer() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let ctx_offset = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::BinOp {
        dst: ctx_offset,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(8),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetSocketCookie as u32,
        args: vec![MirValue::VReg(ctx_offset)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected offset raw ctx pointer to be rejected for bpf_get_socket_cookie");
    assert!(errs.iter().any(|e| e.message.contains(
        "helper 'bpf_get_socket_cookie' arg0 expects raw ctx pointer in socket_filter programs"
    )));
}

#[test]
fn test_type_error_get_socket_cookie_helper_rejects_cgroup_sock_addr_socket_field() {
    let mut func = make_test_function();
    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: sk,
        field: CtxField::Socket,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetSocketCookie as u32,
        args: vec![MirValue::VReg(sk)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected cgroup_sock_addr ctx.sk to be rejected for bpf_get_socket_cookie");
    assert!(errs.iter().any(|e| e.message.contains(
        "helper 'bpf_get_socket_cookie' arg0 expects raw ctx pointer in cgroup_sock_addr programs"
    )));
}

#[test]
fn test_infer_get_socket_cookie_helper_from_cgroup_sock_socket_alias() {
    let mut func = make_test_function();
    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: sk,
        field: CtxField::Socket,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetSocketCookie as u32,
        args: vec![MirValue::VReg(sk)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected cgroup_sock ctx.sk alias to satisfy bpf_get_socket_cookie");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_infer_get_socket_uid_helper_in_cgroup_skb_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetSocketUid as u32,
        args: vec![MirValue::VReg(ctx)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_get_socket_uid to infer on cgroup_skb");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_infer_get_socket_uid_helper_in_tc_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetSocketUid as u32,
        args: vec![MirValue::VReg(ctx)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_get_socket_uid to infer on tc");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_infer_get_netns_cookie_helper_in_cgroup_sockopt_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetNetnsCookie as u32,
        args: vec![MirValue::VReg(ctx)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_get_netns_cookie to infer on cgroup_sockopt");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_infer_get_netns_cookie_helper_in_sk_msg_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetNetnsCookie as u32,
        args: vec![MirValue::VReg(ctx)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_get_netns_cookie to infer on sk_msg");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_type_error_lirc_helpers_reject_non_lirc_programs() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::RcRepeat as u32,
        args: vec![MirValue::VReg(ctx)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected lirc helper to be rejected on non-lirc programs");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_rc_repeat' is only valid in lirc_mode2 programs")
    }));
}

#[test]
fn test_infer_lirc_helper_ctx_argument_in_lirc_mode2_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::RcRepeat as u32,
        args: vec![MirValue::VReg(ctx)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::LircMode2, "/dev/lirc0");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected lirc helper to infer in lirc_mode2 program");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_type_error_redirect_helper_rejects_non_packet_programs() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::Redirect as u32,
        args: vec![MirValue::Const(1), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_redirect to be rejected on non-xdp/tc programs");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect' is only valid in xdp and tc programs")
    }));
}

#[test]
fn test_type_error_redirect_helper_requires_zero_flags_in_xdp() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::Redirect as u32,
        args: vec![MirValue::Const(1), MirValue::Const(1)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected xdp bpf_redirect flags to require zero");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect' requires arg1 = 0 in xdp programs")
    }));
}

#[test]
fn test_infer_redirect_helper_in_tc_program() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::Redirect as u32,
        args: vec![MirValue::Const(1), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected tc bpf_redirect helper to infer");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_type_error_xdp_adjust_meta_helper_rejects_non_xdp_programs() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::XdpAdjustMeta as u32,
        args: vec![MirValue::VReg(ctx), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_xdp_adjust_meta to be rejected on non-xdp programs");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_xdp_adjust_meta' is only valid in xdp programs")
    }));
}

#[test]
fn test_infer_xdp_adjust_meta_helper_in_xdp_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::XdpAdjustMeta as u32,
        args: vec![MirValue::VReg(ctx), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_xdp_adjust_meta helper to infer on xdp programs");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_type_error_skb_packet_mutation_helpers_reject_invalid_programs() {
    for (helper, args) in [
        (
            BpfHelper::SkbChangeTail,
            vec![MirValue::Const(64), MirValue::Const(0)],
        ),
        (
            BpfHelper::CloneRedirect,
            vec![MirValue::Const(1), MirValue::Const(0)],
        ),
        (BpfHelper::SkbPullData, vec![MirValue::Const(64)]),
        (
            BpfHelper::SkbChangeHead,
            vec![MirValue::Const(14), MirValue::Const(0)],
        ),
        (
            BpfHelper::SkbVlanPush,
            vec![MirValue::Const(0x8100), MirValue::Const(1)],
        ),
        (BpfHelper::SkbVlanPop, vec![]),
        (BpfHelper::SetHash, vec![MirValue::Const(0)]),
        (BpfHelper::CsumLevel, vec![MirValue::Const(0)]),
        (
            BpfHelper::SkbAdjustRoom,
            vec![MirValue::Const(14), MirValue::Const(0), MirValue::Const(0)],
        ),
    ] {
        let mut func = make_test_function();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: std::iter::once(MirValue::VReg(ctx))
                .chain(args.into_iter())
                .collect(),
        });
        block.terminator = MirInst::Return { val: None };

        let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
        let mut ti = TypeInference::new(Some(probe_ctx));
        let errs = ti
            .infer(&func)
            .expect_err("expected skb packet-mutation helper to be rejected");
        assert!(errs.iter().any(|e| {
            e.message.contains(&format!(
                "helper '{}' is only valid in tc, sk_skb, and sk_skb_parser programs",
                helper.name()
            ))
        }));
    }
}

#[test]
fn test_type_error_skb_change_head_helper_requires_zero_flags() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkbChangeHead as u32,
        args: vec![MirValue::VReg(ctx), MirValue::Const(14), MirValue::Const(1)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_skb_change_head flags to require zero");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_skb_change_head' requires arg2 = 0")
    }));
}

#[test]
fn test_infer_skb_packet_mutation_helpers_in_supported_programs() {
    for (probe_ctx, helper, extra_args) in [
        (
            ProbeContext::new(EbpfProgramType::Tc, "lo:ingress"),
            BpfHelper::SkbPullData,
            vec![MirValue::Const(64)],
        ),
        (
            ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap"),
            BpfHelper::SkbChangeHead,
            vec![MirValue::Const(14), MirValue::Const(0)],
        ),
        (
            ProbeContext::new(EbpfProgramType::Tc, "lo:egress"),
            BpfHelper::CloneRedirect,
            vec![MirValue::Const(1), MirValue::Const(0)],
        ),
        (
            ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap"),
            BpfHelper::SkbVlanPush,
            vec![MirValue::Const(0x8100), MirValue::Const(1)],
        ),
        (
            ProbeContext::new(EbpfProgramType::SkSkbParser, "/sys/fs/bpf/demo_sockmap"),
            BpfHelper::SkbVlanPop,
            vec![],
        ),
        (
            ProbeContext::new(EbpfProgramType::Tc, "lo:ingress"),
            BpfHelper::SetHash,
            vec![MirValue::Const(0)],
        ),
        (
            ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap"),
            BpfHelper::CsumLevel,
            vec![MirValue::Const(0)],
        ),
        (
            ProbeContext::new(EbpfProgramType::SkSkbParser, "/sys/fs/bpf/demo_sockmap"),
            BpfHelper::SkbAdjustRoom,
            vec![MirValue::Const(14), MirValue::Const(0), MirValue::Const(0)],
        ),
    ] {
        let mut func = make_test_function();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: std::iter::once(MirValue::VReg(ctx))
                .chain(extra_args.into_iter())
                .collect(),
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(Some(probe_ctx));
        let types = ti
            .infer(&func)
            .expect("expected skb packet-mutation helper to infer");
        assert_eq!(types.get(&dst), Some(&MirType::I64));
    }
}

#[test]
fn test_type_error_skb_set_tstamp_helper_rejects_non_tc_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkbSetTstamp as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::Const(123),
            MirValue::Const(1),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_skb_set_tstamp to be rejected outside tc");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_skb_set_tstamp' is only valid in tc programs")
    }));
}

#[test]
fn test_type_error_skb_set_tstamp_helper_requires_zero_tstamp_for_unspec_type() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkbSetTstamp as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::Const(123),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected unspec tstamp type to require zero timestamp");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_skb_set_tstamp' requires arg1 = 0 when arg2 is 0")
    }));
}

#[test]
fn test_infer_skb_set_tstamp_helper_in_tc_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkbSetTstamp as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::Const(123),
            MirValue::Const(1),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected tc bpf_skb_set_tstamp helper to infer");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_type_error_msg_helpers_reject_non_sk_msg_programs() {
    for (helper, args) in [
        (BpfHelper::MsgApplyBytes, vec![MirValue::Const(8)]),
        (BpfHelper::MsgCorkBytes, vec![MirValue::Const(8)]),
        (
            BpfHelper::MsgPullData,
            vec![MirValue::Const(0), MirValue::Const(8), MirValue::Const(0)],
        ),
        (
            BpfHelper::MsgPushData,
            vec![MirValue::Const(0), MirValue::Const(8), MirValue::Const(0)],
        ),
        (
            BpfHelper::MsgPopData,
            vec![MirValue::Const(0), MirValue::Const(8), MirValue::Const(0)],
        ),
    ] {
        let mut func = make_test_function();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: std::iter::once(MirValue::VReg(ctx))
                .chain(args.into_iter())
                .collect(),
        });
        block.terminator = MirInst::Return { val: None };

        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
        let mut ti = TypeInference::new(Some(probe_ctx));
        let errs = ti
            .infer(&func)
            .expect_err("expected sk_msg helper to be rejected outside sk_msg");
        assert!(errs.iter().any(|e| {
            e.message.contains(&format!(
                "helper '{}' is only valid in sk_msg programs",
                helper.name()
            ))
        }));
    }
}

#[test]
fn test_type_error_sysctl_helpers_reject_non_sysctl_programs() {
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
        let mut func = make_test_function();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: std::iter::once(MirValue::VReg(ctx))
                .chain(extra_args.into_iter().map(|arg| match arg {
                    MirValue::StackSlot(StackSlotId(0)) => MirValue::StackSlot(buf_slot),
                    other => other,
                }))
                .collect(),
        });
        block.terminator = MirInst::Return { val: None };

        let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
        let mut ti = TypeInference::new(Some(probe_ctx));
        let errs = ti
            .infer(&func)
            .expect_err("expected sysctl helper to be rejected outside cgroup_sysctl");
        assert!(errs.iter().any(|e| {
            e.message.contains(&format!(
                "helper '{}' is only valid in cgroup_sysctl programs",
                helper.name()
            ))
        }));
    }
}

#[test]
fn test_type_error_sockopt_helpers_reject_invalid_program_or_attach() {
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
        let mut func = make_test_function();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let optval_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
        block.instructions.push(MirInst::CallHelper {
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
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(Some(probe_ctx));
        let errs = ti
            .infer(&func)
            .expect_err("expected sockopt helper to be rejected");
        assert!(errs.iter().any(|e| e.message.contains(expected)));
    }
}

#[test]
fn test_type_error_bind_helper_rejects_invalid_program_or_attach() {
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
        let mut func = make_test_function();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let addr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::Bind as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(addr_slot),
                MirValue::Const(16),
            ],
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(Some(probe_ctx));
        let errs = ti
            .infer(&func)
            .expect_err("expected bind helper to be rejected");
        assert!(errs.iter().any(|e| e.message.contains(expected)));
    }
}

#[test]
fn test_type_error_sock_ops_cb_flags_set_rejects_invalid_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SockOpsCbFlagsSet as u32,
        args: vec![MirValue::VReg(ctx), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(Some(ProbeContext::new(
        EbpfProgramType::Kprobe,
        "ksys_read",
    )));
    let errs = ti
        .infer(&func)
        .expect_err("expected sock_ops_cb_flags_set helper to be rejected");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_sock_ops_cb_flags_set' is only valid in sock_ops programs")
    }));
}

#[test]
fn test_type_error_sock_ops_hdr_opt_helpers_reject_invalid_program() {
    for helper in [
        BpfHelper::LoadHdrOpt,
        BpfHelper::StoreHdrOpt,
        BpfHelper::ReserveHdrOpt,
    ] {
        let mut func = make_test_function();
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
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args,
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(Some(ProbeContext::new(
            EbpfProgramType::Kprobe,
            "ksys_read",
        )));
        let errs = ti
            .infer(&func)
            .expect_err("expected sock_ops hdr-opt helper to be rejected");
        assert!(errs.iter().any(|e| e.message.contains(&format!(
            "helper '{}' is only valid in sock_ops programs",
            helper.name()
        ))));
    }
}

#[test]
fn test_infer_sockopt_helpers_in_supported_socket_contexts() {
    for (helper, probe_ctx) in [
        (
            BpfHelper::SetSockOpt,
            ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup"),
        ),
        (
            BpfHelper::GetSockOpt,
            ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4"),
        ),
        (
            BpfHelper::SetSockOpt,
            ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4"),
        ),
        (
            BpfHelper::GetSockOpt,
            ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get"),
        ),
        (
            BpfHelper::SetSockOpt,
            ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:set"),
        ),
    ] {
        let mut func = make_test_function();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let optval_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
        block.instructions.push(MirInst::CallHelper {
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
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(Some(probe_ctx));
        let types = ti
            .infer(&func)
            .expect("expected sockopt helper to infer in supported context");
        assert_eq!(types.get(&dst), Some(&MirType::I64));
    }
}

#[test]
fn test_infer_sock_ops_hdr_opt_helpers_in_sock_ops_context_when_guarded() {
    for (helper, callback_op) in [
        (BpfHelper::LoadHdrOpt, BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB),
        (BpfHelper::StoreHdrOpt, BPF_SOCK_OPS_WRITE_HDR_OPT_CB),
        (BpfHelper::ReserveHdrOpt, BPF_SOCK_OPS_HDR_OPT_LEN_CB),
    ] {
        let mut func = make_test_function();
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
                rhs: MirValue::Const(callback_op),
            });
        func.block_mut(BlockId(0)).terminator = MirInst::Branch {
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

        let mut ti = TypeInference::new(Some(ProbeContext::new(
            EbpfProgramType::SockOps,
            "/sys/fs/cgroup",
        )));
        let types = ti
            .infer(&func)
            .expect("expected guarded sock_ops hdr-opt helper in sock_ops context");
        assert_eq!(types.get(&dst), Some(&MirType::I64));
    }
}

#[test]
fn test_infer_sock_ops_cb_flags_set_in_sock_ops_context_when_guarded() {
    let mut func = make_test_function();
    let guarded = func.alloc_block();
    let done = func.alloc_block();
    let op = func.alloc_vreg();
    let matches = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
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

    let mut ti = TypeInference::new(Some(ProbeContext::new(
        EbpfProgramType::SockOps,
        "/sys/fs/cgroup",
    )));
    let types = ti
        .infer(&func)
        .expect("expected guarded sock_ops_cb_flags_set helper in sock_ops context");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_infer_sock_ops_callback_sensitive_helpers_without_static_callback_proof() {
    for helper in [
        BpfHelper::SockOpsCbFlagsSet,
        BpfHelper::LoadHdrOpt,
        BpfHelper::StoreHdrOpt,
        BpfHelper::ReserveHdrOpt,
    ] {
        let mut func = make_test_function();
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

        func.block_mut(BlockId(0))
            .instructions
            .push(MirInst::LoadCtxField {
                dst: ctx,
                field: CtxField::Context,
                slot: None,
            });
        func.block_mut(BlockId(0))
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args,
            });
        func.block_mut(BlockId(0)).terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(Some(ProbeContext::new(
            EbpfProgramType::SockOps,
            "/sys/fs/cgroup",
        )));
        let types = ti
            .infer(&func)
            .expect("expected sock_ops callback-sensitive helper to infer");
        assert_eq!(types.get(&dst), Some(&MirType::I64));
    }
}

#[test]
fn test_type_error_socket_map_helpers_reject_invalid_programs() {
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
        let mut func = make_test_function();
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

        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args,
        });
        block.terminator = MirInst::Return { val: None };

        let probe_ctx = ProbeContext::new(program_type, spec);
        let mut ti = TypeInference::new(Some(probe_ctx));
        let errs = ti
            .infer(&func)
            .expect_err("expected socket-map helper to be rejected outside its program family");
        assert!(errs.iter().any(|e| e.message.contains(expected)));
    }
}

#[test]
fn test_infer_socket_map_helpers_in_supported_programs() {
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
        let mut func = make_test_function();
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

        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args,
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(Some(probe_ctx));
        let types = ti
            .infer(&func)
            .expect("expected socket-map helper to infer in supported program");
        assert_eq!(types.get(&dst), Some(&MirType::I64));
    }
}

#[test]
fn test_type_error_redirect_map_helper_rejects_invalid_programs() {
    let mut func = make_test_function();
    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_redirect_map".to_string(),
            kind: MapKind::DevMap,
        },
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::RedirectMap as u32,
        args: vec![MirValue::VReg(map), MirValue::Const(0), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected redirect_map helper to be rejected outside xdp");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect_map' is only valid in xdp programs")
    }));
}

#[test]
fn test_infer_redirect_map_helper_in_xdp_programs() {
    let mut func = make_test_function();
    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_redirect_map".to_string(),
            kind: MapKind::DevMapHash,
        },
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::RedirectMap as u32,
        args: vec![MirValue::VReg(map), MirValue::Const(7), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected redirect_map helper to infer in xdp");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
    assert!(matches!(types.get(&map), Some(MirType::MapRef { .. })));
}

#[test]
fn test_type_error_perf_event_output_helper_rejects_lsm_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_perf_events".to_string(),
            kind: MapKind::PerfEventArray,
        },
    });
    block.instructions.push(MirInst::CallHelper {
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
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Lsm, "file_open");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_perf_event_output to be rejected on lsm");
    assert!(errs.iter().any(|e| e.message.contains(
        "helper 'bpf_perf_event_output' is only valid in cgroup_device, cgroup_skb, cgroup_sock, cgroup_sockopt, cgroup_sock_addr, cgroup_sysctl, kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, tp_btf, socket_filter, tc, sk_lookup, sk_msg, sk_skb, sk_skb_parser, sock_ops, and xdp programs"
    )));
}

#[test]
fn test_type_error_get_stackid_helper_rejects_xdp_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_stacks".to_string(),
            kind: MapKind::StackTrace,
        },
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetStackId as u32,
        args: vec![MirValue::VReg(ctx), MirValue::VReg(map), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_get_stackid to be rejected on xdp");
    assert!(errs.iter().any(|e| e.message.contains(
        "helper 'bpf_get_stackid' is only valid in kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, and tp_btf programs"
    )));
}

#[test]
fn test_infer_get_stack_helper_allows_zero_size_buffer_in_kprobe() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetStack as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(buf_slot),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_get_stack zero-size buffer to infer");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_type_error_get_stack_helper_rejects_small_stack_buffer() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetStack as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(buf_slot),
            MirValue::Const(64),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_get_stack stack buffer bounds error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("helper get_stack buf requires 64 bytes")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_get_stack_helper_rejects_negative_size() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetStack as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(buf_slot),
            MirValue::Const(-1),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_get_stack negative-size error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("helper 67 arg2 must be >= 0")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_get_stack_helper_rejects_xdp_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetStack as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(buf_slot),
            MirValue::Const(32),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_get_stack to be rejected on xdp");
    assert!(errs.iter().any(|e| e.message.contains(
        "helper 'bpf_get_stack' is only valid in kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, and tp_btf programs"
    )));
}

#[test]
fn test_type_error_probe_read_helper_rejects_xdp_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let out_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::ProbeRead as u32,
        args: vec![
            MirValue::StackSlot(out_slot),
            MirValue::Const(8),
            MirValue::VReg(ctx),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_probe_read to be rejected on xdp");
    assert!(errs.iter().any(|e| e.message.contains(
        "helper 'bpf_probe_read' is only valid in kprobe, kretprobe, uprobe, uretprobe, lsm, perf_event, raw_tracepoint, tracepoint, fentry, fexit, and tp_btf programs"
    )));
}

#[test]
fn test_type_error_store_hdr_opt_helper_requires_zero_flags() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::StoreHdrOpt as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(buf_slot),
            MirValue::Const(16),
            MirValue::Const(1),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(Some(ProbeContext::new(
        EbpfProgramType::SockOps,
        "/sys/fs/cgroup",
    )));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_store_hdr_opt flags to require zero");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_store_hdr_opt' requires arg3 = 0")
    }));
}

#[test]
fn test_infer_bind_helper_in_supported_socket_context() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let addr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::Bind as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(addr_slot),
            MirValue::Const(16),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(Some(ProbeContext::new(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect4",
    )));
    let types = ti
        .infer(&func)
        .expect("expected bind helper in cgroup_sock_addr connect context");
    assert_eq!(types[&dst], MirType::I64);
}

#[test]
fn test_infer_msg_helpers_in_sk_msg_program() {
    for (helper, args) in [
        (BpfHelper::MsgApplyBytes, vec![MirValue::Const(8)]),
        (BpfHelper::MsgCorkBytes, vec![MirValue::Const(8)]),
        (
            BpfHelper::MsgPullData,
            vec![MirValue::Const(0), MirValue::Const(8), MirValue::Const(0)],
        ),
        (
            BpfHelper::MsgPushData,
            vec![MirValue::Const(0), MirValue::Const(8), MirValue::Const(0)],
        ),
        (
            BpfHelper::MsgPopData,
            vec![MirValue::Const(0), MirValue::Const(8), MirValue::Const(0)],
        ),
    ] {
        let mut func = make_test_function();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: std::iter::once(MirValue::VReg(ctx))
                .chain(args.into_iter())
                .collect(),
        });
        block.terminator = MirInst::Return { val: None };

        let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
        let mut ti = TypeInference::new(Some(probe_ctx));
        let types = ti
            .infer(&func)
            .expect("expected sk_msg helper to infer in sk_msg program");
        assert_eq!(types.get(&dst), Some(&MirType::I64));
    }
}

#[test]
fn test_type_error_sk_cgroup_helpers_reject_sk_msg_program() {
    for (helper, args) in [
        (BpfHelper::SkCgroupId, vec![]),
        (BpfHelper::SkAncestorCgroupId, vec![MirValue::Const(0)]),
    ] {
        let mut func = make_test_function();
        let sk = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: sk,
            field: CtxField::Socket,
            slot: None,
        });
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: std::iter::once(MirValue::VReg(sk))
                .chain(args.into_iter())
                .collect(),
        });
        block.terminator = MirInst::Return { val: None };

        let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
        let mut ti = TypeInference::new(Some(probe_ctx));
        let errs = ti
            .infer(&func)
            .expect_err("expected sk_cgroup helper to be rejected on sk_msg");
        assert!(errs.iter().any(|e| e.message.contains("helper 'bpf_sk_")
            && e.message.contains("is only valid in cgroup_skb programs")));
    }
}

#[test]
fn test_infer_sk_cgroup_helpers_in_cgroup_skb_program() {
    for (helper, args) in [
        (BpfHelper::SkCgroupId, vec![]),
        (BpfHelper::SkAncestorCgroupId, vec![MirValue::Const(0)]),
    ] {
        let mut func = make_test_function();
        let call = func.alloc_block();
        let done = func.alloc_block();
        let ctx = func.alloc_vreg();
        let sock = func.alloc_vreg();
        let sock_non_null = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let cleanup_ret = func.alloc_vreg();
        let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

        let entry = func.block_mut(BlockId(0));
        entry.instructions.push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
        entry.instructions.push(MirInst::CallHelper {
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
        entry.instructions.push(MirInst::BinOp {
            dst: sock_non_null,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(sock),
            rhs: MirValue::Const(0),
        });
        entry.terminator = MirInst::Branch {
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

        let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
        let mut ti = TypeInference::new(Some(probe_ctx));
        let types = ti
            .infer(&func)
            .expect("expected sk_cgroup helper to infer on cgroup_skb");
        assert_eq!(types.get(&dst), Some(&MirType::I64));
    }
}

#[test]
fn test_infer_get_current_ancestor_cgroup_id_helper_returns_i64() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetCurrentAncestorCgroupId as u32,
        args: vec![MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected bpf_get_current_ancestor_cgroup_id to infer");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_infer_no_arg_scalar_helpers_return_i64() {
    for (helper, name) in [
        (BpfHelper::GetNumaNodeId, "bpf_get_numa_node_id"),
        (BpfHelper::KtimeGetCoarseNs, "bpf_ktime_get_coarse_ns"),
        (BpfHelper::KtimeGetTaiNs, "bpf_ktime_get_tai_ns"),
        (BpfHelper::Jiffies64, "bpf_jiffies64"),
    ] {
        let mut func = make_test_function();
        let dst = func.alloc_vreg();
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: vec![],
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti
            .infer(&func)
            .unwrap_or_else(|_| panic!("expected {name} to infer"));
        assert_eq!(types.get(&dst), Some(&MirType::I64));
    }
}

#[test]
fn test_infer_tc_egress_skb_metadata_helpers() {
    for (helper, extra_args) in [
        (BpfHelper::GetCgroupClassid, vec![]),
        (BpfHelper::GetRouteRealm, vec![]),
        (BpfHelper::SkbCgroupId, vec![]),
        (BpfHelper::SkbAncestorCgroupId, vec![MirValue::Const(0)]),
    ] {
        let mut func = make_test_function();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: std::iter::once(MirValue::VReg(ctx))
                .chain(extra_args.into_iter())
                .collect(),
        });
        block.terminator = MirInst::Return { val: None };

        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:egress");
        let mut ti = TypeInference::new(Some(probe_ctx));
        let types = ti
            .infer(&func)
            .expect("expected tc-egress skb metadata helper to infer");
        assert_eq!(types.get(&dst), Some(&MirType::I64));
    }
}

#[test]
fn test_type_error_tc_egress_skb_metadata_helpers_reject_tc_ingress() {
    for (helper, extra_args) in [
        (BpfHelper::GetCgroupClassid, vec![]),
        (BpfHelper::GetRouteRealm, vec![]),
        (BpfHelper::SkbCgroupId, vec![]),
        (BpfHelper::SkbAncestorCgroupId, vec![MirValue::Const(0)]),
    ] {
        let mut func = make_test_function();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: std::iter::once(MirValue::VReg(ctx))
                .chain(extra_args.into_iter())
                .collect(),
        });
        block.terminator = MirInst::Return { val: None };

        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
        let mut ti = TypeInference::new(Some(probe_ctx));
        let errs = ti
            .infer(&func)
            .expect_err("expected tc-egress skb metadata helper to reject tc ingress");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("is only valid in tc egress programs"))
        );
    }
}

#[test]
fn test_type_error_tc_egress_skb_metadata_helpers_reject_non_tc_program() {
    for (helper, extra_args) in [
        (BpfHelper::GetCgroupClassid, vec![]),
        (BpfHelper::GetRouteRealm, vec![]),
        (BpfHelper::SkbCgroupId, vec![]),
        (BpfHelper::SkbAncestorCgroupId, vec![MirValue::Const(0)]),
    ] {
        let mut func = make_test_function();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: std::iter::once(MirValue::VReg(ctx))
                .chain(extra_args.into_iter())
                .collect(),
        });
        block.terminator = MirInst::Return { val: None };

        let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
        let mut ti = TypeInference::new(Some(probe_ctx));
        let errs = ti
            .infer(&func)
            .expect_err("expected tc-egress skb metadata helper to reject non-tc program");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("is only valid in tc programs"))
        );
    }
}

#[test]
fn test_type_error_redirect_peer_helper_rejects_tc_egress() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::RedirectPeer as u32,
        args: vec![MirValue::Const(1), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:egress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_redirect_peer to be rejected on tc egress");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect_peer' is only valid in tc ingress programs")
    }));
}

#[test]
fn test_type_error_redirect_peer_helper_rejects_non_tc_program() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::RedirectPeer as u32,
        args: vec![MirValue::Const(1), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_redirect_peer to be rejected outside tc");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect_peer' is only valid in tc programs")
    }));
}

#[test]
fn test_type_error_sk_lookup_tcp_helper_rejects_invalid_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
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
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_sk_lookup_tcp to be rejected on kprobe");
    assert!(errs.iter().any(|e| {
        e.message.contains(
            "helper 'bpf_sk_lookup_tcp' is only valid in xdp, tc, cgroup_skb, cgroup_sock_addr, and sk_skb programs",
        )
    }));
}

#[test]
fn test_infer_sk_lookup_tcp_helper_in_xdp_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
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
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_sk_lookup_tcp to infer on xdp");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer type, got {:?}", other),
    }
}

#[test]
fn test_type_error_sk_assign_helper_rejects_tc_egress() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkAssign as u32,
        args: vec![MirValue::VReg(ctx), MirValue::Const(0), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:egress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_sk_assign to be rejected on tc egress");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_sk_assign' is only valid in tc ingress programs")
    }));
}

#[test]
fn test_type_error_sk_assign_helper_requires_zero_flags_in_tc() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkAssign as u32,
        args: vec![MirValue::VReg(ctx), MirValue::Const(0), MirValue::Const(1)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_sk_assign flags to require zero on tc");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_sk_assign' requires arg2 = 0 in tc programs")
    }));
}

#[test]
fn test_infer_sk_assign_helper_in_sk_lookup_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkAssign as u32,
        args: vec![MirValue::VReg(ctx), MirValue::Const(0), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_sk_assign to infer on sk_lookup");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_type_error_get_listener_sock_helper_rejects_sk_lookup_program() {
    let mut func = make_test_function();
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: sock,
        field: CtxField::Socket,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetListenerSock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_get_listener_sock to be rejected on sk_lookup");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_get_listener_sock' is only valid in tc and cgroup_skb programs")
    }));
}

#[test]
fn test_infer_get_listener_sock_helper_in_cgroup_skb_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
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
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetListenerSock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_get_listener_sock to infer on cgroup_skb");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer type, got {:?}", other),
    }
}

#[test]
fn test_type_error_sk_fullsock_helper_rejects_sk_lookup_program() {
    let mut func = make_test_function();
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: sock,
        field: CtxField::Socket,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkFullsock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_sk_fullsock to be rejected on sk_lookup");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_sk_fullsock' is only valid in tc and cgroup_skb programs")
    }));
}

#[test]
fn test_infer_sk_fullsock_helper_in_cgroup_skb_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
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
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkFullsock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_sk_fullsock to infer on cgroup_skb");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer type, got {:?}", other),
    }
}

#[test]
fn test_type_error_tcp_sock_helper_rejects_sk_lookup_program() {
    let mut func = make_test_function();
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: sock,
        field: CtxField::Socket,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TcpSock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_tcp_sock to be rejected on sk_lookup");
    assert!(errs.iter().any(|e| {
        e.message.contains(
            "helper 'bpf_tcp_sock' is only valid in tc, cgroup_skb, cgroup_sockopt, and sock_ops programs",
        )
    }));
}

#[test]
fn test_infer_tcp_sock_helper_in_cgroup_sockopt_program() {
    let mut func = make_test_function();
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: sock,
        field: CtxField::Socket,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TcpSock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_tcp_sock to infer on cgroup_sockopt");
    assert_bpf_tcp_sock_ptr(types.get(&dst));
}

#[test]
fn test_type_error_skc_to_tcp_sock_helper_rejects_cgroup_sockopt_program() {
    let mut func = make_test_function();
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: sock,
        field: CtxField::Socket,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkcToTcpSock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_skc_to_tcp_sock to be rejected on cgroup_sockopt");
    assert!(errs.iter().any(|e| e.message.contains(
        "helper 'bpf_skc_to_tcp_sock' is only valid in fentry, fexit, tp_btf, sk_lookup, sk_msg, sk_skb, sk_skb_parser, and sock_ops programs"
    )));
}

#[test]
fn test_infer_skc_to_tcp_sock_helper_in_sk_lookup_program() {
    let mut func = make_test_function();
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: sock,
        field: CtxField::Socket,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkcToTcpSock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_skc_to_tcp_sock to infer on sk_lookup");
    assert_eq!(
        types.get(&dst),
        Some(&MirType::named_kernel_struct_ptr("tcp_sock"))
    );
}

#[test]
fn test_type_error_sock_from_file_helper_rejects_kprobe_program() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let file = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: file,
        kfunc: "bpf_get_task_exe_file".to_string(),
        btf_id: None,
        args: vec![task],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SockFromFile as u32,
        args: vec![MirValue::VReg(file)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_sock_from_file to be rejected on kprobe");
    assert!(errs.iter().any(|e| e.message.contains(
        "helper 'bpf_sock_from_file' is only valid in fentry, fexit, and tp_btf programs"
    )));
}

#[test]
fn test_infer_sock_from_file_helper_in_fentry_program() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let file = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: file,
        kfunc: "bpf_get_task_exe_file".to_string(),
        btf_id: None,
        args: vec![task],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SockFromFile as u32,
        args: vec![MirValue::VReg(file)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "tcp_connect");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_sock_from_file to infer on fentry");
    assert!(
        types.get(&task).is_some_and(MirType::is_task_struct_ptr),
        "expected task vreg to infer as task_struct pointer, got {:?}",
        types.get(&task)
    );
    assert!(
        types.get(&file).is_some_and(MirType::is_file_ptr),
        "expected file vreg to infer as file pointer, got {:?}",
        types.get(&file)
    );
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer type, got {:?}", other),
    }
}

#[test]
fn test_type_error_task_storage_get_helper_rejects_xdp_program() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TaskStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(task),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_task_storage_get to be rejected on xdp");
    assert!(errs.iter().any(|e| e.message.contains(
        "helper 'bpf_task_storage_get' is only valid in kprobe, kretprobe, uprobe, uretprobe, perf_event, raw_tracepoint, tracepoint, fentry, fexit, tp_btf, and lsm programs"
    )));
}

#[test]
fn test_infer_task_storage_get_helper_in_kretprobe_program() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TaskStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(task),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kretprobe, "do_sys_openat2");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_task_storage_get to infer on kretprobe");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Map);
        }
        other => panic!("expected map pointer type, got {:?}", other),
    }
}

#[test]
fn test_type_error_inode_storage_get_helper_rejects_kprobe_program() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let inode = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: inode,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::InodeStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(inode),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_inode_storage_get to be rejected on kprobe");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_inode_storage_get' is only valid in lsm programs")
    }));
}

#[test]
fn test_infer_inode_storage_get_helper_in_lsm_program() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let inode = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::InodeStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(inode),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Lsm, "file_open");
    let hints = HashMap::from([(inode, MirType::named_kernel_struct_ptr("inode"))]);
    let mut ti = TypeInference::new_with_env(Some(probe_ctx), None, None, Some(&hints), None);
    let types = ti
        .infer(&func)
        .expect("expected bpf_inode_storage_get to infer on lsm");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Map);
        }
        other => panic!("expected map pointer type, got {:?}", other),
    }
}

#[test]
fn test_type_error_sk_storage_get_helper_rejects_xdp_program() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let pid = func.alloc_vreg();
    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: sk,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(sk),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_sk_storage_get to be rejected on xdp");
    assert!(errs.iter().any(|e| e.message.contains(
        "helper 'bpf_sk_storage_get' is only valid in tc, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, tp_btf, and lsm programs"
    )));
}

#[test]
fn test_infer_sk_storage_get_helper_in_cgroup_sock_program() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: sk,
        field: CtxField::Socket,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(sk),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_sk_storage_get to infer on cgroup_sock");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Map);
        }
        other => panic!("expected map pointer type, got {:?}", other),
    }
}

#[test]
fn test_type_error_sk_storage_delete_helper_rejects_cgroup_sock_program() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: sk,
        field: CtxField::Socket,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkStorageDelete as u32,
        args: vec![MirValue::StackSlot(map_slot), MirValue::VReg(sk)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:post_bind4");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_sk_storage_delete to be rejected on cgroup_sock");
    assert!(errs.iter().any(|e| e.message.contains(
        "helper 'bpf_sk_storage_delete' is only valid in tc, cgroup_skb, cgroup_sock_addr, cgroup_sockopt, sock_ops, sk_msg, struct_ops, fentry, fexit, tp_btf, and lsm programs"
    )));
}

#[test]
fn test_infer_sk_storage_delete_helper_in_cgroup_sockopt_program() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: sk,
        field: CtxField::Socket,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkStorageDelete as u32,
        args: vec![MirValue::StackSlot(map_slot), MirValue::VReg(sk)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_sk_storage_delete to infer on cgroup_sockopt");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_type_error_redirect_peer_helper_requires_zero_flags() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::RedirectPeer as u32,
        args: vec![MirValue::Const(1), MirValue::Const(1)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_redirect_peer flags to require zero");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect_peer' requires arg1 = 0")
    }));
}

#[test]
fn test_infer_redirect_peer_helper_in_tc_ingress_program() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::RedirectPeer as u32,
        args: vec![MirValue::Const(1), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected tc ingress bpf_redirect_peer helper to infer");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_type_error_redirect_neigh_helper_rejects_non_tc_programs() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::RedirectNeigh as u32,
        args: vec![
            MirValue::Const(1),
            MirValue::Const(0),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_redirect_neigh to be rejected outside tc");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect_neigh' is only valid in tc programs")
    }));
}

#[test]
fn test_type_error_redirect_neigh_helper_requires_zero_flags() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::RedirectNeigh as u32,
        args: vec![
            MirValue::Const(1),
            MirValue::Const(0),
            MirValue::Const(0),
            MirValue::Const(1),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_redirect_neigh flags to require zero");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect_neigh' requires arg3 = 0")
    }));
}

#[test]
fn test_type_error_redirect_neigh_helper_requires_zero_plen_for_null_params() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::RedirectNeigh as u32,
        args: vec![
            MirValue::Const(1),
            MirValue::Const(0),
            MirValue::Const(4),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected null params to require plen zero");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect_neigh' requires arg2 = 0 when arg1 is null")
    }));
}

#[test]
fn test_infer_redirect_neigh_helper_in_tc_program() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::RedirectNeigh as u32,
        args: vec![
            MirValue::Const(1),
            MirValue::Const(0),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected tc bpf_redirect_neigh helper to infer");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_type_error_helper_get_current_comm_rejects_small_stack_slot() {
    let mut func = make_test_function();
    let buf_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetCurrentComm as u32,
        args: vec![MirValue::StackSlot(buf_slot), MirValue::Const(16)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected get_current_comm stack-size error");
    assert!(
        errs.iter().any(|e| e
            .message
            .contains("helper get_current_comm dst requires 16 bytes")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_infer_packet_byte_helpers_follow_program_surface() {
    for (helper, program_type, target, args_len) in [
        (
            BpfHelper::SkbLoadBytes,
            EbpfProgramType::SocketFilter,
            "udp4:127.0.0.1:31337",
            4,
        ),
        (
            BpfHelper::SkbLoadBytesRelative,
            EbpfProgramType::CgroupSkb,
            "/sys/fs/cgroup:ingress",
            5,
        ),
        (BpfHelper::XdpLoadBytes, EbpfProgramType::Xdp, "lo", 4),
        (BpfHelper::XdpStoreBytes, EbpfProgramType::Xdp, "lo", 4),
    ] {
        let mut func = make_test_function();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let block = func.block_mut(BlockId(0));
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

        let probe_ctx = ProbeContext::new(program_type, target);
        let mut ti = TypeInference::new(Some(probe_ctx));
        let types = ti.infer(&func).unwrap_or_else(|errs| {
            panic!("expected helper {} to infer: {:?}", helper.name(), errs)
        });
        assert_eq!(types.get(&dst), Some(&MirType::I64));
    }
}

#[test]
fn test_type_error_packet_byte_helpers_reject_invalid_programs() {
    for (helper, program_type, target, expected) in [
        (
            BpfHelper::SkbLoadBytes,
            EbpfProgramType::Kprobe,
            "ksys_read",
            "helper 'bpf_skb_load_bytes' is only valid in socket_filter, tc, cgroup_skb, sk_skb, and sk_skb_parser programs",
        ),
        (
            BpfHelper::SkbLoadBytesRelative,
            EbpfProgramType::SkSkb,
            "/sys/fs/bpf/demo_sockmap",
            "helper 'bpf_skb_load_bytes_relative' is only valid in socket_filter, tc, and cgroup_skb programs",
        ),
        (
            BpfHelper::XdpStoreBytes,
            EbpfProgramType::Tc,
            "lo:ingress",
            "helper 'bpf_xdp_store_bytes' is only valid in xdp programs",
        ),
    ] {
        let mut func = make_test_function();
        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let block = func.block_mut(BlockId(0));
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
        if matches!(helper, BpfHelper::SkbLoadBytesRelative) {
            args.push(MirValue::Const(0));
        }
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args,
        });
        block.terminator = MirInst::Return { val: None };

        let probe_ctx = ProbeContext::new(program_type, target);
        let mut ti = TypeInference::new(Some(probe_ctx));
        let errs = ti
            .infer(&func)
            .expect_err("expected packet-byte helper program-surface error");
        assert!(
            errs.iter().any(|e| e.message.contains(expected)),
            "unexpected errors: {:?}",
            errs
        );
    }
}

#[test]
fn test_type_error_skb_load_bytes_rejects_small_destination_buffer() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(2, 2, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkbLoadBytes as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::Const(0),
            MirValue::StackSlot(buf_slot),
            MirValue::Const(4),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected skb_load_bytes destination buffer bounds error");
    assert!(
        errs.iter().any(|e| e
            .message
            .contains("helper skb_load_bytes to requires 4 bytes")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_infer_helper_csum_diff_allows_null_zero_side() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let to_slot = func.alloc_stack_slot(4, 4, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
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
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(Some(ProbeContext::new(EbpfProgramType::Xdp, "lo")));
    let types = ti
        .infer(&func)
        .expect("expected csum_diff to allow null from with zero from_size");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_type_error_helper_csum_diff_rejects_null_nonzero_side() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let to_slot = func.alloc_stack_slot(4, 4, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
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
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(Some(ProbeContext::new(EbpfProgramType::Xdp, "lo")));
    let errs = ti
        .infer(&func)
        .expect_err("expected csum_diff to reject null from with nonzero from_size");
    assert!(
        errs.iter().any(|e| e
            .message
            .contains("helper 28 arg0 requires arg1 = 0 when arg0 is null")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_helper_csum_diff_rejects_unaligned_size() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let from_slot = func.alloc_stack_slot(4, 4, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
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
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(Some(ProbeContext::new(EbpfProgramType::Xdp, "lo")));
    let errs = ti
        .infer(&func)
        .expect_err("expected csum_diff to reject non-word-sized from_size");
    assert!(
        errs.iter().any(|e| e
            .message
            .contains("helper 'bpf_csum_diff' requires arg1 to be a multiple of 4")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_helper_csum_diff_rejects_small_buffer() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let from_slot = func.alloc_stack_slot(2, 2, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::CsumDiff as u32,
        args: vec![
            MirValue::StackSlot(from_slot),
            MirValue::Const(4),
            MirValue::Const(0),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(Some(ProbeContext::new(EbpfProgramType::Xdp, "lo")));
    let errs = ti
        .infer(&func)
        .expect_err("expected csum_diff to reject too-small from buffer");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("helper csum_diff from requires 4 bytes")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_infer_helper_sysctl_get_current_value_in_cgroup_sysctl_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SysctlGetCurrentValue as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(buf_slot),
            MirValue::Const(16),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected sysctl get_current_value helper to infer");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_type_error_helper_sysctl_get_current_value_rejects_small_stack_slot() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SysctlGetCurrentValue as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(buf_slot),
            MirValue::Const(16),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSysctl, "/sys/fs/cgroup");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected sysctl get_current_value stack-size error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper sysctl_get_current_value buf requires 16 bytes")
    }));
}

#[test]
fn test_infer_helper_map_lookup_returns_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::StackSlot(key_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: 1, // bpf_map_lookup_elem
        args: vec![MirValue::VReg(map), MirValue::VReg(key)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Map);
        }
        other => panic!("Expected helper map lookup pointer return, got {:?}", other),
    }
}

#[test]
fn test_type_error_helper_map_queue_helpers_reject_non_stack_map_arg() {
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
        let mut func = make_test_function();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let map_value_ptr = func.alloc_vreg();
        let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();

        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::CallHelper {
            dst: map_value_ptr,
            helper: BpfHelper::MapLookupElem as u32,
            args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
        });
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: match helper {
                BpfHelper::MapPushElem => vec![
                    MirValue::VReg(map_value_ptr),
                    MirValue::StackSlot(value_slot),
                    MirValue::Const(0),
                ],
                BpfHelper::MapPopElem | BpfHelper::MapPeekElem => {
                    vec![
                        MirValue::VReg(map_value_ptr),
                        MirValue::StackSlot(value_slot),
                    ]
                }
                _ => unreachable!(),
            },
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let errs = ti
            .infer(&func)
            .expect_err("expected map queue helper map-pointer space error");
        assert!(
            errs.iter().any(|e| e.message.contains(needle)),
            "unexpected errors for helper {helper:?}: {:?}",
            errs
        );
    }
}

#[test]
fn test_type_error_helper_map_queue_helpers_reject_non_pointer_value_arg() {
    let helpers = [
        BpfHelper::MapPushElem,
        BpfHelper::MapPopElem,
        BpfHelper::MapPeekElem,
    ];

    for helper in helpers {
        let mut func = make_test_function();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();

        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: match helper {
                BpfHelper::MapPushElem => {
                    vec![
                        MirValue::StackSlot(map_slot),
                        MirValue::Const(0),
                        MirValue::Const(0),
                    ]
                }
                BpfHelper::MapPopElem | BpfHelper::MapPeekElem => {
                    vec![MirValue::StackSlot(map_slot), MirValue::Const(0)]
                }
                _ => unreachable!(),
            },
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let errs = ti
            .infer(&func)
            .expect_err("expected map queue helper value pointer error");
        assert!(
            errs.iter().any(|e| e
                .message
                .contains(&format!("helper {} arg1 expects pointer", helper as u32))),
            "unexpected errors for helper {helper:?}: {:?}",
            errs
        );
    }
}

#[test]
fn test_type_error_helper_ringbuf_query_rejects_non_stack_map_arg() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let lookup = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst: lookup,
        helper: BpfHelper::MapLookupElem as u32,
        args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::RingbufQuery as u32,
        args: vec![MirValue::VReg(lookup), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected ringbuf_query map-pointer space error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper ringbuf_query map expects pointer in [Stack]")
    }));
}

#[test]
fn test_type_error_helper_tcp_check_syncookie_rejects_non_kernel_sk_pointer() {
    let mut func = make_test_function();
    let sk_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sk = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let kptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: sk,
        src: MirValue::StackSlot(sk_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: kptr,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TcpCheckSyncookie as u32,
        args: vec![
            MirValue::VReg(sk),
            MirValue::VReg(kptr),
            MirValue::Const(20),
            MirValue::VReg(kptr),
            MirValue::Const(20),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected tcp_check_syncookie sk pointer-space error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper tcp_check_syncookie sk expects pointer in [Kernel], got Stack")
    }));
}

#[test]
fn test_type_error_helper_tcp_check_syncookie_rejects_non_positive_lengths() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: sk,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TcpCheckSyncookie as u32,
        args: vec![
            MirValue::VReg(sk),
            MirValue::VReg(sk),
            MirValue::Const(0),
            MirValue::VReg(sk),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected tcp_check_syncookie size range errors");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("helper 100 arg2 must be > 0")),
        "unexpected errors: {:?}",
        errs
    );
    assert!(
        errs.iter()
            .any(|e| e.message.contains("helper 100 arg4 must be > 0")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_helper_tcp_gen_syncookie_rejects_non_kernel_sk_pointer() {
    let mut func = make_test_function();
    let sk_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sk = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let kptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: sk,
        src: MirValue::StackSlot(sk_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: kptr,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TcpGenSyncookie as u32,
        args: vec![
            MirValue::VReg(sk),
            MirValue::VReg(kptr),
            MirValue::Const(20),
            MirValue::VReg(kptr),
            MirValue::Const(20),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected tcp_gen_syncookie sk pointer-space error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper tcp_gen_syncookie sk expects pointer in [Kernel], got Stack")
    }));
}

#[test]
fn test_type_error_helper_tcp_gen_syncookie_rejects_non_positive_lengths() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: sk,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TcpGenSyncookie as u32,
        args: vec![
            MirValue::VReg(sk),
            MirValue::VReg(sk),
            MirValue::Const(0),
            MirValue::VReg(sk),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected tcp_gen_syncookie size range errors");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("helper 110 arg2 must be > 0")),
        "unexpected errors: {:?}",
        errs
    );
    assert!(
        errs.iter()
            .any(|e| e.message.contains("helper 110 arg4 must be > 0")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_tcp_check_syncookie_helper_rejects_kprobe_program() {
    let mut func = make_test_function();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TcpCheckSyncookie as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::VReg(ctx),
            MirValue::Const(20),
            MirValue::VReg(ctx),
            MirValue::Const(20),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let errs = ti
        .infer(&func)
        .expect_err("expected bpf_tcp_check_syncookie to be rejected on kprobe");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_tcp_check_syncookie' is only valid in xdp and tc programs")
    }));
}

#[test]
fn test_infer_tcp_check_syncookie_helper_in_xdp_program() {
    let mut func = make_test_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
    let ctx = func.alloc_vreg();
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    let entry = func.block_mut(BlockId(0));
    entry.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    entry.instructions.push(MirInst::CallHelper {
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
    entry.instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    entry.terminator = MirInst::Branch {
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

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_tcp_check_syncookie to infer on xdp");
    assert_eq!(types.get(&syncookie_ret), Some(&MirType::I64));
}

#[test]
fn test_infer_tcp_gen_syncookie_helper_in_tc_program() {
    let mut func = make_test_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
    let ctx = func.alloc_vreg();
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    let entry = func.block_mut(BlockId(0));
    entry.instructions.push(MirInst::LoadCtxField {
        dst: ctx,
        field: CtxField::Context,
        slot: None,
    });
    entry.instructions.push(MirInst::CallHelper {
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
    entry.instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    entry.terminator = MirInst::Branch {
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

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let mut ti = TypeInference::new(Some(probe_ctx));
    let types = ti
        .infer(&func)
        .expect("expected bpf_tcp_gen_syncookie to infer on tc");
    assert_eq!(types.get(&syncookie_ret), Some(&MirType::I64));
}

#[test]
fn test_infer_helper_sk_storage_get_returns_map_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(sk),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let hints = HashMap::from([(sk, MirType::named_kernel_struct_ptr("bpf_sock"))]);
    let mut ti = TypeInference::new_with_env(None, None, None, Some(&hints), None);
    let types = ti.infer(&func).unwrap();
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Map);
        }
        other => panic!(
            "Expected helper sk_storage_get map pointer return, got {:?}",
            other
        ),
    }
}

#[test]
fn test_type_error_helper_sk_storage_get_rejects_anonymous_kernel_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(sk),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let hints = HashMap::from([(
        sk,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    )]);
    let mut ti = TypeInference::new_with_env(None, None, None, Some(&hints), None);
    let errs = ti
        .infer(&func)
        .expect_err("expected anonymous kernel pointer to fail sk_storage_get");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_sk_storage_get' arg1 expects socket pointer")
    }));
}

#[test]
fn test_type_error_helper_sk_storage_get_rejects_non_stack_map_arg() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map_value_ptr = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst: map_value_ptr,
        helper: BpfHelper::MapLookupElem as u32,
        args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
    });
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: sk,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkStorageGet as u32,
        args: vec![
            MirValue::VReg(map_value_ptr),
            MirValue::VReg(sk),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected sk_storage_get map-pointer space error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper sk_storage_get map expects pointer in [Stack]")
    }));
}

#[test]
fn test_type_error_helper_sk_storage_get_rejects_non_kernel_sk_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sk_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: sk,
        src: MirValue::StackSlot(sk_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(sk),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected sk_storage_get sk pointer-space error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper sk_storage_get sk expects pointer in [Kernel], got Stack")
    }));
}

#[test]
fn test_type_error_helper_sk_storage_delete_rejects_non_kernel_sk_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sk_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: sk,
        src: MirValue::StackSlot(sk_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkStorageDelete as u32,
        args: vec![MirValue::StackSlot(map_slot), MirValue::VReg(sk)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected sk_storage_delete sk pointer-space error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper sk_storage_delete sk expects pointer in [Kernel], got Stack")
    }));
}

#[test]
fn test_infer_helper_task_storage_get_returns_map_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TaskStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(task),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Map);
        }
        other => panic!(
            "Expected helper task_storage_get map pointer return, got {:?}",
            other
        ),
    }
}

#[test]
fn test_infer_helper_task_storage_get_return_uses_map_value_hint() {
    let mut func = make_test_function();
    let map = func.alloc_vreg();
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TaskStorageGet as u32,
        args: vec![
            MirValue::VReg(map),
            MirValue::VReg(task),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let value_ty = MirType::Array {
        elem: Box::new(MirType::U8),
        len: 16,
    };
    let hints = HashMap::from([
        (
            map,
            MirType::MapRef {
                key_ty: Box::new(MirType::U32),
                val_ty: Box::new(value_ty.clone()),
            },
        ),
        (task, MirType::named_kernel_struct_ptr("task_struct")),
    ]);
    let mut ti = TypeInference::new_with_env(None, None, None, Some(&hints), None);
    let types = ti.infer(&func).unwrap();
    assert_eq!(
        types.get(&dst),
        Some(&MirType::Ptr {
            pointee: Box::new(value_ty),
            address_space: AddressSpace::Map,
        })
    );
}

#[test]
fn test_infer_helper_cgrp_storage_get_allows_null_cgroup_and_returns_map_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::CgrpStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::Const(0),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected bpf_cgrp_storage_get to allow null cgroup");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Map);
        }
        other => panic!(
            "Expected helper cgrp_storage_get map pointer return, got {:?}",
            other
        ),
    }
}

#[test]
fn test_infer_helper_cgrp_storage_get_return_uses_map_value_hint() {
    let mut func = make_test_function();
    let map = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::CgrpStorageGet as u32,
        args: vec![
            MirValue::VReg(map),
            MirValue::VReg(cgroup),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let value_ty = MirType::Array {
        elem: Box::new(MirType::U8),
        len: 16,
    };
    let hints = HashMap::from([
        (
            map,
            MirType::MapRef {
                key_ty: Box::new(MirType::U32),
                val_ty: Box::new(value_ty.clone()),
            },
        ),
        (cgroup, MirType::named_kernel_struct_ptr("cgroup")),
    ]);
    let mut ti = TypeInference::new_with_env(None, None, None, Some(&hints), None);
    let types = ti.infer(&func).unwrap();
    assert_eq!(
        types.get(&dst),
        Some(&MirType::Ptr {
            pointee: Box::new(value_ty),
            address_space: AddressSpace::Map,
        })
    );
}

#[test]
fn test_type_error_helper_cgrp_storage_get_rejects_anonymous_kernel_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let cgroup = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::CgrpStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(cgroup),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let hints = HashMap::from([(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    )]);
    let mut ti = TypeInference::new_with_env(None, None, None, Some(&hints), None);
    let errs = ti
        .infer(&func)
        .expect_err("expected anonymous kernel pointer to fail cgrp_storage_get");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_cgrp_storage_get' arg1 expects cgroup pointer")
    }));
}

#[test]
fn test_infer_helper_cgrp_storage_delete_allows_null_cgroup() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::CgrpStorageDelete as u32,
        args: vec![MirValue::StackSlot(map_slot), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected bpf_cgrp_storage_delete to allow null cgroup");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_type_error_helper_cgrp_storage_delete_rejects_anonymous_kernel_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let cgroup = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::CgrpStorageDelete as u32,
        args: vec![MirValue::StackSlot(map_slot), MirValue::VReg(cgroup)],
    });
    block.terminator = MirInst::Return { val: None };

    let hints = HashMap::from([(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    )]);
    let mut ti = TypeInference::new_with_env(None, None, None, Some(&hints), None);
    let errs = ti
        .infer(&func)
        .expect_err("expected anonymous kernel pointer to fail cgrp_storage_delete");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_cgrp_storage_delete' arg1 expects cgroup pointer")
    }));
}

#[test]
fn test_type_error_helper_task_storage_get_rejects_anonymous_kernel_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TaskStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(task),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let hints = HashMap::from([(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    )]);
    let mut ti = TypeInference::new_with_env(None, None, None, Some(&hints), None);
    let errs = ti
        .infer(&func)
        .expect_err("expected anonymous kernel pointer to fail task_storage_get");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_task_storage_get' arg1 expects task pointer")
    }));
}

#[test]
fn test_type_error_helper_task_storage_get_rejects_non_stack_map_arg() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map_value_ptr = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst: map_value_ptr,
        helper: BpfHelper::MapLookupElem as u32,
        args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
    });
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TaskStorageGet as u32,
        args: vec![
            MirValue::VReg(map_value_ptr),
            MirValue::VReg(task),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected task_storage_get map-pointer space error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper task_storage_get map expects pointer in [Stack]")
    }));
}

#[test]
fn test_type_error_helper_task_storage_get_rejects_non_kernel_task_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let task_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: task,
        src: MirValue::StackSlot(task_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TaskStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(task),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected task_storage_get task pointer-space error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper task_storage_get task expects pointer in [Kernel], got Stack")
    }));
}

#[test]
fn test_type_error_helper_task_storage_delete_rejects_non_kernel_task_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let task_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: task,
        src: MirValue::StackSlot(task_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TaskStorageDelete as u32,
        args: vec![MirValue::StackSlot(map_slot), MirValue::VReg(task)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected task_storage_delete task pointer-space error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper task_storage_delete task expects pointer in [Kernel], got Stack")
    }));
}

#[test]
fn test_infer_helper_inode_storage_get_returns_map_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let inode = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::InodeStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(inode),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let hints = HashMap::from([(inode, MirType::named_kernel_struct_ptr("inode"))]);
    let mut ti = TypeInference::new_with_env(None, None, None, Some(&hints), None);
    let types = ti.infer(&func).unwrap();
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Map);
        }
        other => panic!(
            "Expected helper inode_storage_get map pointer return, got {:?}",
            other
        ),
    }
}

#[test]
fn test_type_error_helper_inode_storage_get_rejects_anonymous_kernel_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let inode = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::InodeStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(inode),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let hints = HashMap::from([(
        inode,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    )]);
    let mut ti = TypeInference::new_with_env(None, None, None, Some(&hints), None);
    let errs = ti
        .infer(&func)
        .expect_err("expected anonymous kernel pointer to fail inode_storage_get");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_inode_storage_get' arg1 expects inode pointer")
    }));
}

#[test]
fn test_type_error_helper_inode_storage_get_rejects_non_stack_map_arg() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map_value_ptr = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let inode = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst: map_value_ptr,
        helper: BpfHelper::MapLookupElem as u32,
        args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
    });
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: inode,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::InodeStorageGet as u32,
        args: vec![
            MirValue::VReg(map_value_ptr),
            MirValue::VReg(inode),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected inode_storage_get map-pointer space error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper inode_storage_get map expects pointer in [Stack]")
    }));
}

#[test]
fn test_type_error_helper_inode_storage_get_rejects_non_kernel_inode_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let inode_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let inode = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: inode,
        src: MirValue::StackSlot(inode_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::InodeStorageGet as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::VReg(inode),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected inode_storage_get inode pointer-space error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper inode_storage_get inode expects pointer in [Kernel], got Stack")
    }));
}

#[test]
fn test_type_error_helper_inode_storage_delete_rejects_non_kernel_inode_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let inode_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let inode = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: inode,
        src: MirValue::StackSlot(inode_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::InodeStorageDelete as u32,
        args: vec![MirValue::StackSlot(map_slot), MirValue::VReg(inode)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected inode_storage_delete inode pointer-space error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper inode_storage_delete inode expects pointer in [Kernel], got Stack")
    }));
}

#[test]
fn test_infer_helper_sk_lookup_returns_kernel_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: ctx,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
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
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!(
            "Expected helper sk_lookup kernel pointer return, got {:?}",
            other
        ),
    }
}

#[test]
fn test_infer_helper_skc_lookup_returns_kernel_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: ctx,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkcLookupTcp as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(tuple_slot),
            MirValue::Const(16),
            MirValue::Const(0),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!(
            "Expected helper skc_lookup kernel pointer return, got {:?}",
            other
        ),
    }
}

#[test]
fn test_infer_helper_get_listener_sock_returns_kernel_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: ctx,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
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
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetListenerSock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();
    assert_eq!(
        types.get(&dst),
        Some(&MirType::named_kernel_struct_ptr("bpf_sock"))
    );
}

#[test]
fn test_infer_helper_sk_fullsock_returns_kernel_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: ctx,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
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
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkFullsock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();
    assert_eq!(
        types.get(&dst),
        Some(&MirType::named_kernel_struct_ptr("bpf_sock"))
    );
}

#[test]
fn test_infer_helper_tcp_sock_returns_kernel_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: ctx,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
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
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TcpSock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();
    assert_bpf_tcp_sock_ptr(types.get(&dst));
}

#[test]
fn test_infer_helper_skc_to_tcp_sock_returns_kernel_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: ctx,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
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
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkcToTcpSock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();
    assert_eq!(
        types.get(&dst),
        Some(&MirType::named_kernel_struct_ptr("tcp_sock"))
    );
}

#[test]
fn test_infer_helper_skc_to_tcp6_sock_returns_kernel_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: ctx,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
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
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkcToTcp6Sock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();
    assert_eq!(
        types.get(&dst),
        Some(&MirType::named_kernel_struct_ptr("tcp6_sock"))
    );
}

#[test]
fn test_infer_helper_additional_skc_casts_return_kernel_pointer() {
    let helpers = [
        (
            BpfHelper::SkcToTcpTimewaitSock,
            MirType::named_kernel_struct_ptr("tcp_timewait_sock"),
        ),
        (
            BpfHelper::SkcToTcpRequestSock,
            MirType::named_kernel_struct_ptr("tcp_request_sock"),
        ),
        (
            BpfHelper::SkcToUdp6Sock,
            MirType::named_kernel_struct_ptr("udp6_sock"),
        ),
        (
            BpfHelper::SkcToUnixSock,
            MirType::named_kernel_struct_ptr("unix_sock"),
        ),
    ];

    for (helper, expected_ty) in helpers {
        let mut func = make_test_function();
        let pid = func.alloc_vreg();
        let ctx = func.alloc_vreg();
        let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let sock = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::Copy {
            dst: pid,
            src: MirValue::Const(7),
        });
        block.instructions.push(MirInst::CallKfunc {
            dst: ctx,
            kfunc: "bpf_task_from_pid".to_string(),
            btf_id: None,
            args: vec![pid],
        });
        block.instructions.push(MirInst::CallHelper {
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
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: vec![MirValue::VReg(sock)],
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti
            .infer(&func)
            .unwrap_or_else(|errs| panic!("expected helper {helper:?} to infer: {errs:?}"));
        assert_eq!(types.get(&dst), Some(&expected_ty));
    }
}

#[test]
fn test_infer_helper_sock_from_file_returns_kernel_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let file = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: file,
        kfunc: "bpf_get_task_exe_file".to_string(),
        btf_id: None,
        args: vec![task],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SockFromFile as u32,
        args: vec![MirValue::VReg(file)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!(
            "Expected helper sock_from_file kernel pointer return, got {:?}",
            other
        ),
    }
}

#[test]
fn test_infer_helper_get_current_task_btf_returns_task_pointer() {
    for helper in [BpfHelper::GetCurrentTask, BpfHelper::GetCurrentTaskBtf] {
        let mut func = make_test_function();
        let task = func.alloc_vreg();
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::CallHelper {
            dst: task,
            helper: helper as u32,
            args: vec![],
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let types = ti.infer(&func).unwrap();
        assert!(
            types.get(&task).is_some_and(MirType::is_task_struct_ptr),
            "expected current-task helper to infer task_struct pointer, got {:?}",
            types.get(&task)
        );
    }
}

#[test]
fn test_infer_helper_task_pt_regs_returns_kernel_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TaskPtRegs as u32,
        args: vec![MirValue::VReg(task)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();
    assert!(
        types.get(&task).is_some_and(MirType::is_task_struct_ptr),
        "expected task vreg to infer as task_struct pointer, got {:?}",
        types.get(&task)
    );
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!(
            "Expected helper task_pt_regs kernel pointer return, got {:?}",
            other
        ),
    }
}

#[test]
fn test_type_error_helper_sk_fullsock_rejects_non_kernel_pointer() {
    let mut func = make_test_function();
    let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: sock,
        src: MirValue::StackSlot(sock_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkFullsock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected non-kernel sk_fullsock pointer error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper sk_fullsock sk expects pointer in [Kernel], got Stack")
    }));
}

#[test]
fn test_type_error_helper_tcp_sock_rejects_non_kernel_pointer() {
    let mut func = make_test_function();
    let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: sock,
        src: MirValue::StackSlot(sock_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TcpSock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected non-kernel tcp_sock pointer error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper tcp_sock sk expects pointer in [Kernel], got Stack")
    }));
}

#[test]
fn test_type_error_helper_skc_to_tcp_sock_rejects_non_kernel_pointer() {
    let mut func = make_test_function();
    let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: sock,
        src: MirValue::StackSlot(sock_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkcToTcpSock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected non-kernel skc_to_tcp_sock pointer error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper skc_to_tcp_sock sk expects pointer in [Kernel], got Stack")
    }));
}

#[test]
fn test_type_error_helper_skc_to_tcp6_sock_rejects_non_kernel_pointer() {
    let mut func = make_test_function();
    let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: sock,
        src: MirValue::StackSlot(sock_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkcToTcp6Sock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected non-kernel skc_to_tcp6_sock pointer error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper skc_to_tcp6_sock sk expects pointer in [Kernel], got Stack")
    }));
}

#[test]
fn test_type_error_helper_additional_skc_casts_reject_non_kernel_pointer() {
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
        let mut func = make_test_function();
        let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let sock = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let block = func.block_mut(BlockId(0));
        block.instructions.push(MirInst::Copy {
            dst: sock,
            src: MirValue::StackSlot(sock_slot),
        });
        block.instructions.push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: vec![MirValue::VReg(sock)],
        });
        block.terminator = MirInst::Return { val: None };

        let mut ti = TypeInference::new(None);
        let errs = ti
            .infer(&func)
            .expect_err("expected non-kernel skc cast helper pointer error");
        assert!(
            errs.iter().any(|e| e.message.contains(needle)),
            "expected helper {helper:?} pointer-space error containing '{needle}', got {:?}",
            errs
        );
    }
}

#[test]
fn test_type_error_helper_sock_from_file_rejects_non_kernel_pointer() {
    let mut func = make_test_function();
    let file_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let file = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: file,
        src: MirValue::StackSlot(file_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SockFromFile as u32,
        args: vec![MirValue::VReg(file)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected non-kernel sock_from_file pointer error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper sock_from_file file expects pointer in [Kernel], got Stack")
    }));
}

#[test]
fn test_infer_helper_sock_from_file_accepts_named_file_pointer() {
    let mut func = make_test_function();
    let file = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SockFromFile as u32,
        args: vec![MirValue::VReg(file)],
    });
    block.terminator = MirInst::Return { val: None };

    let hints = HashMap::from([(file, MirType::named_kernel_struct_ptr("file"))]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "tcp_connect");
    let mut ti = TypeInference::new_with_env(Some(probe_ctx), None, None, Some(&hints), None);
    let types = ti
        .infer(&func)
        .expect("expected named file pointer to satisfy bpf_sock_from_file");
    assert_eq!(
        types.get(&dst).and_then(TypeInference::mir_ptr_space),
        Some(AddressSpace::Kernel)
    );
}

#[test]
fn test_type_error_helper_sock_from_file_rejects_anonymous_kernel_pointer() {
    let mut func = make_test_function();
    let file = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SockFromFile as u32,
        args: vec![MirValue::VReg(file)],
    });
    block.terminator = MirInst::Return { val: None };

    let hints = HashMap::from([(
        file,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    )]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Fentry, "tcp_connect");
    let mut ti = TypeInference::new_with_env(Some(probe_ctx), None, None, Some(&hints), None);
    let errs = ti
        .infer(&func)
        .expect_err("expected anonymous kernel pointer to fail bpf_sock_from_file");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_sock_from_file' arg0 expects file pointer")
    }));
}

#[test]
fn test_type_error_helper_task_pt_regs_rejects_non_kernel_pointer() {
    let mut func = make_test_function();
    let task_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: task,
        src: MirValue::StackSlot(task_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TaskPtRegs as u32,
        args: vec![MirValue::VReg(task)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected non-kernel task_pt_regs pointer error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper task_pt_regs task expects pointer in [Kernel], got Stack")
    }));
}

#[test]
fn test_infer_helper_task_pt_regs_accepts_named_task_pointer() {
    let mut func = make_test_function();
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TaskPtRegs as u32,
        args: vec![MirValue::VReg(task)],
    });
    block.terminator = MirInst::Return { val: None };

    let hints = HashMap::from([(task, MirType::named_kernel_struct_ptr("task_struct"))]);
    let mut ti = TypeInference::new_with_env(None, None, None, Some(&hints), None);
    let types = ti
        .infer(&func)
        .expect("expected named task pointer to satisfy bpf_task_pt_regs");
    assert_eq!(
        types.get(&dst).and_then(TypeInference::mir_ptr_space),
        Some(AddressSpace::Kernel)
    );
}

#[test]
fn test_type_error_helper_task_pt_regs_rejects_anonymous_kernel_pointer() {
    let mut func = make_test_function();
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::TaskPtRegs as u32,
        args: vec![MirValue::VReg(task)],
    });
    block.terminator = MirInst::Return { val: None };

    let hints = HashMap::from([(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    )]);
    let mut ti = TypeInference::new_with_env(None, None, None, Some(&hints), None);
    let errs = ti
        .infer(&func)
        .expect_err("expected anonymous kernel pointer to fail bpf_task_pt_regs");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper 'bpf_task_pt_regs' arg0 expects task pointer")
    }));
}

#[test]
fn test_type_error_helper_get_listener_sock_rejects_non_kernel_pointer() {
    let mut func = make_test_function();
    let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: sock,
        src: MirValue::StackSlot(sock_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetListenerSock as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected non-kernel get_listener_sock pointer error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper get_listener_sock sk expects pointer in [Kernel], got Stack")
    }));
}

#[test]
fn test_type_error_helper_sk_release_rejects_non_kernel_pointer() {
    let mut func = make_test_function();
    let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: sock,
        src: MirValue::StackSlot(sock_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkRelease as u32,
        args: vec![MirValue::VReg(sock)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected non-kernel sk_release pointer error");
    assert!(
        errs.iter().any(|e| e
            .message
            .contains("helper sk_release sock expects pointer in [Kernel], got Stack")),
        "unexpected type errors: {:?}",
        errs
    );
}

#[test]
fn test_infer_helper_sk_assign_allows_null_sk_arg() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: ctx,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkAssign as u32,
        args: vec![MirValue::VReg(ctx), MirValue::Const(0), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected sk_assign with null sk to infer");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
}

#[test]
fn test_type_error_helper_sk_assign_rejects_non_kernel_ctx_pointer() {
    let mut func = make_test_function();
    let ctx_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let pid = func.alloc_vreg();
    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: sk,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkAssign as u32,
        args: vec![
            MirValue::StackSlot(ctx_slot),
            MirValue::VReg(sk),
            MirValue::Const(0),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected sk_assign ctx pointer-space error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper sk_assign ctx expects pointer in [Kernel]")
    }));
}

#[test]
fn test_type_error_helper_sk_assign_rejects_non_kernel_sk_pointer() {
    let mut func = make_test_function();
    let sk_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let pid = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let sk = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: sk,
        src: MirValue::StackSlot(sk_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: ctx,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::SkAssign as u32,
        args: vec![MirValue::VReg(ctx), MirValue::VReg(sk), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected sk_assign sk pointer-space error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper sk_assign sk expects pointer in [Kernel], got Stack")
    }));
}

#[test]
fn test_infer_helper_kptr_xchg_returns_kernel_pointer() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::StackSlot(key_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst: dst_ptr,
        helper: BpfHelper::MapLookupElem as u32,
        args: vec![MirValue::VReg(map), MirValue::VReg(key)],
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti.infer(&func).unwrap();
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!(
            "Expected helper kptr_xchg kernel pointer return, got {:?}",
            other
        ),
    }
}

#[test]
fn test_type_error_helper_kptr_xchg_rejects_non_map_dst_arg0() {
    let mut func = make_test_function();
    let dst_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: dst_ptr,
        src: MirValue::StackSlot(dst_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::Const(0)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected non-map kptr_xchg destination error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper kptr_xchg dst expects pointer in [Map]")
    }));
}

#[test]
fn test_infer_helper_kptr_xchg_allows_zero_vreg_arg1() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst_ptr = func.alloc_vreg();
    let zero = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::StackSlot(key_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst: dst_ptr,
        helper: BpfHelper::MapLookupElem as u32,
        args: vec![MirValue::VReg(map), MirValue::VReg(key)],
    });
    block.instructions.push(MirInst::Copy {
        dst: zero,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::VReg(zero)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected known-zero vreg to satisfy nullable helper arg");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!(
            "Expected helper kptr_xchg kernel pointer return, got {:?}",
            other
        ),
    }
}

#[test]
fn test_type_error_helper_kptr_xchg_rejects_non_zero_vreg_arg1() {
    let mut func = make_test_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst_ptr = func.alloc_vreg();
    let one = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::StackSlot(key_slot),
    });
    block.instructions.push(MirInst::CallHelper {
        dst: dst_ptr,
        helper: BpfHelper::MapLookupElem as u32,
        args: vec![MirValue::VReg(map), MirValue::VReg(key)],
    });
    block.instructions.push(MirInst::Copy {
        dst: one,
        src: MirValue::Const(1),
    });
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::VReg(one)],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected non-zero vreg to be rejected for nullable helper arg");
    assert!(
        errs.iter()
            .any(|e| { e.message.contains("helper 194 arg1 expects pointer value") })
    );
}

#[test]
fn test_type_error_helper_probe_read_user_rejects_stack_src() {
    let mut func = make_test_function();
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::ProbeReadUser as u32,
        args: vec![
            MirValue::StackSlot(dst_slot),
            MirValue::Const(8),
            MirValue::StackSlot(src_slot),
        ],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected probe_read_user source pointer-space error");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("helper probe_read src expects pointer in [User]")
    }));
}
