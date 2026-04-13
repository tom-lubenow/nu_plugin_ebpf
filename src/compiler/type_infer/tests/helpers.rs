use super::*;
use crate::compiler::EbpfProgramType;

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

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkLookup, "/proc/self/ns/net");
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
        (BpfHelper::SkbPullData, vec![MirValue::Const(64)]),
        (
            BpfHelper::SkbChangeHead,
            vec![MirValue::Const(14), MirValue::Const(0)],
        ),
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
fn test_type_error_sockopt_helpers_reject_invalid_program() {
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
            BpfHelper::GetSockOpt,
            ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:bind4"),
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
fn test_infer_sock_ops_hdr_opt_helpers_in_sock_ops_context() {
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
            EbpfProgramType::SockOps,
            "/sys/fs/cgroup",
        )));
        let types = ti
            .infer(&func)
            .expect("expected sock_ops hdr-opt helper in sock_ops context");
        assert_eq!(types.get(&dst), Some(&MirType::I64));
    }
}

#[test]
fn test_infer_sock_ops_cb_flags_set_in_sock_ops_context() {
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
        EbpfProgramType::SockOps,
        "/sys/fs/cgroup",
    )));
    let types = ti
        .infer(&func)
        .expect("expected sock_ops_cb_flags_set helper in sock_ops context");
    assert_eq!(types.get(&dst), Some(&MirType::I64));
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
fn test_infer_sk_cgroup_helpers_from_socket_pointer() {
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
        let types = ti
            .infer(&func)
            .expect("expected socket helper to infer from ctx.sk");
        assert_eq!(types.get(&dst), Some(&MirType::I64));
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
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer type, got {:?}", other),
    }
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
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer type, got {:?}", other),
    }
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

    let probe_ctx = ProbeContext::new(EbpfProgramType::Lsm, "file_open");
    let mut ti = TypeInference::new(Some(probe_ctx));
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
fn test_infer_helper_sk_storage_get_returns_map_pointer() {
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

    let mut ti = TypeInference::new(None);
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
    let pid = func.alloc_vreg();
    let inode = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
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
            MirValue::StackSlot(map_slot),
            MirValue::VReg(inode),
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
            "Expected helper inode_storage_get map pointer return, got {:?}",
            other
        ),
    }
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
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!(
            "Expected helper get_listener_sock kernel pointer return, got {:?}",
            other
        ),
    }
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
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!(
            "Expected helper sk_fullsock kernel pointer return, got {:?}",
            other
        ),
    }
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
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!(
            "Expected helper tcp_sock kernel pointer return, got {:?}",
            other
        ),
    }
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
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!(
            "Expected helper skc_to_tcp_sock kernel pointer return, got {:?}",
            other
        ),
    }
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
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!(
            "Expected helper skc_to_tcp6_sock kernel pointer return, got {:?}",
            other
        ),
    }
}

#[test]
fn test_infer_helper_additional_skc_casts_return_kernel_pointer() {
    let helpers = [
        BpfHelper::SkcToTcpTimewaitSock,
        BpfHelper::SkcToTcpRequestSock,
        BpfHelper::SkcToUdp6Sock,
        BpfHelper::SkcToUnixSock,
    ];

    for helper in helpers {
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
        match types.get(&dst) {
            Some(MirType::Ptr { address_space, .. }) => {
                assert_eq!(*address_space, AddressSpace::Kernel);
            }
            other => panic!(
                "Expected helper {helper:?} kernel pointer return, got {:?}",
                other
            ),
        }
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
