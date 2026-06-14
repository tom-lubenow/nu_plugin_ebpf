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
        (
            BpfHelper::XdpStoreBytes,
            EbpfProgramType::Tc.info(),
            "helper 'bpf_xdp_store_bytes' is only valid in xdp programs",
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
        (BpfHelper::XdpLoadBytes, EbpfProgramType::Xdp.info(), 4),
        (BpfHelper::XdpStoreBytes, EbpfProgramType::Xdp.info(), 4),
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

fn make_skb_bytes_verify_call(
    helper: BpfHelper,
    offset: i64,
    len: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
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
    let mut args = vec![
        MirValue::VReg(ctx),
        MirValue::Const(offset),
        MirValue::StackSlot(buf_slot),
        MirValue::Const(len),
    ];
    if matches!(
        helper,
        BpfHelper::SkbStoreBytes | BpfHelper::SkbLoadBytesRelative
    ) {
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
    (func, types)
}

#[test]
fn test_verify_mir_for_probe_context_skb_byte_helpers_reject_invalid_offsets() {
    for (helper, offset, expected) in [
        (
            BpfHelper::SkbStoreBytes,
            -1,
            "skb byte helpers require arg1 offset to be between 0 and i32::MAX",
        ),
        (
            BpfHelper::SkbLoadBytes,
            0x8000_0000,
            "skb byte helpers require arg1 offset to be between 0 and i32::MAX",
        ),
        (
            BpfHelper::SkbLoadBytesRelative,
            -1,
            "helper 'bpf_skb_load_bytes_relative' requires arg1 offset to be between 0 and 0xffff",
        ),
        (
            BpfHelper::SkbLoadBytesRelative,
            0x1_0000,
            "helper 'bpf_skb_load_bytes_relative' requires arg1 offset to be between 0 and 0xffff",
        ),
    ] {
        let (func, types) = make_skb_bytes_verify_call(helper, offset, 4);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected skb byte helper scalar range validation error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "expected {expected:?}, got {err:?}"
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_skb_store_bytes_rejects_len_over_u32() {
    let (func, types) = make_skb_bytes_verify_call(BpfHelper::SkbStoreBytes, 0, 0x1_0000_0000);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_store_bytes len range validation error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_skb_store_bytes' requires arg3 len to be between 0 and u32::MAX"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_packet_byte_helpers_reject_zero_len() {
    for helper in [
        BpfHelper::SkbStoreBytes,
        BpfHelper::SkbLoadBytes,
        BpfHelper::SkbLoadBytesRelative,
        BpfHelper::XdpLoadBytes,
        BpfHelper::XdpStoreBytes,
    ] {
        let (func, types) = make_skb_bytes_verify_call(helper, 0, 0);
        let probe_ctx = if matches!(helper, BpfHelper::XdpLoadBytes | BpfHelper::XdpStoreBytes) {
            ProbeContext::new(EbpfProgramType::Xdp, "lo")
        } else {
            ProbeContext::new(EbpfProgramType::Tc, "lo:ingress")
        };
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected packet byte helper zero-len error");
        assert!(
            err.iter().any(|e| e.message.contains("arg3 must be > 0")),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_skb_load_bytes_rejects_len_over_u32() {
    for helper in [BpfHelper::SkbLoadBytes, BpfHelper::SkbLoadBytesRelative] {
        let (func, types) = make_skb_bytes_verify_call(helper, 0, 0x1_0000_0000);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected skb load byte helper len range validation error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("skb load byte helpers require arg3 len to be between 0 and u32::MAX")),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_flow_dissector_skb_load_bytes_rejects_large_offset() {
    let (func, types) = make_skb_bytes_verify_call(BpfHelper::SkbLoadBytes, 0x1_0000, 4);
    let probe_ctx = ProbeContext::new(EbpfProgramType::FlowDissector, "/proc/self/ns/net");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected flow_dissector skb_load_bytes offset validation error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_skb_load_bytes' requires arg1 offset to be between 0 and 0xffff in flow_dissector programs"
        )),
        "unexpected errors: {:?}",
        err
    );
}

fn make_xdp_bytes_verify_call(
    helper: BpfHelper,
    offset: i64,
    len: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
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
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(offset),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(len),
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
fn test_verify_mir_for_probe_context_xdp_byte_helpers_reject_invalid_offset_or_len() {
    for (helper, offset, len, expected) in [
        (
            BpfHelper::XdpLoadBytes,
            -1,
            16,
            "xdp byte helpers require arg1 offset to be between 0 and 0xffff",
        ),
        (
            BpfHelper::XdpStoreBytes,
            0x1_0000,
            16,
            "xdp byte helpers require arg1 offset to be between 0 and 0xffff",
        ),
        (
            BpfHelper::XdpLoadBytes,
            0,
            -1,
            "xdp byte helpers require arg3 len to be between 0 and 0xffff",
        ),
        (
            BpfHelper::XdpStoreBytes,
            0,
            0x1_0000,
            "xdp byte helpers require arg3 len to be between 0 and 0xffff",
        ),
    ] {
        let (func, types) = make_xdp_bytes_verify_call(helper, offset, len);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected xdp byte helper scalar range validation error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "expected {expected:?}, got {err:?}"
        );
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

fn make_sysctl_helper_verify_call(
    helper: BpfHelper,
    buf_len: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let mut args = vec![
        MirValue::VReg(ctx),
        MirValue::StackSlot(buf_slot),
        MirValue::Const(buf_len),
    ];
    if matches!(helper, BpfHelper::SysctlGetName) {
        args.push(MirValue::Const(0));
    }

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
fn test_verify_mir_sysctl_helpers_reject_zero_buf_len() {
    for helper in [
        BpfHelper::SysctlGetName,
        BpfHelper::SysctlGetCurrentValue,
        BpfHelper::SysctlGetNewValue,
        BpfHelper::SysctlSetNewValue,
    ] {
        let (func, types) = make_sysctl_helper_verify_call(helper, 0);
        let err = verify_mir_for_program(&func, &types, EbpfProgramType::CgroupSysctl.info())
            .expect_err("expected sysctl helper zero-length buffer error");
        assert!(
            err.iter().any(|e| e.message.contains("arg2 must be > 0")),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
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
fn test_verify_mir_helper_redirect_neigh_rejects_invalid_ifindex() {
    for ifindex in [-1_i64, 0x1_0000_0000] {
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
                    MirValue::Const(ifindex),
                    MirValue::Const(0),
                    MirValue::Const(0),
                    MirValue::Const(0),
                ],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types)
            .expect_err("expected bpf_redirect_neigh ifindex to be rejected");
        assert!(
            err.iter().any(|e| e.message.contains(
                "helper 'bpf_redirect_neigh' requires arg0 ifindex to be between 0 and u32::MAX"
            )),
            "unexpected errors for ifindex {ifindex}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_helper_redirect_neigh_rejects_invalid_plen() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let params = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::RedirectNeigh as u32,
            args: vec![
                MirValue::Const(1),
                MirValue::StackSlot(params),
                MirValue::Const(i64::from(i32::MAX) + 1),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bpf_redirect_neigh plen range error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_redirect_neigh' requires arg2 plen to be between 0 and i32::MAX"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_redirect_neigh_rejects_small_params_buffer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let params = func.alloc_stack_slot(4, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::RedirectNeigh as u32,
            args: vec![
                MirValue::Const(1),
                MirValue::StackSlot(params),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected redirect_neigh params bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper redirect_neigh params out of bounds")),
        "unexpected errors: {:?}",
        err
    );
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
fn test_verify_mir_helper_redirect_peer_rejects_invalid_ifindex() {
    for ifindex in [-1_i64, 0x1_0000_0000] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: BpfHelper::RedirectPeer as u32,
                args: vec![MirValue::Const(ifindex), MirValue::Const(0)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types)
            .expect_err("expected bpf_redirect_peer ifindex to be rejected");
        assert!(
            err.iter().any(|e| e.message.contains(
                "helper 'bpf_redirect_peer' requires arg0 ifindex to be between 0 and u32::MAX"
            )),
            "unexpected errors for ifindex {ifindex}: {:?}",
            err
        );
    }
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
fn test_verify_mir_helper_load_hdr_opt_rejects_unknown_flags() {
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
            helper: BpfHelper::LoadHdrOpt as u32,
            args: vec![
                MirValue::VReg(ctx),
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

    let err = verify_mir(&func, &types).expect_err("expected load_hdr_opt flags error");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "helper 'bpf_load_hdr_opt' requires arg3 flags to contain only BPF_LOAD_HDR_OPT_TCP_SYN",
        )
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
                MirValue::Const(12),
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
                MirValue::Const(12),
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
    make_socket_lookup_verify_call_with_tuple_size_and_netns(helper, 12, 0, flags)
}

fn make_socket_lookup_verify_call_with_tuple_size(
    helper: BpfHelper,
    tuple_size: i64,
    flags: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    make_socket_lookup_verify_call_with_tuple_size_and_netns(helper, tuple_size, 0, flags)
}

fn make_socket_lookup_verify_call_with_tuple_size_and_netns(
    helper: BpfHelper,
    tuple_size: i64,
    netns: i64,
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
                MirValue::Const(tuple_size),
                MirValue::Const(netns),
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
fn test_verify_mir_for_probe_context_socket_lookup_rejects_tuple_size_above_u32_max() {
    let (func, types) =
        make_socket_lookup_verify_call_with_tuple_size(BpfHelper::SkLookupTcp, 0x1_0000_0000, 0);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected socket lookup tuple_size range error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "socket lookup helpers require arg2 tuple_size to be between 0 and u32::MAX"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_socket_lookup_rejects_invalid_tuple_size() {
    for helper in [
        BpfHelper::SkLookupTcp,
        BpfHelper::SkLookupUdp,
        BpfHelper::SkcLookupTcp,
    ] {
        for tuple_size in [0, 16] {
            let (func, types) =
                make_socket_lookup_verify_call_with_tuple_size(helper, tuple_size, 0);
            let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
            let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
                .expect_err("expected socket lookup tuple_size exact-size error");
            assert!(
                err.iter().any(|e| e.message.contains(
                    "socket lookup helpers require arg2 tuple_size to be sizeof(tuple->ipv4) (12) or sizeof(tuple->ipv6) (36)"
                )),
                "unexpected errors for {:?} tuple_size {}: {:?}",
                helper,
                tuple_size,
                err
            );
        }
    }
}

#[test]
fn test_verify_mir_for_probe_context_socket_lookup_rejects_netns_outside_i32_range() {
    for helper in [
        BpfHelper::SkLookupTcp,
        BpfHelper::SkLookupUdp,
        BpfHelper::SkcLookupTcp,
    ] {
        for netns in [i32::MIN as i64 - 1, i32::MAX as i64 + 1] {
            let (func, types) =
                make_socket_lookup_verify_call_with_tuple_size_and_netns(helper, 12, netns, 0);
            let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
            let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
                .expect_err("expected socket lookup netns range error");
            assert!(
                err.iter().any(|e| e.message.contains(
                    "socket lookup helpers require arg3 netns to be between i32::MIN and i32::MAX"
                )),
                "unexpected errors for {:?} netns {}: {:?}",
                helper,
                netns,
                err
            );
        }
    }
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
fn test_verify_mir_for_probe_context_sk_assign_requires_zero_flags_in_tc_action() {
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

    let probe_ctx = ProbeContext::new(EbpfProgramType::TcAction, "demo-action");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected sk_assign tc_action flags error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_sk_assign' requires arg2 = 0 in tc_action programs")
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
                MirValue::Const(12),
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
                MirValue::Const(12),
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
fn test_verify_mir_for_probe_context_tcp_send_ack_rejects_rcv_nxt_above_u32_max() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let tcp_sock = func.alloc_vreg();
    func.param_non_null.insert(tcp_sock.0 as usize);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::TcpSendAck as u32,
            args: vec![MirValue::VReg(tcp_sock), MirValue::Const(0x1_0000_0000)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(tcp_sock, MirType::named_kernel_struct_ptr("tcp_sock"));
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new_struct_ops_callback("tcp_congestion_ops", "cong_avoid");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_tcp_send_ack rcv_nxt range error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_tcp_send_ack' requires arg1 rcv_nxt to be between 0 and u32::MAX"
        )),
        "unexpected errors: {:?}",
        err
    );
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
    make_get_task_stack_verify_call_with_flags(size, buf_size, 0)
}

fn make_get_task_stack_verify_call_with_flags(
    size: i64,
    buf_size: usize,
    flags: i64,
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
                MirValue::Const(flags),
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
fn test_verify_mir_helper_get_task_stack_rejects_build_id_without_user_stack() {
    let (func, types) = make_get_task_stack_verify_call_with_flags(24, 24, 0x0800);
    let err = verify_mir(&func, &types)
        .expect_err("expected get_task_stack build-id flag combination error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "stack-copy helpers require BPF_F_USER_STACK when BPF_F_USER_BUILD_ID is set"
        )),
        "unexpected errors: {:?}",
        err
    );
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
        err.iter().any(|e| e
            .message
            .contains("stack-copy helpers require arg2 size to be between 0 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_get_task_stack_rejects_size_over_u32() {
    let (func, types) = make_get_task_stack_verify_call(0x1_0000_0000, 8);
    let err = verify_mir(&func, &types).expect_err("expected get_task_stack size range error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("stack-copy helpers require arg2 size to be between 0 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_trampoline_arg_verify_call(
    helper: BpfHelper,
    output_size: usize,
    ctx_non_null: bool,
    arg_index: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let ctx = func.alloc_vreg();
    if ctx_non_null {
        func.param_non_null.insert(ctx.0 as usize);
    }
    let dst = func.alloc_vreg();
    let output_slot = func.alloc_stack_slot(output_size, 8, StackSlotKind::StringBuffer);
    let args = match helper {
        BpfHelper::GetFuncArg => {
            vec![
                MirValue::VReg(ctx),
                MirValue::Const(arg_index),
                MirValue::StackSlot(output_slot),
            ]
        }
        BpfHelper::GetFuncRet => vec![MirValue::VReg(ctx), MirValue::StackSlot(output_slot)],
        BpfHelper::GetFuncArgCnt => vec![MirValue::VReg(ctx)],
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

    let types = HashMap::from([
        (
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::Unknown),
                address_space: AddressSpace::Kernel,
            },
        ),
        (dst, MirType::I64),
    ]);

    (func, types)
}

fn trampoline_helper_probe_context(helper: BpfHelper) -> ProbeContext {
    match helper {
        BpfHelper::GetFuncArg | BpfHelper::GetFuncArgCnt => {
            ProbeContext::new(EbpfProgramType::Fentry, "tcp_connect")
        }
        BpfHelper::GetFuncRet => ProbeContext::new(EbpfProgramType::Fexit, "tcp_connect"),
        _ => unreachable!(),
    }
}

#[test]
fn test_verify_mir_trampoline_arg_helpers_accept_non_null_raw_context() {
    for helper in [
        BpfHelper::GetFuncArg,
        BpfHelper::GetFuncRet,
        BpfHelper::GetFuncArgCnt,
    ] {
        let (func, types) = make_trampoline_arg_verify_call(helper, 8, true, 0);
        let probe_ctx = trampoline_helper_probe_context(helper);
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .unwrap_or_else(|err| panic!("expected {helper:?} to verify: {err:?}"));
    }
}

#[test]
fn test_verify_mir_trampoline_arg_helpers_reject_unchecked_nullable_raw_context() {
    for helper in [
        BpfHelper::GetFuncArg,
        BpfHelper::GetFuncRet,
        BpfHelper::GetFuncArgCnt,
    ] {
        let (func, types) = make_trampoline_arg_verify_call(helper, 8, false, 0);
        let probe_ctx = trampoline_helper_probe_context(helper);
        let err = match verify_mir_for_probe_context(&func, &types, &probe_ctx) {
            Ok(()) => panic!("expected {helper:?} null-check error"),
            Err(err) => err,
        };
        assert!(
            err.iter()
                .any(|e| e.message.contains("may dereference null pointer")),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_trampoline_arg_helpers_reject_small_output_buffer() {
    for helper in [BpfHelper::GetFuncArg, BpfHelper::GetFuncRet] {
        let (func, types) = make_trampoline_arg_verify_call(helper, 4, true, 0);
        let probe_ctx = trampoline_helper_probe_context(helper);
        let err = match verify_mir_for_probe_context(&func, &types, &probe_ctx) {
            Ok(()) => panic!("expected {helper:?} output bounds error"),
            Err(err) => err,
        };
        assert!(
            err.iter().any(|e| e.message.contains("out of bounds")),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_get_func_arg_rejects_index_above_u32_max() {
    let (func, types) =
        make_trampoline_arg_verify_call(BpfHelper::GetFuncArg, 8, true, 0x1_0000_0000);
    let probe_ctx = trampoline_helper_probe_context(BpfHelper::GetFuncArg);
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected get_func_arg index range error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_get_func_arg' requires arg1 n to be between 0 and u32::MAX")),
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
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_d_path' requires arg2 size to be between 0 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_d_path_rejects_size_over_u32() {
    let (func, types) = make_d_path_verify_call(0x1_0000_0000, 8);
    let err = verify_mir(&func, &types).expect_err("expected d_path size range error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_d_path' requires arg2 size to be between 0 and u32::MAX")),
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
fn test_verify_mir_helper_ima_hash_helpers_require_positive_size() {
    for (helper, object_type_name, expected) in [
        (
            BpfHelper::ImaInodeHash,
            "inode",
            "helper 161 arg2 must be > 0",
        ),
        (
            BpfHelper::ImaFileHash,
            "file",
            "helper 193 arg2 must be > 0",
        ),
    ] {
        let (func, types) = make_ima_hash_verify_call(helper, object_type_name, 0, 16);
        let err = verify_mir(&func, &types).expect_err("expected IMA positive-size error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "expected {expected:?}, got {err:?}"
        );
    }
}

#[test]
fn test_verify_mir_helper_ima_inode_hash_rejects_size_over_u32() {
    let (func, types) =
        make_ima_hash_verify_call(BpfHelper::ImaInodeHash, "inode", 0x1_0000_0000, 16);
    let err = verify_mir(&func, &types).expect_err("expected IMA inode size range error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("IMA hash helpers require arg2 size to be between 1 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ima_file_hash_rejects_size_over_u32() {
    let (func, types) =
        make_ima_hash_verify_call(BpfHelper::ImaFileHash, "file", 0x1_0000_0000, 16);
    let err = verify_mir(&func, &types).expect_err("expected IMA file size range error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("IMA hash helpers require arg2 size to be between 1 and u32::MAX")),
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

