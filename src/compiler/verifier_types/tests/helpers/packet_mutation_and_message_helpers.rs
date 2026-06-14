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

fn make_xdp_adjust_verify_call(
    helper: BpfHelper,
    delta: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
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
            args: vec![MirValue::VReg(ctx), MirValue::Const(delta)],
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
fn test_verify_mir_for_probe_context_xdp_adjust_rejects_delta_outside_i32_range() {
    for helper in [
        BpfHelper::XdpAdjustHead,
        BpfHelper::XdpAdjustMeta,
        BpfHelper::XdpAdjustTail,
    ] {
        for delta in [i32::MIN as i64 - 1, i32::MAX as i64 + 1] {
            let (func, types) = make_xdp_adjust_verify_call(helper, delta);
            let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
            let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
                .expect_err("expected xdp adjust delta range error");
            assert!(
                err.iter().any(|e| e.message.contains(
                    "XDP adjust helpers require arg1 delta to be between i32::MIN and i32::MAX"
                )),
                "unexpected errors for {:?} delta {}: {:?}",
                helper,
                delta,
                err
            );
        }
    }
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
            .any(|e| e.message.contains("stale packet pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_tail_call_invalidates_prior_packet_pointers() {
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
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

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
        helper: BpfHelper::TailCall as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(map_slot),
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

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected stale packet pointer load to fail after tail_call");
    assert!(
        err.iter()
            .any(|e| e.message.contains("stale packet pointer")),
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

fn make_skb_change_head_verify_call(
    head_room: i64,
    flags: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
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
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(head_room),
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

fn make_skb_change_tail_verify_call(
    new_len: i64,
    flags: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
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
            helper: BpfHelper::SkbChangeTail as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(new_len),
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

fn make_skb_pull_data_verify_call(len: i64) -> (MirFunction, HashMap<VReg, MirType>) {
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
            helper: BpfHelper::SkbPullData as u32,
            args: vec![MirValue::VReg(ctx), MirValue::Const(len)],
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
fn test_verify_mir_for_probe_context_skb_change_head_requires_zero_flags() {
    let (func, types) = make_skb_change_head_verify_call(14, 1);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_change_head flags to require zero");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_skb_change_head' requires arg2 = 0")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_skb_change_head_rejects_invalid_head_room() {
    for head_room in [-1_i64, 0x8000_0000] {
        let (func, types) = make_skb_change_head_verify_call(head_room, 0);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected bpf_skb_change_head head_room to be rejected");
        assert!(
            err.iter().any(|e| e.message.contains(
                "helper 'bpf_skb_change_head' requires arg1 head_room to be between 0 and i32::MAX"
            )),
            "unexpected errors for head_room {head_room}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_skb_change_tail_rejects_invalid_new_len() {
    for new_len in [-1_i64, 0x8000_0000] {
        let (func, types) = make_skb_change_tail_verify_call(new_len, 0);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected bpf_skb_change_tail new_len to be rejected");
        assert!(
            err.iter().any(|e| e.message.contains(
                "helper 'bpf_skb_change_tail' requires arg1 new_len to be between 0 and i32::MAX"
            )),
            "unexpected errors for new_len {new_len}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_skb_pull_data_rejects_invalid_len() {
    for len in [-1_i64, 0x1_0000_0000] {
        let (func, types) = make_skb_pull_data_verify_call(len);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected bpf_skb_pull_data len to be rejected");
        assert!(
            err.iter().any(|e| e.message.contains(
                "helper 'bpf_skb_pull_data' requires arg1 len to be between 0 and u32::MAX"
            )),
            "unexpected errors for len {len}: {:?}",
            err
        );
    }
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
    make_check_mtu_verify_call_with_len_diff(flags, mtu_len_size, 0)
}

fn make_check_mtu_verify_call_with_len_diff(
    flags: i64,
    mtu_len_size: usize,
    len_diff: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    make_check_mtu_verify_call_with_ifindex_len_diff_and_mtu_len_value(
        0,
        flags,
        mtu_len_size,
        len_diff,
        None,
    )
}

fn make_check_mtu_verify_call_with_len_diff_and_mtu_len_value(
    flags: i64,
    mtu_len_size: usize,
    len_diff: i64,
    mtu_len_value: Option<i64>,
) -> (MirFunction, HashMap<VReg, MirType>) {
    make_check_mtu_verify_call_with_ifindex_len_diff_and_mtu_len_value(
        0,
        flags,
        mtu_len_size,
        len_diff,
        mtu_len_value,
    )
}

fn make_check_mtu_verify_call_with_ifindex(
    ifindex: i64,
    flags: i64,
    mtu_len_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    make_check_mtu_verify_call_with_ifindex_len_diff_and_mtu_len_value(
        ifindex,
        flags,
        mtu_len_size,
        0,
        None,
    )
}

fn make_check_mtu_verify_call_with_ifindex_len_diff_and_mtu_len_value(
    ifindex: i64,
    flags: i64,
    mtu_len_size: usize,
    len_diff: i64,
    mtu_len_value: Option<i64>,
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
    if let Some(value) = mtu_len_value {
        func.block_mut(entry).instructions.push(MirInst::StoreSlot {
            slot: mtu_len,
            offset: 0,
            val: MirValue::Const(value),
            ty: MirType::U32,
        });
    }
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::CheckMtu as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(ifindex),
                MirValue::StackSlot(mtu_len),
                MirValue::Const(len_diff),
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
fn test_verify_mir_for_probe_context_check_mtu_rejects_unknown_tc_flags() {
    let (func, types) = make_check_mtu_verify_call(0x02, 4);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_check_mtu unknown flags to be rejected");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_check_mtu' requires arg4 flags")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_check_mtu_rejects_ifindex_above_u32_max() {
    let (func, types) = make_check_mtu_verify_call_with_ifindex(0x1_0000_0000, 0, 4);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_check_mtu ifindex range error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_check_mtu' requires arg1 ifindex to be between 0 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_check_mtu_rejects_len_diff_above_i32_max() {
    let (func, types) = make_check_mtu_verify_call_with_len_diff(0, 4, 0x8000_0000);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_check_mtu len_diff range error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_check_mtu' requires arg3 len_diff to be between i32::MIN and i32::MAX"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_check_mtu_rejects_len_diff_with_segment_flags() {
    let (func, types) = make_check_mtu_verify_call_with_len_diff(1, 4, 1);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_check_mtu segment flags to reject len_diff");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_check_mtu' requires arg3 len_diff to be 0 when arg4 has BPF_MTU_CHK_SEGS"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_check_mtu_rejects_known_mtu_len_with_segment_flags() {
    let (func, types) =
        make_check_mtu_verify_call_with_len_diff_and_mtu_len_value(1, 4, 0, Some(1));
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_check_mtu segment flags to reject nonzero mtu_len");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_check_mtu' requires *arg2 mtu_len to be 0 when arg4 has BPF_MTU_CHK_SEGS"
        )),
        "unexpected errors: {:?}",
        err
    );
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
fn test_verify_mir_for_probe_context_fib_lookup_rejects_small_plen() {
    let (func, types) = make_fib_lookup_verify_call(8, 64, 0);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_fib_lookup plen error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_fib_lookup' requires arg2 plen")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_fib_lookup_rejects_zero_plen() {
    let (func, types) = make_fib_lookup_verify_call(0, 64, 0);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_fib_lookup zero plen error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 69 arg2 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_fib_lookup_rejects_plen_above_i32_max() {
    let (func, types) = make_fib_lookup_verify_call(i32::MAX as i64 + 1, 64, 0);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_fib_lookup plen upper-bound error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_fib_lookup' requires arg2 plen")),
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

#[test]
fn test_verify_mir_for_probe_context_fib_lookup_rejects_tbid_without_direct() {
    let (func, types) = make_fib_lookup_verify_call(64, 64, 0x08);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_fib_lookup TBID flag-combination error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_fib_lookup' requires BPF_FIB_LOOKUP_TBID to be used with BPF_FIB_LOOKUP_DIRECT"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_fib_lookup_rejects_mark_with_direct() {
    let (func, types) = make_fib_lookup_verify_call(64, 64, 0x21);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_fib_lookup MARK flag-combination error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_fib_lookup' requires BPF_FIB_LOOKUP_MARK not to be used with BPF_FIB_LOOKUP_DIRECT"
        )),
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
            let size = if matches!(
                helper,
                BpfHelper::SkbGetTunnelKey | BpfHelper::SkbSetTunnelKey
            ) {
                44
            } else {
                16
            };
            let (func, types) = make_skb_tunnel_verify_call(helper, size, size as usize, 0);
            verify_mir_for_probe_context(&func, &types, &probe_ctx)
                .expect("expected skb tunnel helper to verify");
        }
    }
}

#[test]
fn test_verify_mir_for_probe_context_skb_tunnel_helpers_reject_non_tc_lwt_xmit_program() {
    let (func, types) = make_skb_tunnel_verify_call(BpfHelper::SkbSetTunnelKey, 44, 44, 0);
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
fn test_verify_mir_for_probe_context_skb_tunnel_helpers_reject_zero_size() {
    for helper in [
        BpfHelper::SkbGetTunnelKey,
        BpfHelper::SkbSetTunnelKey,
        BpfHelper::SkbGetTunnelOpt,
        BpfHelper::SkbSetTunnelOpt,
    ] {
        let (func, types) = make_skb_tunnel_verify_call(helper, 0, 16, 0);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected skb tunnel zero-size error");
        assert!(
            err.iter().any(|e| e.message.contains("arg2 must be > 0")),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_skb_tunnel_key_helpers_reject_invalid_size() {
    let (func, types) = make_skb_tunnel_verify_call(BpfHelper::SkbSetTunnelKey, 16, 16, 0);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected skb tunnel key size validation error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "skb tunnel key helpers require arg2 size to be one of 8, 22, 24, 28, or 44 bytes"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_skb_get_tunnel_option_helper_rejects_size_above_u32() {
    let (func, types) =
        make_skb_tunnel_verify_call(BpfHelper::SkbGetTunnelOpt, 0x1_0000_0000, 16, 0);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected skb get tunnel option size validation error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_skb_get_tunnel_opt' requires arg2 size to be between 0 and u32::MAX"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_skb_set_tunnel_option_rejects_size_above_opts_max() {
    let (func, types) = make_skb_tunnel_verify_call(BpfHelper::SkbSetTunnelOpt, 256, 256, 0);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected skb set tunnel option size validation error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_skb_set_tunnel_opt' requires arg2 size to be between 0 and IP_TUNNEL_OPTS_MAX (255)"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_skb_set_tunnel_option_helper_rejects_unaligned_size() {
    let (func, types) = make_skb_tunnel_verify_call(BpfHelper::SkbSetTunnelOpt, 18, 18, 0);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected skb set tunnel option size alignment error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_skb_set_tunnel_opt' requires arg2 size to be a multiple of 4")),
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
        let (func, types) = make_skb_tunnel_verify_call(helper, 44, 44, flags);
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
    make_skb_get_xfrm_state_verify_call_with_index(0, flags, size, buffer_size)
}

fn make_skb_get_xfrm_state_verify_call_with_index(
    index: i64,
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
                MirValue::Const(index),
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
        let (func, types) = make_skb_get_xfrm_state_verify_call(0, 28, 28);
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected bpf_skb_get_xfrm_state helper to verify");
    }
}

#[test]
fn test_verify_mir_for_probe_context_skb_get_xfrm_state_rejects_non_tc_program() {
    let (func, types) = make_skb_get_xfrm_state_verify_call(0, 28, 28);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_get_xfrm_state to be rejected outside tc");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_skb_get_xfrm_state' is only valid in tc_action, tc, tcx, and netkit programs"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_skb_get_xfrm_state_requires_zero_flags() {
    let (func, types) = make_skb_get_xfrm_state_verify_call(1, 28, 28);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_get_xfrm_state flags to require zero");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_skb_get_xfrm_state' requires arg4 = 0")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_skb_get_xfrm_state_rejects_index_above_u32() {
    let (func, types) = make_skb_get_xfrm_state_verify_call_with_index(0x1_0000_0000, 0, 28, 28);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_get_xfrm_state index range error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_skb_get_xfrm_state' requires arg1 index to be between 0 and u32::MAX"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_skb_get_xfrm_state_rejects_size_above_u32() {
    let (func, types) = make_skb_get_xfrm_state_verify_call(0, 0x1_0000_0000, 28);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_get_xfrm_state size range error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_skb_get_xfrm_state' requires arg3 size to be between 0 and u32::MAX"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_skb_get_xfrm_state_rejects_small_buffer() {
    let (func, types) = make_skb_get_xfrm_state_verify_call(0, 28, 16);
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

#[test]
fn test_verify_mir_for_probe_context_skb_get_xfrm_state_rejects_zero_size() {
    let (func, types) = make_skb_get_xfrm_state_verify_call(0, 0, 28);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_get_xfrm_state zero-size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 66 arg3 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_skb_get_xfrm_state_rejects_size_not_struct_size() {
    let (func, types) = make_skb_get_xfrm_state_verify_call(0, 16, 28);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_get_xfrm_state exact size error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_skb_get_xfrm_state' requires arg3 size = sizeof(struct bpf_xfrm_state) (28 bytes)"
        )),
        "unexpected errors: {:?}",
        err
    );
}

fn make_lwt_buffer_verify_call_with_selector(
    helper: BpfHelper,
    selector: i64,
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
                MirValue::Const(selector),
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

fn make_lwt_buffer_verify_call(
    helper: BpfHelper,
    size: i64,
    buffer_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let selector = match helper {
        BpfHelper::LwtPushEncap => 2,
        BpfHelper::LwtSeg6Action => 2,
        _ => 0,
    };
    make_lwt_buffer_verify_call_with_selector(helper, selector, size, buffer_size)
}

fn make_lwt_seg6_adjust_srh_verify_call_with_args(
    offset: i64,
    delta: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
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
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(offset),
                MirValue::Const(delta),
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
    make_lwt_seg6_adjust_srh_verify_call_with_args(0, 4)
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
fn test_verify_mir_for_probe_context_lwt_push_encap_rejects_invalid_type() {
    let (func, types) =
        make_lwt_buffer_verify_call_with_selector(BpfHelper::LwtPushEncap, 3, 16, 16);
    let probe_ctx = ProbeContext::new(EbpfProgramType::LwtIn, "demo-route");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_lwt_push_encap type to be rejected");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_lwt_push_encap' requires arg1 type")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_lwt_push_encap_requires_ip_type_on_lwt_xmit() {
    let (func, types) =
        make_lwt_buffer_verify_call_with_selector(BpfHelper::LwtPushEncap, 0, 16, 16);
    let probe_ctx = ProbeContext::new(EbpfProgramType::LwtXmit, "demo-route");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected lwt_xmit bpf_lwt_push_encap type to be rejected");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_lwt_push_encap' requires arg1 type = BPF_LWT_ENCAP_IP")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_lwt_seg6_helpers_accept_lwt_seg6local_programs() {
    for (func, types) in [
        make_lwt_buffer_verify_call(BpfHelper::LwtSeg6StoreBytes, 16, 16),
        make_lwt_buffer_verify_call(BpfHelper::LwtSeg6Action, 16, 16),
        make_lwt_buffer_verify_call_with_selector(BpfHelper::LwtSeg6Action, 3, 4, 4),
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
fn test_verify_mir_for_probe_context_lwt_seg6_action_rejects_invalid_action() {
    let (func, types) =
        make_lwt_buffer_verify_call_with_selector(BpfHelper::LwtSeg6Action, 4, 16, 16);
    let probe_ctx = ProbeContext::new(EbpfProgramType::LwtSeg6Local, "demo-route");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_lwt_seg6_action action to be rejected");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_lwt_seg6_action' requires arg1 action")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_lwt_seg6_action_rejects_invalid_param_len_for_action() {
    for (action, size, expected) in [
        (
            2,
            4,
            "helper 'bpf_lwt_seg6_action' requires arg3 param_len = 16 for SEG6_LOCAL_ACTION_END_X",
        ),
        (
            3,
            16,
            "helper 'bpf_lwt_seg6_action' requires arg3 param_len = 4 for SEG6_LOCAL_ACTION_END_T",
        ),
    ] {
        let (func, types) =
            make_lwt_buffer_verify_call_with_selector(BpfHelper::LwtSeg6Action, action, size, 16);
        let probe_ctx = ProbeContext::new(EbpfProgramType::LwtSeg6Local, "demo-route");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected bpf_lwt_seg6_action param_len to be rejected");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "unexpected errors for action {action}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_lwt_buffer_helpers_reject_size_over_u32() {
    for (helper, program_type, target) in [
        (
            BpfHelper::LwtPushEncap,
            EbpfProgramType::LwtIn,
            "demo-route",
        ),
        (
            BpfHelper::LwtSeg6StoreBytes,
            EbpfProgramType::LwtSeg6Local,
            "demo-route",
        ),
        (
            BpfHelper::LwtSeg6Action,
            EbpfProgramType::LwtSeg6Local,
            "demo-route",
        ),
    ] {
        let (func, types) = make_lwt_buffer_verify_call(helper, 0x1_0000_0000, 16);
        let probe_ctx = ProbeContext::new(program_type, target);
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected lwt helper size range error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("lwt buffer helpers require arg3 size to be between 0 and u32::MAX")),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_lwt_buffer_helpers_reject_zero_size() {
    for (helper, program_type, target) in [
        (
            BpfHelper::LwtPushEncap,
            EbpfProgramType::LwtIn,
            "demo-route",
        ),
        (
            BpfHelper::LwtSeg6StoreBytes,
            EbpfProgramType::LwtSeg6Local,
            "demo-route",
        ),
        (
            BpfHelper::LwtSeg6Action,
            EbpfProgramType::LwtSeg6Local,
            "demo-route",
        ),
    ] {
        let (func, types) = make_lwt_buffer_verify_call(helper, 0, 16);
        let probe_ctx = ProbeContext::new(program_type, target);
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected lwt helper zero-size error");
        let expected = format!("helper {} arg3 must be > 0", helper as u32);
        assert!(
            err.iter().any(|e| e.message.contains(&expected)),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_lwt_seg6_helpers_reject_offset_over_u32() {
    for (func, types, helper_name) in [
        {
            let (func, types) = make_lwt_buffer_verify_call_with_selector(
                BpfHelper::LwtSeg6StoreBytes,
                0x1_0000_0000,
                16,
                16,
            );
            (func, types, "bpf_lwt_seg6_store_bytes")
        },
        {
            let (func, types) = make_lwt_seg6_adjust_srh_verify_call_with_args(0x1_0000_0000, 4);
            (func, types, "bpf_lwt_seg6_adjust_srh")
        },
    ] {
        let probe_ctx = ProbeContext::new(EbpfProgramType::LwtSeg6Local, "demo-route");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected lwt helper offset range error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("lwt seg6 helpers require arg1 offset to be between 0 and u32::MAX")),
            "unexpected errors for {helper_name}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_lwt_seg6_adjust_srh_rejects_delta_outside_i32_range() {
    for delta in [i32::MAX as i64 + 1, i32::MIN as i64 - 1] {
        let (func, types) = make_lwt_seg6_adjust_srh_verify_call_with_args(0, delta);
        let probe_ctx = ProbeContext::new(EbpfProgramType::LwtSeg6Local, "demo-route");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected lwt_seg6_adjust_srh delta range error");
        assert!(
            err.iter().any(|e| e.message.contains(
                "helper 'bpf_lwt_seg6_adjust_srh' requires arg2 delta to be between i32::MIN and i32::MAX"
            )),
            "unexpected errors for delta {delta}: {:?}",
            err
        );
    }
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
            .any(|e| e.message.contains("stale packet pointer")),
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
fn test_verify_mir_for_probe_context_msg_data_helpers_invalidate_prior_packet_pointers() {
    for helper in [
        BpfHelper::MsgPullData,
        BpfHelper::MsgPushData,
        BpfHelper::MsgPopData,
    ] {
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
            helper: helper as u32,
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
            .expect_err("expected stale packet pointer load to fail after message data helper");
        assert!(
            err.iter()
                .any(|e| e.message.contains("stale packet pointer")),
            "{} produced unexpected errors: {:?}",
            helper.name(),
            err
        );
    }
}

fn make_msg_data_verify_call(
    helper: BpfHelper,
    flags: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    make_msg_data_verify_call_with_range(helper, 0, 8, flags)
}

fn make_msg_byte_count_verify_call(
    helper: BpfHelper,
    bytes: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
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
            args: vec![MirValue::VReg(ctx), MirValue::Const(bytes)],
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

fn make_msg_data_verify_call_with_range(
    helper: BpfHelper,
    start: i64,
    end: i64,
    flags: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
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
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(start),
                MirValue::Const(end),
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
fn test_verify_mir_for_probe_context_msg_byte_count_helpers_reject_invalid_bytes() {
    for helper in [BpfHelper::MsgApplyBytes, BpfHelper::MsgCorkBytes] {
        for bytes in [-1_i64, 0x1_0000_0000] {
            let (func, types) = make_msg_byte_count_verify_call(helper, bytes);
            let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
            let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
                .expect_err("expected message byte-count helper bytes error");
            assert!(
                err.iter().any(|e| e.message.contains(
                    "message byte-count helpers require arg1 bytes to be between 0 and u32::MAX"
                )),
                "{} bytes={bytes} produced unexpected errors: {:?}",
                helper.name(),
                err
            );
        }
    }
}

#[test]
fn test_verify_mir_for_probe_context_msg_data_helpers_reject_nonzero_flags() {
    for helper in [
        BpfHelper::MsgPullData,
        BpfHelper::MsgPushData,
        BpfHelper::MsgPopData,
    ] {
        let (func, types) = make_msg_data_verify_call(helper, 1);
        let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected message data helper flags error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("message data reshaping helpers require arg3 flags to be 0")),
            "{} produced unexpected errors: {:?}",
            helper.name(),
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_msg_data_helpers_reject_invalid_u32_args() {
    for (helper, start, end_or_len, expected) in [
        (
            BpfHelper::MsgPullData,
            -1,
            8,
            "helper 'bpf_msg_pull_data' requires arg1 start to be between 0 and u32::MAX",
        ),
        (
            BpfHelper::MsgPullData,
            0x1_0000_0000,
            8,
            "helper 'bpf_msg_pull_data' requires arg1 start to be between 0 and u32::MAX",
        ),
        (
            BpfHelper::MsgPullData,
            0,
            -1,
            "helper 'bpf_msg_pull_data' requires arg2 end to be between 0 and u32::MAX",
        ),
        (
            BpfHelper::MsgPullData,
            0,
            0x1_0000_0000,
            "helper 'bpf_msg_pull_data' requires arg2 end to be between 0 and u32::MAX",
        ),
        (
            BpfHelper::MsgPushData,
            -1,
            8,
            "message data reshaping helpers require arg1 start to be between 0 and u32::MAX",
        ),
        (
            BpfHelper::MsgPushData,
            0x1_0000_0000,
            8,
            "message data reshaping helpers require arg1 start to be between 0 and u32::MAX",
        ),
        (
            BpfHelper::MsgPushData,
            0,
            -1,
            "message data reshaping helpers require arg2 len to be between 0 and u32::MAX",
        ),
        (
            BpfHelper::MsgPushData,
            0,
            0x1_0000_0000,
            "message data reshaping helpers require arg2 len to be between 0 and u32::MAX",
        ),
        (
            BpfHelper::MsgPopData,
            -1,
            8,
            "message data reshaping helpers require arg1 start to be between 0 and u32::MAX",
        ),
        (
            BpfHelper::MsgPopData,
            0x1_0000_0000,
            8,
            "message data reshaping helpers require arg1 start to be between 0 and u32::MAX",
        ),
        (
            BpfHelper::MsgPopData,
            0,
            -1,
            "message data reshaping helpers require arg2 len to be between 0 and u32::MAX",
        ),
        (
            BpfHelper::MsgPopData,
            0,
            0x1_0000_0000,
            "message data reshaping helpers require arg2 len to be between 0 and u32::MAX",
        ),
    ] {
        let (func, types) = make_msg_data_verify_call_with_range(helper, start, end_or_len, 0);
        let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected message data helper u32 range error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "{} start={start} end_or_len={end_or_len} produced unexpected errors: {:?}",
            helper.name(),
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_msg_pull_data_rejects_invalid_range() {
    for (start, end) in [(8, 8), (9, 8)] {
        let (func, types) =
            make_msg_data_verify_call_with_range(BpfHelper::MsgPullData, start, end, 0);
        let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected bpf_msg_pull_data range error");
        assert!(
            err.iter().any(|e| e.message.contains(
                "helper 'bpf_msg_pull_data' requires arg2 end to be greater than arg1 start"
            )),
            "start={start} end={end} produced unexpected errors: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_msg_data_helpers_allow_reloaded_packet_pointers() {
    for helper in [
        BpfHelper::MsgPullData,
        BpfHelper::MsgPushData,
        BpfHelper::MsgPopData,
    ] {
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
                helper: helper as u32,
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
        verify_mir_for_probe_context(&func, &types, &probe_ctx).unwrap_or_else(|err| {
            panic!("{} produced unexpected errors: {:?}", helper.name(), err)
        });
    }
}

#[test]
fn test_verify_mir_for_probe_context_store_hdr_opt_invalidates_prior_packet_pointers() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let guarded = func.alloc_block();
    let mutate = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let op = func.alloc_vreg();
    let matches = func.alloc_vreg();
    let data = func.alloc_vreg();
    let access_end = func.alloc_vreg();
    let data_end = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

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
        rhs: MirValue::Const(BPF_SOCK_OPS_WRITE_HDR_OPT_CB),
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
    func.block_mut(guarded).instructions.push(MirInst::BinOp {
        dst: access_end,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(data),
        rhs: MirValue::Const(1),
    });
    func.block_mut(guarded)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data_end,
            field: CtxField::DataEnd,
            slot: None,
        });
    func.block_mut(guarded).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Le,
        lhs: MirValue::VReg(access_end),
        rhs: MirValue::VReg(data_end),
    });
    func.block_mut(guarded).terminator = MirInst::Branch {
        cond,
        if_true: mutate,
        if_false: done,
    };

    func.block_mut(mutate)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(mutate)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::StoreHdrOpt as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(16),
                MirValue::Const(0),
            ],
        });
    func.block_mut(mutate).instructions.push(MirInst::Load {
        dst,
        ptr: data,
        offset: 0,
        ty: MirType::U8,
    });
    func.block_mut(mutate).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let packet_ptr = MirType::Ptr {
        pointee: Box::new(MirType::U8),
        address_space: AddressSpace::Packet,
    };
    let mut types = HashMap::new();
    types.insert(op, MirType::I32);
    types.insert(matches, MirType::Bool);
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

    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected stale packet pointer load to fail after store_hdr_opt");
    assert!(
        err.iter()
            .any(|e| e.message.contains("stale packet pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_packet_mutating_subfn_invalidates_prior_packet_pointers() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let load = func.alloc_block();
    let done = func.alloc_block();

    let data = func.alloc_vreg();
    let access_end = func.alloc_vreg();
    let data_end = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let call_ret = func.alloc_vreg();
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
    func.block_mut(load).instructions.push(MirInst::CallSubfn {
        dst: call_ret,
        subfn: SubfunctionId(0),
        args: vec![ctx],
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
    types.insert(call_ret, MirType::I64);
    types.insert(dst, MirType::U8);

    let mut subfn = MirFunction::new();
    let sub_entry = subfn.alloc_block();
    subfn.entry = sub_entry;
    subfn.param_count = 1;
    subfn.vreg_count = 1;
    let helper_ret = subfn.alloc_vreg();
    subfn
        .block_mut(sub_entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::MsgPushData as u32,
            args: vec![
                MirValue::VReg(VReg(0)),
                MirValue::Const(0),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
    subfn.block_mut(sub_entry).terminator = MirInst::Return { val: None };
    let summaries = infer_subfunction_summaries(&[subfn]);

    let probe_ctx = ProbeContext::new(EbpfProgramType::SkMsg, "/sys/fs/bpf/demo_sockmap");
    let err = verify_mir_with_subfunction_summaries_for_probe_context(
        &func,
        &types,
        &summaries,
        Some(&probe_ctx),
        None,
    )
    .expect_err("expected stale packet pointer load to fail after packet-mutating subfn");
    assert!(
        err.iter()
            .any(|e| e.message.contains("stale packet pointer")),
        "unexpected errors: {:?}",
        err
    );
}

