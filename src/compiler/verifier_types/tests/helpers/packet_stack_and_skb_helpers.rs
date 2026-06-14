fn make_packet_output_verify_call(
    helper: BpfHelper,
    size: i64,
    data_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    make_packet_output_verify_call_with_arg0(
        helper,
        0,
        size,
        data_size,
        CtxField::Context,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    )
}

fn kernel_struct_ptr(name: &str) -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::opaque_named_struct(name)),
        address_space: AddressSpace::Kernel,
    }
}

fn make_packet_output_verify_call_with_arg0(
    helper: BpfHelper,
    flags: i64,
    size: i64,
    data_size: usize,
    arg0_field: CtxField,
    arg0_type: MirType,
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
            field: arg0_field,
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
                MirValue::Const(flags),
                MirValue::StackSlot(data_slot),
                MirValue::Const(size),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ctx, arg0_type);
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

fn make_packet_output_verify_null_data_call_with_arg0(
    helper: BpfHelper,
    arg0_field: CtxField,
    arg0_type: MirType,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: arg0_field,
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
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ctx, arg0_type);
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
fn test_verify_mir_for_probe_context_packet_output_helpers_accept_typed_packet_args() {
    for (helper, arg0_type, probe_ctx) in [
        (
            BpfHelper::SkbOutput,
            kernel_struct_ptr("sk_buff"),
            ProbeContext::new(EbpfProgramType::Fentry, "netif_receive_skb"),
        ),
        (
            BpfHelper::XdpOutput,
            kernel_struct_ptr("xdp_buff"),
            ProbeContext::new(EbpfProgramType::Fentry, "xdp_do_redirect"),
        ),
    ] {
        let (func, types) =
            make_packet_output_verify_call_with_arg0(helper, 0, 8, 8, CtxField::Arg(0), arg0_type);
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected packet output helper to verify");
    }
}

#[test]
fn test_verify_mir_for_probe_context_packet_output_helpers_accept_zero_size_null_data() {
    for (helper, arg0_type, probe_ctx) in [
        (
            BpfHelper::SkbOutput,
            kernel_struct_ptr("sk_buff"),
            ProbeContext::new(EbpfProgramType::Fentry, "netif_receive_skb"),
        ),
        (
            BpfHelper::XdpOutput,
            kernel_struct_ptr("xdp_buff"),
            ProbeContext::new(EbpfProgramType::Fentry, "xdp_do_redirect"),
        ),
    ] {
        let (func, types) =
            make_packet_output_verify_null_data_call_with_arg0(helper, CtxField::Arg(0), arg0_type);
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected packet output helper to verify with null zero-size data");
    }
}

#[test]
fn test_verify_mir_for_probe_context_packet_output_helpers_reject_raw_context() {
    for (helper, probe_ctx, expected) in [
        (
            BpfHelper::SkbOutput,
            ProbeContext::new(EbpfProgramType::Fentry, "netif_receive_skb"),
            "helper 'bpf_skb_output' arg0 expects sk_buff pointer",
        ),
        (
            BpfHelper::XdpOutput,
            ProbeContext::new(EbpfProgramType::Fentry, "xdp_do_redirect"),
            "helper 'bpf_xdp_output' arg0 expects xdp_buff pointer",
        ),
    ] {
        let (func, types) = make_packet_output_verify_call(helper, 8, 8);
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected raw tracing context to fail packet output arg0");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
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
    let (func, types) = make_packet_output_verify_call_with_arg0(
        BpfHelper::SkbOutput,
        0,
        16,
        8,
        CtxField::Arg(0),
        kernel_struct_ptr("sk_buff"),
    );
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
fn test_verify_mir_for_probe_context_packet_output_helpers_reject_invalid_flags() {
    for (helper, arg0_type, probe_ctx) in [
        (
            BpfHelper::SkbOutput,
            kernel_struct_ptr("sk_buff"),
            ProbeContext::new(EbpfProgramType::Fentry, "netif_receive_skb"),
        ),
        (
            BpfHelper::XdpOutput,
            kernel_struct_ptr("xdp_buff"),
            ProbeContext::new(EbpfProgramType::Fentry, "xdp_do_redirect"),
        ),
    ] {
        for flags in [-1, 0x1_0000_0000] {
            let (func, types) = make_packet_output_verify_call_with_arg0(
                helper,
                flags,
                8,
                8,
                CtxField::Arg(0),
                arg0_type.clone(),
            );
            let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
                .expect_err("expected packet output flags error");
            assert!(
                err.iter()
                    .any(|e| e.message.contains("perf output helpers require arg2 flags")),
                "unexpected errors for {helper:?} flags {flags}: {:?}",
                err
            );
        }
    }
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
fn test_verify_mir_get_stack_allows_zero_size_null_buffer() {
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
            helper: BpfHelper::GetStack as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(0),
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

    verify_mir_for_program(&func, &types, EbpfProgramType::Kprobe.info())
        .expect("expected get_stack zero-size null buffer to pass");
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
fn test_verify_mir_get_stack_rejects_build_id_without_user_stack() {
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
                MirValue::Const(0x0800),
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
        .expect_err("expected get_stack build-id flag combination error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "stack-copy helpers require BPF_F_USER_STACK when BPF_F_USER_BUILD_ID is set"
        )),
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
        err.iter().any(|e| e
            .message
            .contains("stack-copy helpers require arg2 size to be between 0 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_get_stack_rejects_size_over_u32() {
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
                MirValue::Const(0x1_0000_0000),
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
        .expect_err("expected get_stack size range error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("stack-copy helpers require arg2 size to be between 0 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_get_stack_accepts_variable_zero_to_slot_size_range() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let size = func.alloc_vreg();
    func.param_count = 1;
    let ctx = func.alloc_vreg();
    let ge_zero = func.alloc_vreg();
    let le_slot = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ge_zero,
        op: BinOpKind::Ge,
        lhs: MirValue::VReg(size),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: ge_zero,
        if_true: check_upper,
        if_false: done,
    };

    func.block_mut(check_upper)
        .instructions
        .push(MirInst::BinOp {
            dst: le_slot,
            op: BinOpKind::Le,
            lhs: MirValue::VReg(size),
            rhs: MirValue::Const(32),
        });
    func.block_mut(check_upper).terminator = MirInst::Branch {
        cond: le_slot,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetStack as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(buf_slot),
            MirValue::VReg(size),
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
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    verify_mir_for_program(&func, &types, EbpfProgramType::Kprobe.info())
        .expect("expected bounded zero-inclusive get_stack size range to pass");
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
                    .chain(args)
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
fn test_verify_mir_for_program_skb_vlan_push_rejects_invalid_u16_args() {
    for (arg_idx, bad_value, message) in [
        (
            1,
            -1_i64,
            "helper 'bpf_skb_vlan_push' requires arg1 vlan_proto to be between 0 and u16::MAX",
        ),
        (
            1,
            0x1_0000,
            "helper 'bpf_skb_vlan_push' requires arg1 vlan_proto to be between 0 and u16::MAX",
        ),
        (
            2,
            -1_i64,
            "helper 'bpf_skb_vlan_push' requires arg2 vlan_tci to be between 0 and u16::MAX",
        ),
        (
            2,
            0x1_0000,
            "helper 'bpf_skb_vlan_push' requires arg2 vlan_tci to be between 0 and u16::MAX",
        ),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let mut args = vec![
            MirValue::VReg(ctx),
            MirValue::Const(0x8100),
            MirValue::Const(1),
        ];
        args[arg_idx] = MirValue::Const(bad_value);

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
                helper: BpfHelper::SkbVlanPush as u32,
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

        let err = verify_mir_for_program(&func, &types, EbpfProgramType::SkSkb.info())
            .expect_err("expected bpf_skb_vlan_push u16 arg to be rejected");
        assert!(
            err.iter().any(|e| e.message.contains(message)),
            "unexpected errors for arg{arg_idx}={bad_value}: {:?}",
            err
        );
    }
}

fn make_csum_update_verify_call(csum: i64) -> (MirFunction, HashMap<VReg, MirType>) {
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
            helper: BpfHelper::CsumUpdate as u32,
            args: vec![MirValue::VReg(ctx), MirValue::Const(csum)],
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
fn test_verify_mir_for_program_csum_update_rejects_invalid_csum() {
    for csum in [-1_i64, 0x1_0000_0000] {
        let (func, types) = make_csum_update_verify_call(csum);
        let err = verify_mir_for_program(&func, &types, EbpfProgramType::Tc.info())
            .expect_err("expected bpf_csum_update csum range error");
        assert!(
            err.iter().any(|e| e.message.contains(
                "helper 'bpf_csum_update' requires arg1 csum to be between 0 and u32::MAX"
            )),
            "unexpected errors for csum {csum}: {:?}",
            err
        );
    }
}

fn make_set_hash_verify_call(hash: i64) -> (MirFunction, HashMap<VReg, MirType>) {
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
            helper: BpfHelper::SetHash as u32,
            args: vec![MirValue::VReg(ctx), MirValue::Const(hash)],
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
fn test_verify_mir_for_program_set_hash_rejects_invalid_hash() {
    for hash in [-1_i64, 0x1_0000_0000] {
        let (func, types) = make_set_hash_verify_call(hash);
        let err = verify_mir_for_program(&func, &types, EbpfProgramType::Tc.info())
            .expect_err("expected bpf_set_hash hash to be rejected");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("helper 'bpf_set_hash' requires arg1 hash to be between 0 and u32::MAX")),
            "unexpected errors for hash {hash}: {:?}",
            err
        );
    }
}

fn make_clone_redirect_verify_call(
    ifindex: i64,
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
            helper: BpfHelper::CloneRedirect as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(ifindex),
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
fn test_verify_mir_for_program_clone_redirect_rejects_invalid_ifindex() {
    for ifindex in [-1_i64, 0x1_0000_0000] {
        let (func, types) = make_clone_redirect_verify_call(ifindex, 0);
        let err = verify_mir_for_program(&func, &types, EbpfProgramType::Tc.info())
            .expect_err("expected bpf_clone_redirect ifindex to be rejected");
        assert!(
            err.iter().any(|e| e.message.contains(
                "helper 'bpf_clone_redirect' requires arg1 ifindex to be between 0 and u32::MAX"
            )),
            "unexpected errors for ifindex {ifindex}: {:?}",
            err
        );
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
                    .chain(args)
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

fn make_skb_adjust_room_verify_call(mode: i64) -> (MirFunction, HashMap<VReg, MirType>) {
    make_skb_adjust_room_verify_call_with_flags(mode, 0)
}

fn make_skb_adjust_room_verify_call_with_flags(
    mode: i64,
    flags: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    make_skb_adjust_room_verify_call_with_len_diff(14, mode, flags)
}

fn make_skb_adjust_room_verify_call_with_len_diff(
    len_diff: i64,
    mode: i64,
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
            helper: BpfHelper::SkbAdjustRoom as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(len_diff),
                MirValue::Const(mode),
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
fn test_verify_mir_for_probe_context_skb_adjust_room_rejects_invalid_mode() {
    let (func, types) = make_skb_adjust_room_verify_call(2);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_adjust_room mode to be rejected");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_skb_adjust_room' requires arg2 mode")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_skb_adjust_room_rejects_len_diff_out_of_range() {
    for len_diff in [0x1000_i64, -0x1000] {
        let (func, types) = make_skb_adjust_room_verify_call_with_len_diff(len_diff, 0, 0);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected bpf_skb_adjust_room len_diff to be rejected");
        assert!(
            err.iter().any(|e| e.message.contains(
                "helper 'bpf_skb_adjust_room' requires arg1 len_diff to be between -0xfff and 0xfff"
            )),
            "unexpected errors for len_diff {len_diff}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_skb_adjust_room_rejects_invalid_flags() {
    let (func, types) = make_skb_adjust_room_verify_call_with_flags(0, 1 << 20);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_adjust_room flags to be rejected");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_skb_adjust_room' requires arg3 flags to contain only modeled BPF_F_ADJ_ROOM_* bits"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_skb_adjust_room_rejects_incompatible_flags() {
    let (func, types) = make_skb_adjust_room_verify_call_with_flags(0, 0x18);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_adjust_room incompatible flags to be rejected");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_skb_adjust_room' requires at most one BPF_F_ADJ_ROOM_ENCAP_L4_* flag"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_skb_adjust_room_rejects_sk_skb_nonzero_mode_and_flags() {
    let (func, types) = make_skb_adjust_room_verify_call_with_flags(1, 1);
    let probe_ctx = ProbeContext::new(EbpfProgramType::SkSkb, "/sys/fs/bpf/demo_sockmap");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected sk_skb bpf_skb_adjust_room mode/flags to be rejected");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_skb_adjust_room' requires arg2 mode = 0 in sk_skb programs")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_skb_adjust_room' requires arg3 flags = 0 in sk_skb programs")),
        "unexpected errors: {:?}",
        err
    );
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
    make_skb_change_proto_verify_call_with_proto(0x86dd, flags)
}

fn make_skb_change_proto_verify_call_with_proto(
    proto: i64,
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
            helper: BpfHelper::SkbChangeProto as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(proto),
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
    make_skb_change_type_verify_call_with_type(0)
}

fn make_skb_change_type_verify_call_with_type(
    pkt_type: i64,
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
            helper: BpfHelper::SkbChangeType as u32,
            args: vec![MirValue::VReg(ctx), MirValue::Const(pkt_type)],
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
fn test_verify_mir_for_probe_context_skb_change_proto_rejects_invalid_proto() {
    let (func, types) = make_skb_change_proto_verify_call_with_proto(0x0806, 0);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_change_proto proto to be rejected");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_skb_change_proto' requires arg1 proto to be ETH_P_IP or ETH_P_IPV6"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_skb_change_type_rejects_invalid_type() {
    let (func, types) = make_skb_change_type_verify_call_with_type(4);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_skb_change_type type to be rejected");
    assert!(err.iter().any(|e| e.message.contains(
        "helper 'bpf_skb_change_type' requires arg1 type to be PACKET_HOST, PACKET_BROADCAST, PACKET_MULTICAST, or PACKET_OTHERHOST"
    )));
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

fn make_csum_replace_verify_call(
    helper: BpfHelper,
    offset: i64,
    from: i64,
    flags: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: helper as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::Const(offset),
                MirValue::Const(from),
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
fn test_verify_mir_for_probe_context_csum_replace_helpers_reject_invalid_flags() {
    for (helper, flags, expected) in [
        (
            BpfHelper::L3CsumReplace,
            0x10,
            "helper 'bpf_l3_csum_replace' requires arg4 flags",
        ),
        (
            BpfHelper::L4CsumReplace,
            0x100,
            "helper 'bpf_l4_csum_replace' requires arg4 flags",
        ),
        (
            BpfHelper::L3CsumReplace,
            0x01,
            "checksum replacement helpers require BPF_F_HDR_FIELD_MASK size",
        ),
        (
            BpfHelper::L4CsumReplace,
            0x06,
            "checksum replacement helpers require BPF_F_HDR_FIELD_MASK size",
        ),
    ] {
        let (func, types) = make_csum_replace_verify_call(helper, 0, 0, flags);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected checksum replacement helper flag validation error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "expected {expected:?}, got {err:?}"
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_csum_replace_helpers_reject_nonzero_from_with_diff_size() {
    for (helper, flags) in [
        (BpfHelper::L3CsumReplace, 0),
        (BpfHelper::L4CsumReplace, 0x10),
    ] {
        let (func, types) = make_csum_replace_verify_call(helper, 0, 1, flags);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected checksum replacement helper from validation error");
        assert!(
            err.iter().any(|e| e.message.contains(
                "checksum replacement helpers require arg2 from to be 0 when BPF_F_HDR_FIELD_MASK size is 0"
            )),
            "got {err:?}"
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_csum_replace_helpers_reject_invalid_offsets() {
    for (helper, offset, expected) in [
        (
            BpfHelper::L3CsumReplace,
            0x1,
            "checksum replacement helpers require arg1 offset to be even",
        ),
        (
            BpfHelper::L4CsumReplace,
            0x1_0000,
            "checksum replacement helpers require arg1 offset to be between 0 and 0xffff",
        ),
    ] {
        let (func, types) = make_csum_replace_verify_call(helper, offset, 0, 2);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected checksum replacement helper offset validation error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "expected {expected:?}, got {err:?}"
        );
    }
}

fn make_csum_level_verify_call(level: i64) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::CsumLevel as u32,
            args: vec![MirValue::VReg(ctx), MirValue::Const(level)],
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
fn test_verify_mir_for_probe_context_csum_level_helper_rejects_invalid_level() {
    let (func, types) = make_csum_level_verify_call(4);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_csum_level invalid level error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_csum_level' requires arg1 level")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_csum_diff_allows_null_zero_side() {
    for null_to in [false, true] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;
        let dst = func.alloc_vreg();
        let args = if null_to {
            let from_slot = func.alloc_stack_slot(4, 4, StackSlotKind::StringBuffer);
            vec![
                MirValue::StackSlot(from_slot),
                MirValue::Const(4),
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::Const(0),
            ]
        } else {
            let to_slot = func.alloc_stack_slot(4, 4, StackSlotKind::StringBuffer);
            vec![
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::StackSlot(to_slot),
                MirValue::Const(4),
                MirValue::Const(0),
            ]
        };

        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: BpfHelper::CsumDiff as u32,
                args,
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        for probe_ctx in [
            ProbeContext::new(EbpfProgramType::Xdp, "lo"),
            ProbeContext::new(EbpfProgramType::LwtOut, "demo-route"),
        ] {
            verify_mir_for_probe_context(&func, &types, &probe_ctx)
                .unwrap_or_else(|err| panic!("expected csum_diff null side to verify: {err:?}"));
        }
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

#[test]
fn test_verify_mir_read_branch_records_rejects_size_over_u32() {
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
                MirValue::Const(0x1_0000_0000),
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
        .expect_err("expected read_branch_records size range error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_read_branch_records' requires arg2 size to be between 0 and u32::MAX"
        )),
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
fn test_verify_mir_get_branch_snapshot_rejects_size_over_u32() {
    let (func, types) = make_get_branch_snapshot_verify_call(0x1_0000_0000, 8, 0);
    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected bpf_get_branch_snapshot size range error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_get_branch_snapshot' requires arg1 size to be between 0 and u32::MAX"
        )),
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

fn make_csum_diff_scalar_verify_call(
    arg_idx: usize,
    value: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let dst = func.alloc_vreg();
    let mut args = vec![
        MirValue::Const(0),
        MirValue::Const(0),
        MirValue::Const(0),
        MirValue::Const(0),
        MirValue::Const(0),
    ];
    args[arg_idx] = MirValue::Const(value);

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::CsumDiff as u32,
            args,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);
    (func, types)
}

#[test]
fn test_verify_mir_for_probe_context_csum_diff_rejects_out_of_range_scalars() {
    for (arg_idx, value, expected) in [
        (
            1,
            -4,
            "helper 'bpf_csum_diff' requires arg1 from_size to be between 0 and u32::MAX",
        ),
        (
            1,
            0x1_0000_0000,
            "helper 'bpf_csum_diff' requires arg1 from_size to be between 0 and u32::MAX",
        ),
        (
            3,
            -4,
            "helper 'bpf_csum_diff' requires arg3 to_size to be between 0 and u32::MAX",
        ),
        (
            3,
            0x1_0000_0000,
            "helper 'bpf_csum_diff' requires arg3 to_size to be between 0 and u32::MAX",
        ),
        (
            4,
            -1,
            "helper 'bpf_csum_diff' requires arg4 seed to be between 0 and u32::MAX",
        ),
        (
            4,
            0x1_0000_0000,
            "helper 'bpf_csum_diff' requires arg4 seed to be between 0 and u32::MAX",
        ),
    ] {
        let (func, types) = make_csum_diff_scalar_verify_call(arg_idx, value);
        let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected csum_diff scalar range validation error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "unexpected errors for arg{arg_idx}={value}: {:?}",
            err
        );
    }
}

fn make_lirc_scalar_verify_call(
    helper: BpfHelper,
    scalar_args: Vec<MirValue>,
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

    let mut args = vec![MirValue::VReg(ctx)];
    args.extend(scalar_args);
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
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Kernel,
            },
        ),
        (dst, MirType::I64),
    ]);
    (func, types)
}

#[test]
fn test_verify_mir_for_probe_context_lirc_helpers_reject_out_of_range_scalars() {
    for (helper, scalar_args, expected) in [
        (
            BpfHelper::RcKeydown,
            vec![
                MirValue::Const(0x1_0000_0000),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
            "helper 'bpf_rc_keydown' requires arg1 protocol to be between 0 and u32::MAX",
        ),
        (
            BpfHelper::RcKeydown,
            vec![
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::Const(0x1_0000_0000),
            ],
            "helper 'bpf_rc_keydown' requires arg3 toggle to be between 0 and u32::MAX",
        ),
        (
            BpfHelper::RcPointerRel,
            vec![MirValue::Const(i32::MAX as i64 + 1), MirValue::Const(0)],
            "helper 'bpf_rc_pointer_rel' requires arg1 rel_x to be between i32::MIN and i32::MAX",
        ),
        (
            BpfHelper::RcPointerRel,
            vec![MirValue::Const(0), MirValue::Const(i32::MIN as i64 - 1)],
            "helper 'bpf_rc_pointer_rel' requires arg2 rel_y to be between i32::MIN and i32::MAX",
        ),
    ] {
        let (func, types) = make_lirc_scalar_verify_call(helper, scalar_args);
        let probe_ctx = ProbeContext::new(EbpfProgramType::LircMode2, "/dev/lirc0");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected lirc scalar range validation error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}
