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
fn test_verify_mir_for_probe_context_get_socket_cookie_accepts_returned_socket_filter_context() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst: ctx,
        subfn: SubfunctionId(0),
        args: vec![],
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::GetSocketCookie as u32,
            args: vec![MirValue::VReg(ctx)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut subfn = MirFunction::new();
    let sub_entry = subfn.alloc_block();
    subfn.entry = sub_entry;
    let sub_ctx = subfn.alloc_vreg();
    subfn
        .block_mut(sub_entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: sub_ctx,
            field: CtxField::Context,
            slot: None,
        });
    subfn.block_mut(sub_entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(sub_ctx)),
    };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let summaries = infer_subfunction_summaries(&[subfn]);
    let probe_ctx = ProbeContext::new(EbpfProgramType::SocketFilter, "udp4:127.0.0.1:31337");
    verify_mir_with_subfunction_summaries_for_probe_context(
        &func,
        &types,
        &summaries,
        Some(&probe_ctx),
        None,
    )
    .expect("expected returned get_socket_cookie socket_filter context to verify");
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
fn test_verify_mir_for_probe_context_skb_helper_rejects_socket_field_alias() {
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
            helper: BpfHelper::SkbPullData as u32,
            args: vec![MirValue::VReg(sk), MirValue::Const(0)],
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

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected skb helper to reject non-raw context alias");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_skb_pull_data' arg0 expects raw context pointer")
    }));
}

#[test]
fn test_verify_mir_helper_raw_context_arg_rejects_helper_return_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let stack_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
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
            helper: BpfHelper::GetStack as u32,
            args: vec![
                MirValue::VReg(task),
                MirValue::StackSlot(stack_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(task, MirType::named_kernel_struct_ptr("task_struct"));
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected helper-return pointer to fail raw context helper arg");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_get_stack' arg0 expects raw context pointer")
    }));
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
fn test_verify_mir_for_probe_context_get_current_ancestor_cgroup_id_rejects_invalid_level() {
    for level in [-1, i64::from(i32::MAX) + 1] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: BpfHelper::GetCurrentAncestorCgroupId as u32,
                args: vec![MirValue::Const(level)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "vfs_read");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected bpf_get_current_ancestor_cgroup_id level range error");
        assert!(
            err.iter().any(|e| e.message.contains(
                "ancestor cgroup helpers require ancestor_level to be between 0 and i32::MAX"
            )),
            "unexpected errors for level {level}: {:?}",
            err
        );
    }
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
                    .chain(args)
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
            dst,
            helper: helper as u32,
            args: std::iter::once(MirValue::VReg(sock))
                .chain(args)
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

fn cgroup_membership_map_ref_ty() -> MirType {
    MirType::MapRef {
        key_ty: Box::new(MirType::U32),
        val_ty: Box::new(MirType::U32),
    }
}

fn make_cgroup_membership_verify_call(
    helper: BpfHelper,
    idx: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let mut types = HashMap::new();
    types.insert(map, cgroup_membership_map_ref_ty());
    types.insert(dst, MirType::I64);

    match helper {
        BpfHelper::SkbUnderCgroup => {
            let ctx = func.alloc_vreg();
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
                        MirValue::VReg(map),
                        MirValue::Const(idx),
                    ],
                });
            types.insert(
                ctx,
                MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Kernel,
                },
            );
        }
        BpfHelper::CurrentTaskUnderCgroup => {
            func.block_mut(entry)
                .instructions
                .push(MirInst::CallHelper {
                    dst,
                    helper: helper as u32,
                    args: vec![MirValue::VReg(map), MirValue::Const(idx)],
                });
        }
        _ => panic!("unexpected cgroup membership helper {helper:?}"),
    }
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    (func, types)
}

fn cgroup_membership_verify_probe_context(helper: BpfHelper) -> ProbeContext {
    match helper {
        BpfHelper::SkbUnderCgroup => ProbeContext::new(EbpfProgramType::Tc, "lo:ingress"),
        BpfHelper::CurrentTaskUnderCgroup => ProbeContext::new(EbpfProgramType::Xdp, "lo"),
        _ => panic!("unexpected cgroup membership helper {helper:?}"),
    }
}

#[test]
fn test_verify_mir_for_probe_context_cgroup_membership_helpers_reject_invalid_idx() {
    for helper in [BpfHelper::SkbUnderCgroup, BpfHelper::CurrentTaskUnderCgroup] {
        for idx in [-1_i64, 0x1_0000_0000] {
            let (func, types) = make_cgroup_membership_verify_call(helper, idx);
            let probe_ctx = cgroup_membership_verify_probe_context(helper);
            let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
                .expect_err("expected cgroup membership helper idx range error");
            assert!(
                err.iter().any(|e| e.message.contains(
                    "cgroup membership helpers require idx to be between 0 and u32::MAX"
                )),
                "unexpected errors for {helper:?} idx {idx}: {:?}",
                err
            );
        }
    }
}

#[test]
fn test_verify_mir_for_probe_context_sk_ancestor_cgroup_id_rejects_invalid_level() {
    for level in [-1, i64::from(i32::MAX) + 1] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let sk = func.alloc_vreg();
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: BpfHelper::SkAncestorCgroupId as u32,
                args: vec![MirValue::VReg(sk), MirValue::Const(level)],
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

        let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected bpf_sk_ancestor_cgroup_id level range error");
        assert!(
            err.iter().any(|e| e.message.contains(
                "ancestor cgroup helpers require ancestor_level to be between 0 and i32::MAX"
            )),
            "unexpected errors for level {level}: {:?}",
            err
        );
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
                    .chain(extra_args)
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
fn test_verify_mir_for_probe_context_skb_ancestor_cgroup_id_rejects_invalid_level() {
    for level in [-1, i64::from(i32::MAX) + 1] {
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
                helper: BpfHelper::SkbAncestorCgroupId as u32,
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

        let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:egress");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected bpf_skb_ancestor_cgroup_id level range error");
        assert!(
            err.iter().any(|e| e.message.contains(
                "ancestor cgroup helpers require ancestor_level to be between 0 and i32::MAX"
            )),
            "unexpected errors for level {level}: {:?}",
            err
        );
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
                    .chain(extra_args)
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
                    .chain(extra_args)
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
    let (func, types) = make_redirect_verify_call(1, 1);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected xdp redirect flags error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_redirect' requires arg1 = 0 in xdp programs")
    }));
}

fn make_redirect_verify_call(ifindex: i64, flags: i64) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::Redirect as u32,
            args: vec![MirValue::Const(ifindex), MirValue::Const(flags)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_for_program_redirect_rejects_invalid_ifindex() {
    for ifindex in [-1_i64, 0x1_0000_0000] {
        let (func, types) = make_redirect_verify_call(ifindex, 0);
        let err = verify_mir_for_program(&func, &types, EbpfProgramType::Tc.info())
            .expect_err("expected bpf_redirect ifindex to be rejected");
        assert!(
            err.iter().any(|e| e.message.contains(
                "helper 'bpf_redirect' requires arg0 ifindex to be between 0 and u32::MAX"
            )),
            "unexpected errors for ifindex {ifindex}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_program_redirect_allows_non_zero_flags_outside_xdp() {
    let (func, types) = make_redirect_verify_call(1, 1);

    verify_mir_for_program(&func, &types, EbpfProgramType::Tc.info())
        .expect("expected tc redirect flags to remain allowed");
}

fn make_sockopt_helper_verify_call(
    helper: BpfHelper,
    optlen: i64,
    optval_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let optval_slot = func.alloc_stack_slot(optval_size, 8, StackSlotKind::StringBuffer);
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
                MirValue::Const(optlen),
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
        let (func, types) = make_sockopt_helper_verify_call(helper, 16, 16);
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected sockopt helper program-surface error");
        assert!(err.iter().any(|e| e.message.contains(expected)));
    }
}

#[test]
fn test_verify_mir_for_probe_context_sockopt_helpers_reject_optlen_above_i32_max() {
    for helper in [BpfHelper::SetSockOpt, BpfHelper::GetSockOpt] {
        let (func, types) = make_sockopt_helper_verify_call(helper, 0x8000_0000, 16);
        let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected sockopt helper optlen bounds error");
        assert!(
            err.iter().any(|e| e.message.contains(
                "socket option helpers require arg4 optlen to be between 1 and i32::MAX"
            )),
            "unexpected errors for helper {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_sockopt_helpers_reject_zero_optlen() {
    for (helper, expected) in [
        (BpfHelper::SetSockOpt, "helper 49 arg4 must be > 0"),
        (BpfHelper::GetSockOpt, "helper 57 arg4 must be > 0"),
    ] {
        let (func, types) = make_sockopt_helper_verify_call(helper, 0, 16);
        let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockopt, "/sys/fs/cgroup:get");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected sockopt helper positive optlen error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "expected {expected:?}, got {err:?}"
        );
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
fn test_verify_mir_for_probe_context_set_retval_rejects_retval_outside_i32_range() {
    for retval in [(i32::MAX as i64) + 1, (i32::MIN as i64) - 1] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: BpfHelper::SetRetval as u32,
                args: vec![MirValue::Const(retval)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        let probe_ctx =
            ProbeContext::new(EbpfProgramType::CgroupSock, "/sys/fs/cgroup:sock_create");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected bpf_set_retval retval range error");
        assert!(
            err.iter().any(|e| e.message.contains(
                "helper 'bpf_set_retval' requires arg0 retval to be between i32::MIN and i32::MAX"
            )),
            "unexpected errors for retval {retval}: {:?}",
            err
        );
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

fn make_bind_helper_verify_call(
    addr_len: i64,
    addr_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let addr_slot = func.alloc_stack_slot(addr_size, 8, StackSlotKind::StringBuffer);
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
                MirValue::Const(addr_len),
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
fn test_verify_mir_for_probe_context_bind_helper_rejects_invalid_program_or_attach() {
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
        let (func, types) = make_bind_helper_verify_call(16, 16);
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected bind helper program-surface error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "unexpected errors: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_bind_helper_rejects_addr_len_above_i32_max() {
    let (func, types) = make_bind_helper_verify_call(0x8000_0000, 16);
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bind helper addr_len bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_bind' requires arg2 addr_len to be between 1 and i32::MAX")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_bind_helper_rejects_zero_addr_len() {
    let (func, types) = make_bind_helper_verify_call(0, 16);
    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bind helper positive addr_len error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 64 arg2 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_bind_helper_accepts_cgroup_sock_addr_connect() {
    for probe_ctx in [
        ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect4"),
        ProbeContext::new(EbpfProgramType::CgroupSockAddr, "/sys/fs/cgroup:connect6"),
    ] {
        let (func, types) = make_bind_helper_verify_call(16, 16);
        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected bind helper to verify on cgroup_sock_addr connect hooks");
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
fn test_verify_mir_for_program_socket_redirect_map_helpers_reject_key_above_u32_max() {
    for (helper, program_info) in [
        (BpfHelper::MsgRedirectMap, EbpfProgramType::SkMsg.info()),
        (BpfHelper::SkRedirectMap, EbpfProgramType::SkSkb.info()),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ctx = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
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
                    MirValue::StackSlot(map_slot),
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

        let err = verify_mir_for_program(&func, &types, program_info)
            .expect_err("expected socket redirect map key range error");
        assert!(
            err.iter().any(|e| e.message.contains(
                "socket redirect map helpers require arg2 key to be between 0 and u32::MAX"
            )),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_program_sk_select_reuseport_rejects_nonzero_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
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
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SkSelectReuseport as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(key_slot),
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

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::SkReuseport.info())
        .expect_err("expected sk_select_reuseport helper invalid flags error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_sk_select_reuseport' requires arg3 flags to be 0")
    }));
}

#[test]
fn test_verify_mir_for_probe_context_socket_map_helpers_accept_supported_contexts() {
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
        (
            BpfHelper::SkSelectReuseport,
            ProbeContext::new(EbpfProgramType::SkReuseport, "select"),
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

        verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect("expected socket-map helper to verify in supported context");
    }
}

#[test]
fn test_helper_sock_map_update_rejects_out_of_bounds_key_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::SockOps.info())
        .expect_err("expected socket-map key bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper sock_map_update key out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_sock_ops_callback_sensitive_helpers_reject_invalid_program() {
    for (helper, expected) in [
        (
            BpfHelper::SockOpsCbFlagsSet,
            "helper 'bpf_sock_ops_cb_flags_set' is only valid in sock_ops programs",
        ),
        (
            BpfHelper::LoadHdrOpt,
            "helper 'bpf_load_hdr_opt' is only valid in sock_ops programs",
        ),
        (
            BpfHelper::StoreHdrOpt,
            "helper 'bpf_store_hdr_opt' is only valid in sock_ops programs",
        ),
        (
            BpfHelper::ReserveHdrOpt,
            "helper 'bpf_reserve_hdr_opt' is only valid in sock_ops programs",
        ),
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

        let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected sock_ops helper program-surface error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_sock_ops_callback_sensitive_helpers_without_static_callback_proof()
 {
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

    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected sock_ops cb_flags_set helper to verify without callback proof");
}

fn make_guarded_sock_ops_hdr_opt_verify_call(
    helper: BpfHelper,
    len: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let callback_op = match helper {
        BpfHelper::LoadHdrOpt => BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,
        BpfHelper::StoreHdrOpt => BPF_SOCK_OPS_WRITE_HDR_OPT_CB,
        BpfHelper::ReserveHdrOpt => BPF_SOCK_OPS_HDR_OPT_LEN_CB,
        _ => unreachable!("expected sock_ops header-option helper"),
    };

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
            MirValue::Const(len),
            MirValue::Const(0),
        ],
        BpfHelper::ReserveHdrOpt => vec![
            MirValue::VReg(ctx),
            MirValue::Const(len),
            MirValue::Const(0),
        ],
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

    (func, types)
}

#[test]
fn test_verify_mir_for_probe_context_sock_ops_hdr_opt_helpers_reject_len_outside_kernel_range() {
    for (helper, expected) in [
        (
            BpfHelper::LoadHdrOpt,
            "TCP header option helpers require arg2 len to be between 2 and u32::MAX",
        ),
        (
            BpfHelper::StoreHdrOpt,
            "TCP header option helpers require arg2 len to be between 2 and u32::MAX",
        ),
        (
            BpfHelper::ReserveHdrOpt,
            "helper 'bpf_reserve_hdr_opt' requires arg1 len to be between 2 and u32::MAX",
        ),
    ] {
        for len in [1, 0x1_0000_0000] {
            let (func, types) = make_guarded_sock_ops_hdr_opt_verify_call(helper, len);
            let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
            let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
                .expect_err("expected sock_ops header-option len range error");
            assert!(
                err.iter().any(|e| e.message.contains(expected)),
                "unexpected errors for {helper:?} len {len}: {:?}",
                err
            );
        }
    }
}

#[test]
fn test_verify_mir_for_probe_context_sock_ops_hdr_opt_helpers_reject_zero_len() {
    for (helper, size_arg) in [
        (BpfHelper::LoadHdrOpt, 2),
        (BpfHelper::StoreHdrOpt, 2),
        (BpfHelper::ReserveHdrOpt, 1),
    ] {
        let (func, types) = make_guarded_sock_ops_hdr_opt_verify_call(helper, 0);
        let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected sock_ops header-option zero-len error");
        let expected = format!("helper {} arg{size_arg} must be > 0", helper as u32);
        assert!(
            err.iter().any(|e| e.message.contains(&expected)),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_sock_ops_hdr_opt_helpers_without_static_callback_proof() {
    for (helper, expected) in [
        (
            BpfHelper::LoadHdrOpt,
            "helper 'bpf_load_hdr_opt' without BPF_LOAD_HDR_OPT_TCP_SYN requires proving a packet-data ctx.op callback",
        ),
        (
            BpfHelper::StoreHdrOpt,
            "helper 'bpf_store_hdr_opt' requires proving ctx.op == BPF_SOCK_OPS_WRITE_HDR_OPT_CB",
        ),
        (
            BpfHelper::ReserveHdrOpt,
            "helper 'bpf_reserve_hdr_opt' requires proving ctx.op == BPF_SOCK_OPS_HDR_OPT_LEN_CB",
        ),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;
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

        let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected sock_ops header-option helper to require callback proof");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_for_probe_context_load_hdr_opt_accepts_tcp_syn_flag_without_callback_proof() {
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
                MirValue::Const(BPF_LOAD_HDR_OPT_TCP_SYN),
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
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected bpf_load_hdr_opt TCP_SYN mode to verify without callback proof");
}

#[test]
fn test_verify_mir_for_probe_context_load_hdr_opt_accepts_guarded_tcp_syn_vreg_without_callback_proof()
 {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let guarded = func.alloc_block();
    let done = func.alloc_block();
    let flags = func.alloc_vreg();
    let matches = func.alloc_vreg();
    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: flags,
            helper: BpfHelper::GetPrandomU32 as u32,
            args: vec![],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: matches,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(flags),
        rhs: MirValue::Const(BPF_LOAD_HDR_OPT_TCP_SYN),
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
            helper: BpfHelper::LoadHdrOpt as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(buf_slot),
                MirValue::Const(16),
                MirValue::VReg(flags),
            ],
        });
    func.block_mut(guarded).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(flags, MirType::U32);
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
        .expect("expected guarded bpf_load_hdr_opt TCP_SYN flag to verify without callback proof");
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
    let dst_null = func.alloc_vreg();
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
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: dst_null,
            helper: BpfHelper::PerfEventOutput as u32,
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
    types.insert(dst_null, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::LwtOut, "demo-route");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected perf_event_output helper in lwt_out program");
}

fn make_perf_event_output_verify_call(
    flags: i64,
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
                MirValue::Const(flags),
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
fn test_verify_mir_for_probe_context_perf_event_output_rejects_invalid_flags() {
    for flags in [-1, 0x1_0000_0000] {
        let (func, types) = make_perf_event_output_verify_call(flags, 8, 8);
        let probe_ctx = ProbeContext::new(EbpfProgramType::LwtOut, "demo-route");
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected perf_event_output flags error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("perf output helpers require arg2 flags")),
            "unexpected errors for flags {flags}: {:?}",
            err
        );
    }
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

fn make_perf_prog_read_value_verify_call(
    size: i64,
    buf_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(buf_size, 8, StackSlotKind::StringBuffer);

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
            helper: BpfHelper::PerfProgReadValue as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(buf_slot),
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
