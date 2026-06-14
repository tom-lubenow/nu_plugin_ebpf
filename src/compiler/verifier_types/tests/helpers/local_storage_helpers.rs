#[test]
fn test_helper_get_local_storage_accepts_zero_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let storage = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: storage,
            helper: BpfHelper::GetLocalStorage as u32,
            args: vec![MirValue::StackSlot(map_slot), MirValue::Const(0)],
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

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected bpf_get_local_storage zero flags to verify");
}

#[test]
fn test_helper_get_local_storage_rejects_unrepresentable_value_type_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let storage = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: storage,
            helper: BpfHelper::GetLocalStorage as u32,
            args: vec![MirValue::StackSlot(map_slot), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        storage,
        MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U64),
                len: usize::MAX,
            }),
            address_space: AddressSpace::Map,
        },
    );

    let probe_ctx = ProbeContext::new(EbpfProgramType::CgroupSkb, "/sys/fs/cgroup:ingress");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected unrepresentable helper return bounds rejection");
    assert!(
        err.iter().any(|e| {
            e.message
                .contains("get_local_storage return value type size")
                && e.message.contains("representable verifier bounds")
        }),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_get_local_storage_rejects_nonzero_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let storage = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: storage,
            helper: BpfHelper::GetLocalStorage as u32,
            args: vec![MirValue::StackSlot(map_slot), MirValue::Const(1)],
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
        verify_mir(&func, &types).expect_err("expected bpf_get_local_storage flags to be rejected");
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper 'bpf_get_local_storage' requires arg1 flags to be 0")
    }));
}

#[test]
fn test_helper_get_local_storage_rejects_non_cgroup_program() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let storage = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: storage,
            helper: BpfHelper::GetLocalStorage as u32,
            args: vec![MirValue::StackSlot(map_slot), MirValue::Const(0)],
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

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_get_local_storage kprobe policy error");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "helper 'bpf_get_local_storage' is only valid in cgroup_device, cgroup_skb, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, cgroup_sysctl, and sock_ops programs",
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
