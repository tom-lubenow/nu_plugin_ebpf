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

fn make_copy_from_user_null_dst_verify_call(
    size: i64,
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
    let ret = func.alloc_vreg();
    let task = with_task.then(|| func.alloc_vreg());

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
            MirValue::Const(0),
            MirValue::Const(size),
            MirValue::VReg(src),
            MirValue::VReg(task),
            MirValue::Const(flags),
        ]
    } else {
        vec![
            MirValue::Const(0),
            MirValue::Const(size),
            MirValue::VReg(src),
        ]
    };
    func.block_mut(call_block)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
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
    types.insert(ret, MirType::I64);

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

fn make_probe_read_kernel_verify_call(
    size: i64,
    buf_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ret = func.alloc_vreg();
    let dst_slot = func.alloc_stack_slot(buf_size, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(buf_size, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::ProbeReadKernel as u32,
            args: vec![
                MirValue::StackSlot(dst_slot),
                MirValue::Const(size),
                MirValue::StackSlot(src_slot),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ret, MirType::I64);

    (func, types)
}

fn make_probe_read_kernel_null_dst_verify_call(size: i64) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ret = func.alloc_vreg();
    let src_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::ProbeReadKernel as u32,
            args: vec![
                MirValue::Const(0),
                MirValue::Const(size),
                MirValue::StackSlot(src_slot),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
fn test_verify_mir_helper_copy_from_user_accepts_zero_size_null_dst() {
    let (func, types) = make_copy_from_user_null_dst_verify_call(0, false, 0);
    verify_mir(&func, &types).expect("expected bpf_copy_from_user null dst with zero size");
}

#[test]
fn test_verify_mir_helper_copy_from_user_task_accepts_zero_size_null_dst() {
    let (func, types) = make_copy_from_user_null_dst_verify_call(0, true, 0);
    verify_mir(&func, &types).expect("expected bpf_copy_from_user_task null dst with zero size");
}

#[test]
fn test_verify_mir_helper_probe_write_user_accepts_user_dst() {
    let (func, types) = make_probe_write_user_verify_call(16, 16);
    verify_mir(&func, &types).expect("expected bpf_probe_write_user helper to verify");
}

#[test]
fn test_verify_mir_helper_probe_write_user_rejects_zero_size() {
    let (func, types) = make_probe_write_user_verify_call(0, 16);
    let err = verify_mir(&func, &types).expect_err("expected probe_write_user zero-size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 36 arg2 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_probe_read_kernel_accepts_zero_size_null_dst() {
    let (func, types) = make_probe_read_kernel_null_dst_verify_call(0);
    verify_mir(&func, &types).expect("expected zero-size bpf_probe_read_kernel null dst");
}

#[test]
fn test_verify_mir_helper_probe_read_kernel_rejects_nonzero_size_null_dst() {
    let (func, types) = make_probe_read_kernel_null_dst_verify_call(1);
    let err = verify_mir(&func, &types)
        .expect_err("expected nonzero-size bpf_probe_read_kernel null dst error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 113 arg0 requires arg1 = 0 when arg0 is null")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_probe_memory_rejects_size_over_u32() {
    let (func, types) = make_probe_read_kernel_verify_call(0x1_0000_0000, 16);
    let err = verify_mir(&func, &types).expect_err("expected probe_read size range error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("probe read helpers require arg1 size to be between 0 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );

    let (func, types) = make_probe_write_user_verify_call(0x1_0000_0000, 16);
    let err = verify_mir(&func, &types).expect_err("expected probe_write_user size range error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_probe_write_user' requires arg2 size to be between 1 and u32::MAX"
        )),
        "unexpected errors: {:?}",
        err
    );
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
fn test_verify_mir_helper_copy_from_user_rejects_size_over_u32() {
    for with_task in [false, true] {
        let (func, types) = make_copy_from_user_verify_call(0x1_0000_0000, 16, with_task, 0);
        let err = verify_mir(&func, &types).expect_err("expected copy_from_user range error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("copy-from-user helpers require arg1 size to be between 0 and u32::MAX")),
            "unexpected errors for with_task={with_task}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_helper_copy_from_user_rejects_null_dst_with_nonzero_size() {
    let (func, types) = make_copy_from_user_null_dst_verify_call(8, false, 0);
    let err = verify_mir(&func, &types).expect_err("expected copy_from_user null dst size error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 148 arg0 requires arg1 = 0 when arg0 is null")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_copy_from_user_task_rejects_null_dst_with_nonzero_size() {
    let (func, types) = make_copy_from_user_null_dst_verify_call(8, true, 0);
    let err =
        verify_mir(&func, &types).expect_err("expected copy_from_user_task null dst size error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 191 arg0 requires arg1 = 0 when arg0 is null")),
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

