#[test]
fn test_helper_ringbuf_reserve_submit_releases_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let submit = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
    verify_mir(&func, &types).expect("expected ringbuf reference to be released");
}

#[test]
fn test_helper_ringbuf_reserve_vreg_size_positive_required() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
            helper: BpfHelper::RingbufReserve as u32,
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
            .any(|e| e.message.contains("helper 131 arg1 must be > 0")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_subfn_submit_releases_caller_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let submit = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let record = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let call_ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: record,
            helper: BpfHelper::RingbufReserve as u32,
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
        .push(MirInst::CallSubfn {
            dst: call_ret,
            subfn: crate::compiler::mir::SubfunctionId(0),
            args: vec![record],
        });
    func.block_mut(submit).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut subfn = MirFunction::new();
    let sub_entry = subfn.alloc_block();
    subfn.entry = sub_entry;
    subfn.param_count = 1;
    subfn.vreg_count = 1;
    let submit_ret = subfn.alloc_vreg();
    subfn
        .block_mut(sub_entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: submit_ret,
            helper: BpfHelper::RingbufSubmit as u32,
            args: vec![MirValue::VReg(VReg(0)), MirValue::Const(0)],
        });
    subfn.block_mut(sub_entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(call_ret, MirType::I64);
    let summaries = infer_subfunction_summaries(&[subfn]);
    verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect("expected subfunction submit to release caller ringbuf reference");
}

#[test]
fn test_helper_ringbuf_subfn_reserve_return_releases_caller_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let submit = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let record = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let submit_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst: record,
        subfn: SubfunctionId(0),
        args: vec![],
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
            helper: BpfHelper::RingbufSubmit as u32,
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
    func.block_mut(submit).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut subfn = MirFunction::new();
    let sub_entry = subfn.alloc_block();
    subfn.entry = sub_entry;
    let map_slot = subfn.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let reserved = subfn.alloc_vreg();
    subfn
        .block_mut(sub_entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: reserved,
            helper: BpfHelper::RingbufReserve as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
    subfn.block_mut(sub_entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(reserved)),
    };

    let mut types = HashMap::new();
    types.insert(submit_ret, MirType::I64);
    let summaries = infer_subfunction_summaries(&[subfn.clone()]);
    let summary = summaries
        .get(&SubfunctionId(0))
        .cloned()
        .expect("expected summary");
    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &subfn,
        &HashMap::new(),
        &summaries,
        Some(summary),
        None,
        None,
    )
    .expect("expected subfunction to return ringbuf record");
    verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect("expected caller to submit subfunction-reserved ringbuf record");
}

#[test]
fn test_helper_ringbuf_submit_rejected_after_partial_reserve_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let reserve_path = func.alloc_block();
    let join = func.alloc_block();
    let submit = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let select_cond = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let record = func.alloc_vreg();
    let submit_cond = func.alloc_vreg();
    let submit_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: select_cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: select_cond,
        if_true: reserve_path,
        if_false: join,
    };

    func.block_mut(reserve_path)
        .instructions
        .push(MirInst::CallHelper {
            dst: record,
            helper: BpfHelper::RingbufReserve as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
            ],
        });
    func.block_mut(reserve_path).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: submit_cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(record),
        rhs: MirValue::Const(0),
    });
    func.block_mut(join).terminator = MirInst::Branch {
        cond: submit_cond,
        if_true: submit,
        if_false: done,
    };

    func.block_mut(submit)
        .instructions
        .push(MirInst::CallHelper {
            dst: submit_ret,
            helper: BpfHelper::RingbufSubmit as u32,
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
    func.block_mut(submit).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(select_cond, MirType::Bool);
    types.insert(submit_cond, MirType::Bool);
    types.insert(submit_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected partial-join submit rejection");
    assert!(
        err.iter().any(|e| {
            e.message.contains("expects ringbuf record pointer")
                || e.message.contains("uninitialized")
        }),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_reserve_leak_is_rejected() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let leak = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let record = func.alloc_vreg();
    let cond = func.alloc_vreg();

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
        if_true: leak,
        if_false: done,
    };

    func.block_mut(leak).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected leak error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased ringbuf record reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_submit_requires_ringbuf_record_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
    let err = verify_mir(&func, &types).expect_err("expected ringbuf pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 132 arg0 expects ringbuf record pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_submit_discard_reject_invalid_flags() {
    for helper in [BpfHelper::RingbufSubmit, BpfHelper::RingbufDiscard] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let record = func.alloc_vreg();
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: record,
                helper: BpfHelper::RingbufReserve as u32,
                args: vec![
                    MirValue::StackSlot(map_slot),
                    MirValue::Const(8),
                    MirValue::Const(0),
                ],
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args: vec![MirValue::VReg(record), MirValue::Const(4)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);
        let err = verify_mir(&func, &types).expect_err("expected ringbuf flag validation error");
        assert!(
            err.iter().any(|e| e.message.contains(match helper {
                BpfHelper::RingbufSubmit => "helper 'bpf_ringbuf_submit' requires arg1 flags",
                BpfHelper::RingbufDiscard => "helper 'bpf_ringbuf_discard' requires arg1 flags",
                _ => unreachable!(),
            })),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_helper_ringbuf_submit_rejects_double_release() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let submit = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
        err.iter()
            .any(|e| e.message.contains("ringbuf record already released")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_submit_invalidates_record_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let submit = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
            .any(|e| e.message.contains("load requires pointer type")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_perf_event_output_rejects_user_ctx_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
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
            MirValue::Const(8),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

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
        err.iter().any(|e| e
            .message
            .contains("helper perf_event_output ctx expects pointer in [Kernel]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_get_stackid_rejects_user_ctx_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 27, // bpf_get_stackid(ctx, map, flags)
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(map_slot),
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
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper ctx pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_stackid ctx expects pointer in [Kernel]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_get_stack_rejects_user_ctx_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: BpfHelper::GetStack as u32,
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(buf_slot),
            MirValue::Const(0),
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
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper ctx pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_stack ctx expects pointer in [Kernel]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_tail_call_rejects_user_ctx_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 12, // bpf_tail_call(ctx, prog_array_map, index)
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(map_slot),
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
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper ctx pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper tail_call ctx expects pointer in [Kernel]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_tail_call_rejects_index_above_u32_max() {
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
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "dispatch".to_string(),
            kind: MapKind::ProgArray,
        },
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::TailCall as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::VReg(map),
                MirValue::Const(0x1_0000_0000),
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

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::Xdp.info())
        .expect_err("expected helper tail_call index range error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_tail_call' requires arg2 index to be between 0 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_tail_call_rejects_pointer_index() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
            .any(|e| e.message.contains("tail_call index expects scalar")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_tail_call_rejects_index_above_u32_max() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    func.block_mut(entry).terminator = MirInst::TailCall {
        prog_map: MapRef {
            name: "jumps".to_string(),
            kind: MapKind::ProgArray,
        },
        index: MirValue::Const(0x1_0000_0000),
    };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected tail-call index range error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_tail_call' requires arg2 index to be between 0 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_tail_call_rejects_non_prog_array_map_kind() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
            .any(|e| e.message.contains("tail_call requires prog-array map")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_get_current_comm_requires_positive_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let buf = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
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

    let err = verify_mir(&func, &types).expect_err("expected non-positive size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 16 arg1 must be > 0"))
    );
}

#[test]
fn test_helper_get_current_comm_checks_dst_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let buf = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
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

    let err = verify_mir(&func, &types).expect_err("expected helper dst bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_current_comm dst out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_get_current_comm_verify_call(size: i64) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let buf = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 16, // bpf_get_current_comm(buf, size)
            args: vec![MirValue::StackSlot(buf), MirValue::Const(size)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);
    (func, types)
}

#[test]
fn test_helper_get_current_comm_rejects_out_of_range_size() {
    for size in [-1_i64, 0x1_0000_0000] {
        let (func, types) = make_get_current_comm_verify_call(size);
        let err =
            verify_mir(&func, &types).expect_err("expected get_current_comm size range error");
        assert!(
            err.iter().any(|e| e.message.contains(
                "helper 'bpf_get_current_comm' requires arg1 size to be between 1 and u32::MAX"
            )),
            "unexpected errors for size {size}: {:?}",
            err
        );
    }
}

#[test]
fn test_helper_trace_printk_requires_positive_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let fmt = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
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

    let err = verify_mir(&func, &types).expect_err("expected non-positive size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 6 arg1 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_trace_printk_checks_fmt_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let fmt = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
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

    let err = verify_mir(&func, &types).expect_err("expected helper fmt bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper trace_printk fmt out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_trace_printk_verify_call(
    fmt_size: i64,
    fmt_slot_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let fmt = func.alloc_stack_slot(fmt_slot_size, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::TracePrintk as u32,
            args: vec![MirValue::StackSlot(fmt), MirValue::Const(fmt_size)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_helper_trace_printk_rejects_fmt_size_over_u32() {
    let (func, types) = make_trace_printk_verify_call(0x1_0000_0000, 8);
    let err = verify_mir(&func, &types).expect_err("expected trace_printk size range error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("trace print helpers require arg1 fmt_size to be between 1 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_trace_printk_rejects_user_fmt_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let fmt = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(fmt),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 6, // bpf_trace_printk(fmt, fmt_size, ...)
        args: vec![MirValue::VReg(fmt), MirValue::Const(8)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

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
        err.iter().any(|e| e
            .message
            .contains("helper trace_printk fmt expects pointer in [Stack, Map]")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_trace_vprintk_verify_call(
    fmt_size: i64,
    fmt_slot_size: usize,
    data_len: i64,
    data_slot_size: usize,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let fmt = func.alloc_stack_slot(fmt_slot_size, 8, StackSlotKind::StringBuffer);
    let data = func.alloc_stack_slot(data_slot_size, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::TraceVPrintk as u32,
            args: vec![
                MirValue::StackSlot(fmt),
                MirValue::Const(fmt_size),
                MirValue::StackSlot(data),
                MirValue::Const(data_len),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    (func, types)
}

#[test]
fn test_helper_trace_vprintk_verifies() {
    let (func, types) = make_trace_vprintk_verify_call(8, 8, 16, 16);
    verify_mir(&func, &types).expect("expected trace_vprintk helper to verify");
}

#[test]
fn test_helper_trace_vprintk_accepts_zero_size_null_data() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let fmt = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::TraceVPrintk as u32,
            args: vec![
                MirValue::StackSlot(fmt),
                MirValue::Const(8),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([(dst, MirType::I64)]);
    verify_mir(&func, &types).expect("expected trace_vprintk zero-size null data to verify");
}

#[test]
fn test_helper_trace_vprintk_rejects_zero_fmt_size() {
    let (func, types) = make_trace_vprintk_verify_call(0, 8, 16, 16);
    let err = verify_mir(&func, &types).expect_err("expected trace_vprintk zero-size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 177 arg1 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_trace_vprintk_checks_data_bounds() {
    let (func, types) = make_trace_vprintk_verify_call(8, 8, 16, 8);
    let err = verify_mir(&func, &types).expect_err("expected trace_vprintk data bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper trace_vprintk data out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_trace_vprintk_rejects_invalid_data_len() {
    let (func, types) = make_trace_vprintk_verify_call(8, 8, 10, 16);
    let err = verify_mir(&func, &types).expect_err("expected trace_vprintk data-len error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_trace_vprintk' requires arg3 to be a multiple of 8")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_trace_vprintk_rejects_size_out_of_range() {
    for (fmt_size, data_len, expected) in [
        (
            0x1_0000_0000,
            16,
            "trace print helpers require arg1 fmt_size to be between 1 and u32::MAX",
        ),
        (
            8,
            104,
            "helper 'bpf_trace_vprintk' requires arg3 data_len to be between 0 and MAX_BPRINTF_VARARGS * 8 (96 bytes)",
        ),
    ] {
        let (func, types) = make_trace_vprintk_verify_call(fmt_size, 8, data_len, 16);
        let err = verify_mir(&func, &types).expect_err("expected trace_vprintk size range error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "expected {expected:?}, got {err:?}"
        );
    }
}

#[test]
fn test_helper_get_current_comm_variable_size_range_checks_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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

    let err = verify_mir(&func, &types).expect_err("expected helper dst bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_current_comm dst out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_sysctl_get_current_value_accepts_cgroup_sysctl_context() {
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
fn test_verify_mir_helper_sysctl_get_current_value_rejects_small_stack_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
    assert!(err.iter().any(|e| {
        e.message
            .contains("helper sysctl_get_current_value buf out of bounds")
    }));
}

#[test]
fn test_helper_get_current_comm_variable_size_range_within_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
fn test_helper_probe_read_user_str_rejects_stack_src() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
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

    let err = verify_mir(&func, &types).expect_err("expected user source pointer error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper probe_read src expects pointer in [User]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_probe_read_user_rejects_stack_src() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
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

    let err = verify_mir(&func, &types).expect_err("expected user source pointer error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper probe_read src expects pointer in [User]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_output_checks_data_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
        err.iter().any(|e| e
            .message
            .contains("helper ringbuf_output data out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_output_accepts_zero_size_null_data() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::RingbufOutput as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected ringbuf_output with null zero-size data to verify");
}

#[test]
fn test_helper_ringbuf_rejects_invalid_flags() {
    let cases = [
        (
            BpfHelper::RingbufOutput,
            "helper 'bpf_ringbuf_output' requires arg3 flags",
        ),
        (
            BpfHelper::RingbufReserve,
            "helper 'bpf_ringbuf_reserve' requires arg2 flags",
        ),
        (
            BpfHelper::RingbufReserveDynptr,
            "helper 'bpf_ringbuf_reserve_dynptr' requires arg2 flags",
        ),
        (
            BpfHelper::RingbufQuery,
            "helper 'bpf_ringbuf_query' requires arg1 flags",
        ),
    ];

    for (helper, expected) in cases {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();
        let args = match helper {
            BpfHelper::RingbufOutput => vec![
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(data_slot),
                MirValue::Const(8),
                MirValue::Const(4),
            ],
            BpfHelper::RingbufReserve => vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(1),
            ],
            BpfHelper::RingbufReserveDynptr => vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(1),
                MirValue::StackSlot(data_slot),
            ],
            BpfHelper::RingbufQuery => vec![MirValue::StackSlot(map_slot), MirValue::Const(5)],
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

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);
        let err = verify_mir(&func, &types).expect_err("expected ringbuf flag validation error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_helper_ringbuf_reserve_helpers_reject_zero_size() {
    let cases = [BpfHelper::RingbufReserve, BpfHelper::RingbufReserveDynptr];

    for helper in cases {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();
        let args = match helper {
            BpfHelper::RingbufReserve => vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
            BpfHelper::RingbufReserveDynptr => vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::StackSlot(dynptr_slot),
            ],
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

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);
        let err = verify_mir(&func, &types).expect_err("expected ringbuf reserve zero-size error");
        let expected = format!("helper {} arg1 must be > 0", helper as u32);
        assert!(
            err.iter().any(|e| e.message.contains(&expected)),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_helper_ringbuf_reserve_dynptr_rejects_size_above_u32_max() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::RingbufReserveDynptr as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(0x1_0000_0000),
                MirValue::Const(0),
                MirValue::StackSlot(dynptr_slot),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);
    let err =
        verify_mir(&func, &types).expect_err("expected ringbuf_reserve_dynptr size range error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_ringbuf_reserve_dynptr' requires arg1 size to be between 0 and u32::MAX"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_update_rejects_user_key_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call_block = func.alloc_block();
    let exit_block = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(key),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call_block,
        if_false: exit_block,
    };

    func.block_mut(call_block)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 2, // bpf_map_update_elem(map, key, value, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::VReg(key),
                MirValue::StackSlot(value_slot),
                MirValue::Const(0),
            ],
        });
    func.block_mut(call_block).terminator = MirInst::Return { val: None };

    func.block_mut(exit_block).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        key,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected map key pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper map_update key expects pointer in [Stack, Map]")),
        "unexpected errors: {:?}",
        err
    );
}
