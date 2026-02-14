use super::*;

#[test]
fn test_verify_mir_helper_map_lookup_rejects_out_of_bounds_key_pointer() {
    let (mut func, entry) = new_mir_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key_base = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key_base,
        src: MirValue::StackSlot(key_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: key,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(key_base),
        rhs: MirValue::Const(8),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::VReg(map), MirValue::VReg(key)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper key bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ringbuf_output_checks_data_bounds() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ringbuf_reserve_vreg_size_positive_required() {
    let (mut func, entry) = new_mir_function();
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
            helper: 131, // bpf_ringbuf_reserve(map, size, flags)
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
            .any(|e| e.kind == VccErrorKind::UnsupportedInstruction),
        "expected helper size error, got {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 131 arg1 must be > 0")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ringbuf_reserve_submit_ok() {
    let (mut func, entry) = new_mir_function();
    let submit = func.alloc_block();
    let done = func.alloc_block();
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
    verify_mir(&func, &types).expect("expected ringbuf submit flow to pass");
}

#[test]
fn test_verify_mir_helper_ringbuf_reserve_submit_ok_with_eq_null_branch() {
    let (mut func, entry) = new_mir_function();
    let submit = func.alloc_block();
    let done = func.alloc_block();
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
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(record),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: done,
        if_false: submit,
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
    verify_mir(&func, &types).expect("expected ringbuf submit flow to pass");
}

#[test]
fn test_verify_mir_helper_ringbuf_reserve_without_release_rejected() {
    let (mut func, entry) = new_mir_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let record = func.alloc_vreg();

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
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new())
        .expect_err("expected leak error for unreleased ringbuf record");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased ringbuf record reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ringbuf_submit_requires_null_check() {
    let (mut func, entry) = new_mir_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let record = func.alloc_vreg();
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
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: submit_ret,
            helper: 132, // bpf_ringbuf_submit(data, flags)
            args: vec![MirValue::VReg(record), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(submit_ret, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected missing null-check error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("may dereference null pointer")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ringbuf_submit_rejects_double_release() {
    let (mut func, entry) = new_mir_function();
    let submit = func.alloc_block();
    let done = func.alloc_block();
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
        err.iter().any(|e| {
            e.message.contains("ringbuf record already released")
                || e.message
                    .contains("ringbuf release requires pointer operand")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ringbuf_submit_invalidates_record_pointer() {
    let (mut func, entry) = new_mir_function();
    let submit = func.alloc_block();
    let done = func.alloc_block();
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
            .any(|e| e.message.contains("load requires pointer operand")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ringbuf_submit_rejects_map_lookup_pointer() {
    let (mut func, entry) = new_mir_function();
    let submit = func.alloc_block();
    let done = func.alloc_block();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let submit_ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ptr,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr),
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
            args: vec![MirValue::VReg(ptr), MirValue::Const(0)],
        });
    func.block_mut(submit).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(submit_ret, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected ringbuf pointer provenance error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("expects ringbuf record pointer, got Map")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_ringbuf_submit_rejects_stack_pointer() {
    let (mut func, entry) = new_mir_function();
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
    let err = verify_mir(&func, &types).expect_err("expected ringbuf pointer provenance error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("expects ringbuf record pointer, got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_perf_event_output_rejects_user_ctx_pointer() {
    let (mut func, entry) = new_mir_function();
    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
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
    func.block_mut(entry).terminator = MirInst::Return { val: None };

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
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper perf_event_output ctx expects pointer in [Kernel]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_perf_event_output_variable_size_range_checks_bounds() {
    let (mut func, entry) = new_mir_function();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let ctx = func.alloc_vreg();
    let size = func.alloc_vreg();
    func.param_count = 2;
    let ge_one = func.alloc_vreg();
    let le_sixteen = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
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
        helper: 25, // bpf_perf_event_output(ctx, map, flags, data, size)
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(map_slot),
            MirValue::Const(0),
            MirValue::StackSlot(data_slot),
            MirValue::VReg(size),
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

    let err = verify_mir(&func, &types).expect_err("expected helper bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper perf_event_output data out of bounds")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_perf_event_output_variable_size_range_within_bounds() {
    let (mut func, entry) = new_mir_function();
    let check_ctx = func.alloc_block();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let ctx = func.alloc_vreg();
    let size = func.alloc_vreg();
    func.param_count = 2;
    let ctx_non_null = func.alloc_vreg();
    let ge_one = func.alloc_vreg();
    let le_eight = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ctx_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: ctx_non_null,
        if_true: check_ctx,
        if_false: done,
    };

    func.block_mut(check_ctx).instructions.push(MirInst::BinOp {
        dst: ge_one,
        op: BinOpKind::Ge,
        lhs: MirValue::VReg(size),
        rhs: MirValue::Const(1),
    });
    func.block_mut(check_ctx).terminator = MirInst::Branch {
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
        helper: 25, // bpf_perf_event_output(ctx, map, flags, data, size)
        args: vec![
            MirValue::VReg(ctx),
            MirValue::StackSlot(map_slot),
            MirValue::Const(0),
            MirValue::StackSlot(data_slot),
            MirValue::VReg(size),
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

    verify_mir(&func, &types).expect("expected bounded helper size range to pass");
}

#[test]
fn test_verify_mir_helper_get_stackid_rejects_user_ctx_pointer() {
    let (mut func, entry) = new_mir_function();
    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 27, // bpf_get_stackid(ctx, map, flags)
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

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
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_stackid ctx expects pointer in [Kernel]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_tail_call_rejects_user_ctx_pointer() {
    let (mut func, entry) = new_mir_function();
    let ctx = func.alloc_vreg();
    func.param_count = 1;
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 12, // bpf_tail_call(ctx, prog_array_map, index)
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

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
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper tail_call ctx expects pointer in [Kernel]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_tail_call_rejects_pointer_index() {
    let (mut func, entry) = new_mir_function();
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
            .any(|e| matches!(e.kind, VccErrorKind::TypeMismatch { .. })),
        "expected type mismatch error, got {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("expected scalar value")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_tail_call_rejects_non_prog_array_map_kind() {
    let (mut func, entry) = new_mir_function();
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
            .any(|e| e.kind == VccErrorKind::UnsupportedInstruction
                && e.message.contains("tail_call requires ProgArray map")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_get_current_comm_positive_size_required() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    let buf = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

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

    let err = verify_mir(&func, &types).expect_err("expected helper size error");
    assert!(
        err.iter()
            .any(|e| e.kind == VccErrorKind::UnsupportedInstruction),
        "expected helper size error, got {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 16 arg1 must be > 0")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_get_current_comm_bounds() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    let buf = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

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

    let err = verify_mir(&func, &types).expect_err("expected helper bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_trace_printk_positive_size_required() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    let fmt = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

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

    let err = verify_mir(&func, &types).expect_err("expected helper size error");
    assert!(
        err.iter()
            .any(|e| e.kind == VccErrorKind::UnsupportedInstruction),
        "expected helper size error, got {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 6 arg1 must be > 0")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_trace_printk_bounds() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    let fmt = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

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

    let err = verify_mir(&func, &types).expect_err("expected helper bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_trace_printk_rejects_user_fmt_pointer() {
    let (mut func, entry) = new_mir_function();
    let fmt = func.alloc_vreg();
    func.param_count = 1;
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 6, // bpf_trace_printk(fmt, fmt_size, ...)
            args: vec![MirValue::VReg(fmt), MirValue::Const(8)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

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
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper trace_printk fmt expects pointer in [Stack, Map]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_get_current_comm_variable_size_range_checks_bounds() {
    let (mut func, entry) = new_mir_function();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();

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

    let err = verify_mir(&func, &types).expect_err("expected helper bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_current_comm dst out of bounds")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_get_current_comm_variable_size_range_within_bounds() {
    let (mut func, entry) = new_mir_function();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();

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
fn test_verify_mir_helper_probe_read_variable_size_range_checks_bounds() {
    let (mut func, entry) = new_mir_function();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let size = func.alloc_vreg();
    func.param_count = 1;
    let ge_one = func.alloc_vreg();
    let le_sixteen = func.alloc_vreg();
    let dst_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
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
        helper: 4, // bpf_probe_read(dst, size, src)
        args: vec![
            MirValue::StackSlot(dst_slot),
            MirValue::VReg(size),
            MirValue::StackSlot(src_slot),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper dst bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper probe_read dst out of bounds")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_probe_read_variable_size_range_within_bounds() {
    let (mut func, entry) = new_mir_function();
    let check_upper = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let size = func.alloc_vreg();
    func.param_count = 1;
    let ge_one = func.alloc_vreg();
    let le_eight = func.alloc_vreg();
    let dst_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
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
        helper: 4, // bpf_probe_read(dst, size, src)
        args: vec![
            MirValue::StackSlot(dst_slot),
            MirValue::VReg(size),
            MirValue::StackSlot(src_slot),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);
    verify_mir(&func, &types).expect("expected bounded helper size range to pass");
}

#[test]
fn test_verify_mir_helper_probe_read_user_str_rejects_stack_src() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

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

    let err = verify_mir(&func, &types).expect_err("expected helper source space error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper probe_read src expects pointer in [User]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_map_update_rejects_user_key() {
    let (mut func, entry) = new_mir_function();
    let key = func.alloc_vreg();
    func.param_count = 1;
    let dst = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let val_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 2, // bpf_map_update_elem(map, key, value, flags)
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::VReg(key),
                MirValue::StackSlot(val_slot),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        key,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper key space error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper map_update key expects pointer in [Stack, Map]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_unknown_helper_rejects_more_than_five_args() {
    let (mut func, entry) = new_mir_function();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 9999,
            args: vec![
                MirValue::Const(0),
                MirValue::Const(1),
                MirValue::Const(2),
                MirValue::Const(3),
                MirValue::Const(4),
                MirValue::Const(5),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper-argument count rejection");
    assert!(
        err.iter()
            .any(|e| e.kind == VccErrorKind::UnsupportedInstruction
                && e.message.contains("at most 5 arguments")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_rejects_more_than_five_params() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 6;
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected param-count error");
    assert!(
        err.iter()
            .any(|e| e.kind == VccErrorKind::UnsupportedInstruction
                && e.message.contains("at most 5 arguments")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_rejects_subfn_calls_with_more_than_five_args() {
    let (mut func, entry) = new_mir_function();
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
            .any(|e| e.kind == VccErrorKind::UnsupportedInstruction
                && e.message.contains("at most 5 arguments")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_kptr_xchg_allows_null_const_arg1() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let dst_ptr = func.alloc_vreg();
    let dst_non_null = func.alloc_vreg();
    let swapped = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: dst_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(dst_ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: dst_non_null,
        if_true: call,
        if_false: done,
    };
    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: swapped,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::Const(0)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(dst_non_null, MirType::Bool);
    types.insert(
        swapped,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    verify_mir(&func, &types).expect("expected kptr_xchg null-pointer arg acceptance");
}

#[test]
fn test_verify_mir_helper_kptr_xchg_rejects_non_null_scalar_arg1() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let dst_ptr = func.alloc_vreg();
    let dst_non_null = func.alloc_vreg();
    let swapped = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: dst_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(dst_ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: dst_non_null,
        if_true: call,
        if_false: done,
    };
    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: swapped,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::Const(1)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(dst_non_null, MirType::Bool);
    types.insert(
        swapped,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected helper pointer-arg rejection");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 194 arg1 expects pointer value")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_kptr_xchg_rejects_non_map_dst_arg0() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let dst_ptr = func.alloc_vreg();
    let swapped = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: swapped,
            helper: BpfHelper::KptrXchg as u32,
            args: vec![MirValue::VReg(dst_ptr), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        swapped,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err =
        verify_mir(&func, &types).expect_err("expected kptr_xchg map-pointer destination error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper kptr_xchg dst expects pointer in [Map]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_kptr_xchg_transfers_reference_and_releases_old_value() {
    let (mut func, entry) = new_mir_function();
    let acquire = func.alloc_block();
    let swap = func.alloc_block();
    let release_old = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let dst_ptr = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let dst_non_null = func.alloc_vreg();
    let swapped = func.alloc_vreg();
    let swapped_non_null = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: dst_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(dst_ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: dst_non_null,
        if_true: acquire,
        if_false: done,
    };

    func.block_mut(acquire).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(acquire)
        .instructions
        .push(MirInst::CallKfunc {
            dst: task,
            kfunc: "bpf_task_from_pid".to_string(),
            btf_id: None,
            args: vec![pid],
        });
    func.block_mut(acquire).instructions.push(MirInst::BinOp {
        dst: task_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(acquire).terminator = MirInst::Branch {
        cond: task_non_null,
        if_true: swap,
        if_false: done,
    };

    func.block_mut(swap).instructions.push(MirInst::CallHelper {
        dst: swapped,
        helper: BpfHelper::KptrXchg as u32,
        args: vec![MirValue::VReg(dst_ptr), MirValue::VReg(task)],
    });
    func.block_mut(swap).instructions.push(MirInst::BinOp {
        dst: swapped_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(swapped),
        rhs: MirValue::Const(0),
    });
    func.block_mut(swap).terminator = MirInst::Branch {
        cond: swapped_non_null,
        if_true: release_old,
        if_false: done,
    };

    func.block_mut(release_old)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![swapped],
        });
    func.block_mut(release_old).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(task_non_null, MirType::Bool);
    types.insert(dst_non_null, MirType::Bool);
    types.insert(
        swapped,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(swapped_non_null, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected kptr_xchg transfer/release semantics");
}

#[test]
fn test_verify_mir_helper_sk_lookup_release_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let lookup = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let ctx = func.alloc_vreg();
    let ctx_non_null = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ctx_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: ctx_non_null,
        if_true: lookup,
        if_false: done,
    };

    func.block_mut(lookup)
        .instructions
        .push(MirInst::CallHelper {
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
    func.block_mut(lookup).instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(lookup).terminator = MirInst::Branch {
        cond: sock_non_null,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallHelper {
            dst: release_ret,
            helper: BpfHelper::SkRelease as u32,
            args: vec![MirValue::VReg(sock)],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
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
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(sock_non_null, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected sk_lookup/sk_release socket lifetime to verify");
}

#[test]
fn test_verify_mir_helper_sk_release_rejects_non_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let bad_release_ret = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallHelper {
            dst: bad_release_ret,
            helper: BpfHelper::SkRelease as u32,
            args: vec![MirValue::VReg(task)],
        });
    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: cleanup_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
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
    types.insert(bad_release_ret, MirType::I64);
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected sk_release ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc release expects socket reference, got task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_sk_fullsock_rejects_non_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let fullsock = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        dst: fullsock,
        helper: BpfHelper::SkFullsock as u32,
        args: vec![MirValue::VReg(task)],
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
        fullsock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected sk_fullsock ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 95 arg0 expects socket reference, got task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_tcp_sock_rejects_non_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let tcp_sock = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        dst: tcp_sock,
        helper: BpfHelper::TcpSock as u32,
        args: vec![MirValue::VReg(task)],
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
        tcp_sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected tcp_sock ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 96 arg0 expects socket reference, got task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_skc_to_tcp_sock_rejects_non_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let tcp_sock = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        dst: tcp_sock,
        helper: BpfHelper::SkcToTcpSock as u32,
        args: vec![MirValue::VReg(task)],
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
        tcp_sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected skc_to_tcp_sock ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 137 arg0 expects socket reference, got task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_get_listener_sock_rejects_non_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let task_non_null = func.alloc_vreg();
    let listener = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();

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
        dst: listener,
        helper: BpfHelper::GetListenerSock as u32,
        args: vec![MirValue::VReg(task)],
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
        listener,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cleanup_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected get_listener_sock ref-kind mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 98 arg0 expects socket reference, got task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_get_listener_sock_rejects_non_kernel_pointer() {
    let (mut func, entry) = new_mir_function();

    let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let listener = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: listener,
            helper: BpfHelper::GetListenerSock as u32,
            args: vec![MirValue::StackSlot(sock_slot)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        listener,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected get_listener_sock pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper get_listener_sock sk expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_sk_fullsock_rejects_non_kernel_pointer() {
    let (mut func, entry) = new_mir_function();

    let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let fullsock = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: fullsock,
            helper: BpfHelper::SkFullsock as u32,
            args: vec![MirValue::StackSlot(sock_slot)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        fullsock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected sk_fullsock pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper sk_fullsock sk expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_tcp_sock_rejects_non_kernel_pointer() {
    let (mut func, entry) = new_mir_function();

    let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let tcp_sock = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: tcp_sock,
            helper: BpfHelper::TcpSock as u32,
            args: vec![MirValue::StackSlot(sock_slot)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        tcp_sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected tcp_sock pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper tcp_sock sk expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_skc_to_tcp_sock_rejects_non_kernel_pointer() {
    let (mut func, entry) = new_mir_function();

    let sock_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let tcp_sock = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: tcp_sock,
            helper: BpfHelper::SkcToTcpSock as u32,
            args: vec![MirValue::StackSlot(sock_slot)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        tcp_sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected skc_to_tcp_sock pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper skc_to_tcp_sock sk expects pointer in [Kernel], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_sk_lookup_leak_is_rejected() {
    let (mut func, entry) = new_mir_function();
    let leak = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let ctx = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sock,
            helper: BpfHelper::SkLookupUdp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(tuple_slot),
                MirValue::Const(16),
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
        if_true: leak,
        if_false: done,
    };

    func.block_mut(leak).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
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

    let err = verify_mir(&func, &types).expect_err("expected leaked socket reference error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("unreleased kfunc reference at function exit")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_skc_lookup_release_socket_reference() {
    let (mut func, entry) = new_mir_function();
    let lookup = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let ctx = func.alloc_vreg();
    let ctx_non_null = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ctx_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: ctx_non_null,
        if_true: lookup,
        if_false: done,
    };

    func.block_mut(lookup)
        .instructions
        .push(MirInst::CallHelper {
            dst: sock,
            helper: BpfHelper::SkcLookupTcp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(tuple_slot),
                MirValue::Const(16),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(lookup).instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(lookup).terminator = MirInst::Branch {
        cond: sock_non_null,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallHelper {
            dst: release_ret,
            helper: BpfHelper::SkRelease as u32,
            args: vec![MirValue::VReg(sock)],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
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
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(sock_non_null, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected skc_lookup/sk_release socket lifetime to verify");
}
