#[test]
fn test_kfunc_scx_events_buffer_requires_stack_or_map_space() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call_block = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let events_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(64),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(events_ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call_block,
        if_false: done,
    };
    func.block_mut(call_block)
        .instructions
        .push(MirInst::CallKfunc {
            dst,
            kfunc: "scx_bpf_events".to_string(),
            btf_id: None,
            args: vec![events_ptr, size],
        });
    func.block_mut(call_block).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        events_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected scx_bpf_events buffer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc scx_bpf_events events expects pointer in [Stack, Map], got Kernel")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_events_requires_positive_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let events_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let events_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: events_ptr,
        src: MirValue::StackSlot(events_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_events".to_string(),
        btf_id: None,
        args: vec![events_ptr, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        events_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected scx_bpf_events positive-size error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_events' arg1 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_events_requires_bounded_size_for_stack_buffer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let size = func.alloc_vreg();
    let events_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let events_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: events_ptr,
        src: MirValue::StackSlot(events_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_events".to_string(),
        btf_id: None,
        args: vec![events_ptr, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(size, MirType::I64);
    types.insert(
        events_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected scx_bpf_events bounded-size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 must have bounded upper range")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_events_accepts_stack_buffer_rule() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let events_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let events_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: events_ptr,
        src: MirValue::StackSlot(events_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(64),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_events".to_string(),
        btf_id: None,
        args: vec![events_ptr, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        events_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected scx_bpf_events stack-buffer rule to verify");
}

#[test]
fn test_kfunc_scx_dump_bstr_fmt_requires_stack_or_map_space() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call_block = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let fmt_ptr = func.alloc_vreg();
    let data_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let data_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: data_ptr,
        src: MirValue::StackSlot(data_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(16),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(fmt_ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call_block,
        if_false: done,
    };
    func.block_mut(call_block)
        .instructions
        .push(MirInst::CallKfunc {
            dst,
            kfunc: "scx_bpf_dump_bstr".to_string(),
            btf_id: None,
            args: vec![fmt_ptr, data_ptr, size],
        });
    func.block_mut(call_block).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        fmt_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        data_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected scx_bpf_dump_bstr fmt-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc scx_bpf_dump_bstr fmt expects pointer in [Stack, Map], got Kernel")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_dump_bstr_requires_positive_data_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let fmt_ptr = func.alloc_vreg();
    let data_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let fmt_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: fmt_ptr,
        src: MirValue::StackSlot(fmt_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: data_ptr,
        src: MirValue::StackSlot(data_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_dump_bstr".to_string(),
        btf_id: None,
        args: vec![fmt_ptr, data_ptr, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        fmt_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        data_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected scx_bpf_dump_bstr positive-size error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_dump_bstr' arg2 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_dump_bstr_requires_stack_slot_base_data() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let fmt_ptr = func.alloc_vreg();
    let data_base = func.alloc_vreg();
    let data_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let fmt_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: fmt_ptr,
        src: MirValue::StackSlot(fmt_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: data_base,
        src: MirValue::StackSlot(data_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: data_ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(data_base),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(16),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_dump_bstr".to_string(),
        btf_id: None,
        args: vec![fmt_ptr, data_ptr, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        fmt_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        data_base,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        data_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected scx_bpf_dump_bstr stack-slot-base error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects stack slot base pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_dump_bstr_accepts_stack_fmt_and_data() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let fmt_ptr = func.alloc_vreg();
    let data_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let fmt_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: fmt_ptr,
        src: MirValue::StackSlot(fmt_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: data_ptr,
        src: MirValue::StackSlot(data_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(16),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_dump_bstr".to_string(),
        btf_id: None,
        args: vec![fmt_ptr, data_ptr, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        fmt_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        data_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected scx_bpf_dump_bstr stack fmt/data rule to verify");
}

#[test]
fn test_kfunc_scx_error_bstr_requires_stack_slot_base_fmt() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let fmt_base = func.alloc_vreg();
    let fmt_ptr = func.alloc_vreg();
    let data_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let fmt_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: fmt_base,
        src: MirValue::StackSlot(fmt_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: fmt_ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(fmt_base),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: data_ptr,
        src: MirValue::StackSlot(data_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(16),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_error_bstr".to_string(),
        btf_id: None,
        args: vec![fmt_ptr, data_ptr, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        fmt_base,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        fmt_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        data_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected scx_bpf_error_bstr stack-slot-base error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack slot base pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_error_bstr_requires_positive_data_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let fmt_ptr = func.alloc_vreg();
    let data_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let fmt_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: fmt_ptr,
        src: MirValue::StackSlot(fmt_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: data_ptr,
        src: MirValue::StackSlot(data_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_error_bstr".to_string(),
        btf_id: None,
        args: vec![fmt_ptr, data_ptr, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        fmt_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        data_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected scx_bpf_error_bstr positive-size error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_error_bstr' arg2 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_exit_bstr_requires_positive_data_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let code = func.alloc_vreg();
    let fmt_ptr = func.alloc_vreg();
    let data_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let fmt_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: code,
        src: MirValue::Const(-1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: fmt_ptr,
        src: MirValue::StackSlot(fmt_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: data_ptr,
        src: MirValue::StackSlot(data_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_exit_bstr".to_string(),
        btf_id: None,
        args: vec![code, fmt_ptr, data_ptr, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(code, MirType::I64);
    types.insert(
        fmt_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        data_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected scx_bpf_exit_bstr positive-size error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_exit_bstr' arg3 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_exit_bstr_requires_stack_slot_base_data() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let code = func.alloc_vreg();
    let fmt_ptr = func.alloc_vreg();
    let data_base = func.alloc_vreg();
    let data_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let fmt_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: code,
        src: MirValue::Const(-1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: fmt_ptr,
        src: MirValue::StackSlot(fmt_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: data_base,
        src: MirValue::StackSlot(data_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: data_ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(data_base),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(16),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_exit_bstr".to_string(),
        btf_id: None,
        args: vec![code, fmt_ptr, data_ptr, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(code, MirType::I64);
    types.insert(
        fmt_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        data_base,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        data_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected scx_bpf_exit_bstr stack-slot-base error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg2 expects stack slot base pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_rbtree_first_requires_graph_root_space() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let stack_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_rbtree_first".to_string(),
        btf_id: None,
        args: vec![stack_ptr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        stack_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected graph-root kfunc arg error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc bpf_rbtree root expects pointer in [Map, Kernel]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_cpumask_and_requires_pointer_args() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let cpumask = func.alloc_vreg();
    let scalar = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: scalar,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_cpumask_and".to_string(),
        btf_id: None,
        args: vec![cpumask, scalar, cpumask],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        cpumask,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(scalar, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected cpumask pointer-arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_events_requires_pointer_arg0() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let events = func.alloc_vreg();
    let events_sz = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: events,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: events_sz,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_events".to_string(),
        btf_id: None,
        args: vec![events, events_sz],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(events, MirType::I64);
    types.insert(events_sz, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected scx_bpf_events pointer-arg error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_events' arg0 expects pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_task_acquire_rejects_cgroup_reference_argument() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let cgid = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let acquired_task = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cgid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![cgid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: acquired_task,
        kfunc: "bpf_task_acquire".to_string(),
        btf_id: None,
        args: vec![cgroup],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cgid, MirType::I64);
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        acquired_task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected kfunc provenance mismatch error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects task reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_get_task_exe_file_rejects_cgroup_reference_argument() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let cgid = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let file = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cgid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![cgid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: file,
        kfunc: "bpf_get_task_exe_file".to_string(),
        btf_id: None,
        args: vec![cgroup],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cgid, MirType::I64);
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        file,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected kfunc provenance mismatch error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects task reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_task_cgroup_rejects_cgroup_reference_argument() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let cgid = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let out = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cgid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![cgid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: out,
        kfunc: "scx_bpf_task_cgroup".to_string(),
        btf_id: None,
        args: vec![cgroup],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cgid, MirType::I64);
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        out,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected scx task_cgroup provenance mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_task_cgroup' arg0 expects task reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_put_cpumask_rejects_task_reference_argument() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let put_ret = func.alloc_vreg();
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
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: put_ret,
        kfunc: "scx_bpf_put_cpumask".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(put_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected scx put_cpumask provenance mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_put_cpumask' arg0 expects cpumask reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_dsq_move_requires_stack_iterator_pointer_arg0() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let dsq_id = func.alloc_vreg();
    let enq_flags = func.alloc_vreg();
    let move_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dsq_id,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: enq_flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: move_ret,
        kfunc: "scx_bpf_dsq_move".to_string(),
        btf_id: None,
        args: vec![task, task, dsq_id, enq_flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dsq_id, MirType::I64);
    types.insert(enq_flags, MirType::I64);
    types.insert(move_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected scx dsq_move stack-pointer error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_dsq_move' arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_dsq_move_vtime_requires_stack_iterator_pointer_arg0() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let dsq_id = func.alloc_vreg();
    let vtime = func.alloc_vreg();
    let move_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dsq_id,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: vtime,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: move_ret,
        kfunc: "scx_bpf_dsq_move_vtime".to_string(),
        btf_id: None,
        args: vec![task, task, dsq_id, vtime],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dsq_id, MirType::I64);
    types.insert(vtime, MirType::I64);
    types.insert(move_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected scx dsq_move_vtime stack-pointer error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_dsq_move_vtime' arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_dsq_move_requires_matching_iter_scx_dsq_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let iter_a_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let iter_b_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let iter_a = func.alloc_vreg();
    let iter_b = func.alloc_vreg();
    let dsq_id = func.alloc_vreg();
    let enq_flags = func.alloc_vreg();
    let cpu = func.alloc_vreg();
    let rq = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let move_ret = func.alloc_vreg();
    let destroy_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter_a,
        src: MirValue::StackSlot(iter_a_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter_b,
        src: MirValue::StackSlot(iter_b_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dsq_id,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: enq_flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cpu,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: rq,
        kfunc: "scx_bpf_cpu_rq".to_string(),
        btf_id: None,
        args: vec![cpu],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_scx_dsq_new".to_string(),
        btf_id: None,
        args: vec![iter_a, dsq_id, enq_flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: move_ret,
        kfunc: "scx_bpf_dsq_move".to_string(),
        btf_id: None,
        args: vec![iter_b, rq, dsq_id, enq_flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_scx_dsq_destroy".to_string(),
        btf_id: None,
        args: vec![iter_a],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter_a,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        iter_b,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dsq_id, MirType::I64);
    types.insert(enq_flags, MirType::I64);
    types.insert(cpu, MirType::I64);
    types.insert(
        rq,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(new_ret, MirType::I64);
    types.insert(move_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected scx dsq_move slot mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_dsq_move' requires a matching bpf_iter_scx_dsq_new")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_dsq_move_vtime_requires_matching_iter_scx_dsq_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let iter_a_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let iter_b_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let iter_a = func.alloc_vreg();
    let iter_b = func.alloc_vreg();
    let dsq_id = func.alloc_vreg();
    let vtime = func.alloc_vreg();
    let cpu = func.alloc_vreg();
    let rq = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let move_ret = func.alloc_vreg();
    let destroy_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter_a,
        src: MirValue::StackSlot(iter_a_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter_b,
        src: MirValue::StackSlot(iter_b_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dsq_id,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: vtime,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cpu,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: rq,
        kfunc: "scx_bpf_cpu_rq".to_string(),
        btf_id: None,
        args: vec![cpu],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_scx_dsq_new".to_string(),
        btf_id: None,
        args: vec![iter_a, dsq_id, vtime],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: move_ret,
        kfunc: "scx_bpf_dsq_move_vtime".to_string(),
        btf_id: None,
        args: vec![iter_b, rq, dsq_id, vtime],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_scx_dsq_destroy".to_string(),
        btf_id: None,
        args: vec![iter_a],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter_a,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        iter_b,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dsq_id, MirType::I64);
    types.insert(vtime, MirType::I64);
    types.insert(cpu, MirType::I64);
    types.insert(
        rq,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(new_ret, MirType::I64);
    types.insert(move_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected scx dsq_move_vtime slot mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_dsq_move_vtime' requires a matching bpf_iter_scx_dsq_new")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_dsq_move_rejects_cgroup_task_argument() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let iter_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let iter = func.alloc_vreg();
    let cgid = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let dsq_id = func.alloc_vreg();
    let enq_flags = func.alloc_vreg();
    let move_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(iter_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cgid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![cgid],
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dsq_id,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: enq_flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: move_ret,
        kfunc: "scx_bpf_dsq_move".to_string(),
        btf_id: None,
        args: vec![iter, cgroup, dsq_id, enq_flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(cgid, MirType::I64);
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dsq_id, MirType::I64);
    types.insert(enq_flags, MirType::I64);
    types.insert(move_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected scx dsq_move provenance mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_dsq_move' arg1 expects task reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_dsq_move_set_slice_requires_stack_iterator_pointer_arg0() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let iter = func.alloc_vreg();
    let slice = func.alloc_vreg();
    let move_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: iter,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: slice,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: move_ret,
        kfunc: "scx_bpf_dsq_move_set_slice".to_string(),
        btf_id: None,
        args: vec![iter, slice],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(slice, MirType::I64);
    types.insert(move_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected scx dsq_move_set_slice stack-pointer error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_dsq_move_set_slice' arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_dsq_move_set_vtime_requires_stack_iterator_pointer_arg0() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let iter = func.alloc_vreg();
    let vtime = func.alloc_vreg();
    let move_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: iter,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: vtime,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: move_ret,
        kfunc: "scx_bpf_dsq_move_set_vtime".to_string(),
        btf_id: None,
        args: vec![iter, vtime],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(vtime, MirType::I64);
    types.insert(move_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected scx dsq_move_set_vtime stack-pointer error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_dsq_move_set_vtime' arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_dsq_move_set_slice_requires_matching_iter_scx_dsq_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let iter_a_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let iter_b_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let iter_a = func.alloc_vreg();
    let iter_b = func.alloc_vreg();
    let dsq_id = func.alloc_vreg();
    let slice = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let move_ret = func.alloc_vreg();
    let destroy_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter_a,
        src: MirValue::StackSlot(iter_a_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter_b,
        src: MirValue::StackSlot(iter_b_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dsq_id,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: slice,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_scx_dsq_new".to_string(),
        btf_id: None,
        args: vec![iter_a, dsq_id, slice],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: move_ret,
        kfunc: "scx_bpf_dsq_move_set_slice".to_string(),
        btf_id: None,
        args: vec![iter_b, slice],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_scx_dsq_destroy".to_string(),
        btf_id: None,
        args: vec![iter_a],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter_a,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        iter_b,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dsq_id, MirType::I64);
    types.insert(slice, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(move_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected scx dsq_move_set_slice slot mismatch");
    assert!(
        err.iter().any(|e| e.message.contains(
            "kfunc 'scx_bpf_dsq_move_set_slice' requires a matching bpf_iter_scx_dsq_new"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_dsq_move_set_vtime_requires_matching_iter_scx_dsq_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let iter_a_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let iter_b_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let iter_a = func.alloc_vreg();
    let iter_b = func.alloc_vreg();
    let dsq_id = func.alloc_vreg();
    let vtime = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let move_ret = func.alloc_vreg();
    let destroy_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter_a,
        src: MirValue::StackSlot(iter_a_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter_b,
        src: MirValue::StackSlot(iter_b_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dsq_id,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: vtime,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_scx_dsq_new".to_string(),
        btf_id: None,
        args: vec![iter_a, dsq_id, vtime],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: move_ret,
        kfunc: "scx_bpf_dsq_move_set_vtime".to_string(),
        btf_id: None,
        args: vec![iter_b, vtime],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_scx_dsq_destroy".to_string(),
        btf_id: None,
        args: vec![iter_a],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter_a,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        iter_b,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dsq_id, MirType::I64);
    types.insert(vtime, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(move_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected scx dsq_move_set_vtime slot mismatch");
    assert!(
        err.iter().any(|e| e.message.contains(
            "kfunc 'scx_bpf_dsq_move_set_vtime' requires a matching bpf_iter_scx_dsq_new"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_scx_select_cpu_dfl_rejects_kernel_pointer_for_is_idle_arg3() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let prev_cpu = func.alloc_vreg();
    let wake_flags = func.alloc_vreg();
    let selected_cpu = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: prev_cpu,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: wake_flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: selected_cpu,
        kfunc: "scx_bpf_select_cpu_dfl".to_string(),
        btf_id: None,
        args: vec![task, prev_cpu, wake_flags, task],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(prev_cpu, MirType::I64);
    types.insert(wake_flags, MirType::I64);
    types.insert(selected_cpu, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected scx select_cpu_dfl stack-pointer mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_select_cpu_dfl' arg3 expects stack slot pointer")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_select_cpu_dfl' arg3 expects stack pointer, got Kernel")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_get_task_exe_file_requires_null_check_for_tracked_task_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let file = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: file,
        kfunc: "bpf_get_task_exe_file".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        file,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected tracked-ref null-check error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 may dereference null pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_task_under_cgroup_rejects_task_reference_for_cgroup_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let verdict = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: verdict,
        kfunc: "bpf_task_under_cgroup".to_string(),
        btf_id: None,
        args: vec![task, task],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(verdict, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected kfunc provenance mismatch error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_task_vma_new_rejects_cgroup_reference_for_task_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let it = func.alloc_vreg();
    let cgid = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let addr = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let iter_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: it,
        src: MirValue::StackSlot(iter_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cgid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: addr,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![cgid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_task_vma_new".to_string(),
        btf_id: None,
        args: vec![it, cgroup, addr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        it,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(cgid, MirType::I64);
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(addr, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected kfunc provenance mismatch error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects task reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_task_new_rejects_cgroup_reference_for_task_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let it = func.alloc_vreg();
    let cgid = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let iter_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: it,
        src: MirValue::StackSlot(iter_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cgid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![cgid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_task_new".to_string(),
        btf_id: None,
        args: vec![it, cgroup, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        it,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(cgid, MirType::I64);
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected kfunc provenance mismatch error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects task reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_task_vma_new_requires_stack_iterator_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let iter = func.alloc_vreg();
    let task = func.alloc_vreg();
    let addr = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: addr,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_task_vma_new".to_string(),
        btf_id: None,
        args: vec![iter, task, addr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(addr, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected iter_task_vma_new stack-pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_task_vma_new_requires_stack_slot_base_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let iter = func.alloc_vreg();
    let shifted_iter = func.alloc_vreg();
    let addr = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: shifted_iter,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(iter),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: addr,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_task_vma_new".to_string(),
        btf_id: None,
        args: vec![shifted_iter, task, addr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        shifted_iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(addr, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected iter_task_vma_new stack-slot-base pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack slot base pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_scx_dsq_new_requires_stack_iterator_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let dsq_id = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dsq_id,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_scx_dsq_new".to_string(),
        btf_id: None,
        args: vec![iter, dsq_id, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dsq_id, MirType::I64);
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected iter_scx_dsq_new stack-pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_scx_dsq_new_requires_stack_slot_base_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let shifted_iter = func.alloc_vreg();
    let dsq_id = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: shifted_iter,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(iter),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dsq_id,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_scx_dsq_new".to_string(),
        btf_id: None,
        args: vec![shifted_iter, dsq_id, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        shifted_iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dsq_id, MirType::I64);
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected iter_scx_dsq_new stack-slot-base pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack slot base pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_num_new_requires_stack_iterator_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let start = func.alloc_vreg();
    let end = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: start,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: end,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_num_new".to_string(),
        btf_id: None,
        args: vec![iter, start, end],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(start, MirType::I64);
    types.insert(end, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected iter_num_new stack-pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_num_new_requires_stack_slot_base_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let shifted_iter = func.alloc_vreg();
    let start = func.alloc_vreg();
    let end = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: shifted_iter,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(iter),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: start,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: end,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_num_new".to_string(),
        btf_id: None,
        args: vec![shifted_iter, start, end],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        shifted_iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(start, MirType::I64);
    types.insert(end, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected iter_num_new stack-slot-base pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack slot base pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_bits_new_requires_stack_iterator_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let words = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: words,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::VReg(iter),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_bits_new".to_string(),
        btf_id: None,
        args: vec![iter, ptr, words],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(words, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected iter_bits_new stack-pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_bits_new_requires_stack_slot_base_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let shifted_iter = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let words = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: shifted_iter,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(iter),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: words,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::VReg(iter),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_bits_new".to_string(),
        btf_id: None,
        args: vec![shifted_iter, ptr, words],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        shifted_iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(words, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected iter_bits_new stack-slot-base pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack slot base pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_dmabuf_new_requires_stack_iterator_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_dmabuf_new".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected iter_dmabuf_new stack-pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_dmabuf_new_requires_stack_slot_base_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let shifted_iter = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: shifted_iter,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(iter),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_dmabuf_new".to_string(),
        btf_id: None,
        args: vec![shifted_iter],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        shifted_iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected iter_dmabuf_new stack-slot-base pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack slot base pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_kmem_cache_new_requires_stack_iterator_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_kmem_cache_new".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected iter_kmem_cache_new stack-pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_kmem_cache_new_requires_stack_slot_base_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let shifted_iter = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: shifted_iter,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(iter),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_kmem_cache_new".to_string(),
        btf_id: None,
        args: vec![shifted_iter],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        shifted_iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected iter_kmem_cache_new stack-slot-base pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack slot base pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_css_new_requires_stack_iterator_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_css_new".to_string(),
        btf_id: None,
        args: vec![task, task, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected iter_css_new stack-pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_css_new_requires_stack_slot_base_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let shifted_iter = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: shifted_iter,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(iter),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_css_new".to_string(),
        btf_id: None,
        args: vec![shifted_iter, task, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        shifted_iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
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
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected iter_css_new stack-slot-base pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack slot base pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_css_task_new_requires_stack_iterator_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_css_task_new".to_string(),
        btf_id: None,
        args: vec![task, task, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected iter_css_task_new stack-pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_css_task_new_requires_stack_slot_base_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let shifted_iter = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: shifted_iter,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(iter),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_css_task_new".to_string(),
        btf_id: None,
        args: vec![shifted_iter, task, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        shifted_iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
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
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected iter_css_task_new stack-slot-base pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack slot base pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_css_new_requires_kernel_css_pointer_arg1() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let css = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: css,
        src: MirValue::VReg(iter),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_css_new".to_string(),
        btf_id: None,
        args: vec![iter, css, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        css,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected iter_css_new arg1 kernel-pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects kernel pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_css_task_new_requires_kernel_css_pointer_arg1() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let css = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: css,
        src: MirValue::VReg(iter),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_css_task_new".to_string(),
        btf_id: None,
        args: vec![iter, css, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        css,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected iter_css_task_new arg1 kernel-pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects kernel pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_css_new_rejects_task_reference_for_css_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let pid = func.alloc_vreg();
    let iter = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_css_new".to_string(),
        btf_id: None,
        args: vec![iter, task, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected iter_css_new cgroup provenance mismatch");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_css_task_new_rejects_task_reference_for_css_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let pid = func.alloc_vreg();
    let iter = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_css_task_new".to_string(),
        btf_id: None,
        args: vec![iter, task, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected iter_css_task_new cgroup provenance mismatch");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_task_new_requires_stack_iterator_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::VReg(iter),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_task_new".to_string(),
        btf_id: None,
        args: vec![iter, ptr, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected iter_task_new stack-pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_task_new_requires_stack_slot_base_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let shifted_iter = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: shifted_iter,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(iter),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::VReg(iter),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_task_new".to_string(),
        btf_id: None,
        args: vec![shifted_iter, ptr, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        shifted_iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected iter_task_new stack-slot-base pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack slot base pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_task_vma_lifecycle_balanced() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let iter = func.alloc_vreg();
    let addr = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let next_ret = func.alloc_vreg();
    let destroy_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: addr,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_task_vma_new".to_string(),
        btf_id: None,
        args: vec![iter, task, addr],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_task_vma_next".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_task_vma_destroy".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(addr, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(destroy_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected balanced iter_task_vma new/next/destroy to verify");
}

#[test]
fn test_kfunc_iter_task_vma_next_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let iter_new = func.alloc_vreg();
    let iter_next = func.alloc_vreg();
    let addr = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let next_ret = func.alloc_vreg();
    let new_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let next_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter_new,
        src: MirValue::StackSlot(new_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter_next,
        src: MirValue::StackSlot(next_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: addr,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_task_vma_new".to_string(),
        btf_id: None,
        args: vec![iter_new, task, addr],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_task_vma_next".to_string(),
        btf_id: None,
        args: vec![iter_next],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        iter_new,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        iter_next,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(addr, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected iter_task_vma_next slot mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires a matching bpf_iter_task_vma_new")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_task_vma_next_rejected_after_mixed_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let new_path = func.alloc_block();
    let no_new_path = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let task = func.alloc_vreg();
    let selector = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let iter = func.alloc_vreg();
    let addr = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let next_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: addr,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: new_path,
        if_false: no_new_path,
    };

    func.block_mut(new_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: new_ret,
            kfunc: "bpf_iter_task_vma_new".to_string(),
            btf_id: None,
            args: vec![iter, task, addr],
        });
    func.block_mut(new_path).terminator = MirInst::Jump { target: join };
    func.block_mut(no_new_path).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_task_vma_next".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(selector, MirType::I64);
    types.insert(cond, MirType::Bool);
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(addr, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected mixed-path iter_task_vma_next error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires a matching bpf_iter_task_vma_new")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_task_vma_destroy_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let iter_new = func.alloc_vreg();
    let iter_destroy = func.alloc_vreg();
    let addr = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let destroy_ret = func.alloc_vreg();
    let new_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let destroy_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter_new,
        src: MirValue::StackSlot(new_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter_destroy,
        src: MirValue::StackSlot(destroy_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: addr,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_task_vma_new".to_string(),
        btf_id: None,
        args: vec![iter_new, task, addr],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_task_vma_destroy".to_string(),
        btf_id: None,
        args: vec![iter_destroy],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        iter_new,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        iter_destroy,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(addr, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected iter_task_vma_destroy slot mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires a matching bpf_iter_task_vma_new")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_task_vma_new_must_be_destroyed_at_exit() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let iter = func.alloc_vreg();
    let addr = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: addr,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_task_vma_new".to_string(),
        btf_id: None,
        args: vec![iter, task, addr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(addr, MirType::I64);
    types.insert(new_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unreleased iter_task_vma iterator");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased iter_task_vma iterator")),
        "unexpected errors: {:?}",
        err
    );
}

