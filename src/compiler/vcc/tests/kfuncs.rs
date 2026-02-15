use super::*;

#[test]
fn test_verify_mir_kfunc_unknown_signature_rejected() {
    let (mut func, entry) = new_mir_function();
    let arg = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: arg,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "unknown_kfunc".to_string(),
        btf_id: None,
        args: vec![arg],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(arg, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unknown-kfunc error");
    assert!(err.iter().any(|e| e.message.contains("unknown kfunc")));
}

#[test]
fn test_verify_mir_kfunc_pointer_argument_required() {
    let (mut func, entry) = new_mir_function();
    let scalar = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: scalar,
        src: MirValue::Const(42),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_task_release".to_string(),
        btf_id: None,
        args: vec![scalar],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(scalar, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected kfunc pointer-arg error");
    assert!(err.iter().any(|e| {
        e.message.contains("expects pointer") || e.message.contains("expected pointer value")
    }));
}

#[test]
fn test_verify_mir_kfunc_pointer_argument_requires_kernel_space() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let task_ptr = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: acquired,
        kfunc: "bpf_task_acquire".to_string(),
        btf_id: None,
        args: vec![task_ptr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        acquired,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected kernel-pointer kfunc arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects pointer in [Kernel]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_local_irq_save_requires_stack_pointer() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let kernel_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_local_irq_save".to_string(),
        btf_id: None,
        args: vec![kernel_ptr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        kernel_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected local_irq_save stack-pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects pointer in [Stack]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_local_irq_save_rejects_context_derived_stack_pointer() {
    let (mut func, entry) = new_mir_function();

    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: flags,
            field: CtxField::Arg(0),
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_local_irq_save".to_string(),
        btf_id: None,
        args: vec![flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        flags,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected local_irq_save context-derived stack-pointer rejection");
    assert!(
        err.iter().any(|e| {
            e.message.contains("arg0 expects pointer in [Stack]")
                || e.message.contains("arg0 expects stack slot pointer")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_local_irq_save_requires_stack_slot_base_pointer() {
    let (mut func, entry) = new_mir_function();

    let flags = func.alloc_vreg();
    let shifted = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: shifted,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(flags),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_local_irq_save".to_string(),
        btf_id: None,
        args: vec![shifted],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        flags,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        shifted,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected local_irq_save stack-slot-base error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack slot base pointer")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_res_spin_lock_requires_kernel_pointer() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let stack_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_res_spin_lock".to_string(),
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
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected res_spin_lock kernel-pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects pointer in [Kernel]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_res_spin_lock_irqsave_requires_stack_flags_pointer() {
    let (mut func, entry) = new_mir_function();

    let lock = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: lock,
        kfunc: "bpf_cpumask_create".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_res_spin_lock_irqsave".to_string(),
        btf_id: None,
        args: vec![lock, lock],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        lock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected res_spin_lock_irqsave stack-flags error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects pointer in [Stack]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_list_push_front_requires_kernel_space() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let stack_ptr = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let off = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_list_push_front_impl".to_string(),
        btf_id: None,
        args: vec![stack_ptr, stack_ptr, meta, off],
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
    types.insert(meta, MirType::I64);
    types.insert(off, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected kernel-pointer kfunc arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects pointer in [Kernel]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_path_d_path_requires_kernel_path_arg() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let stack_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(32),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_path_d_path".to_string(),
        btf_id: None,
        args: vec![stack_ptr, stack_ptr, size],
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
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected kernel-pointer kfunc arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects pointer in [Kernel]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_path_d_path_buffer_requires_stack_or_map_space() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 2;

    let path_ptr = func.alloc_vreg();
    let buf_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(32),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_path_d_path".to_string(),
        btf_id: None,
        args: vec![path_ptr, buf_ptr, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        path_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        buf_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected path_d_path buffer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc path_d_path buffer expects pointer in [Stack, Map], got Kernel")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_path_d_path_requires_positive_size() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 2;

    let path_ptr = func.alloc_vreg();
    let buf_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_path_d_path".to_string(),
        btf_id: None,
        args: vec![path_ptr, buf_ptr, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        path_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        buf_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected path_d_path positive-size error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_path_d_path' arg2 must be > 0")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_path_d_path_requires_bounded_size_for_stack_buffer() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 2;

    let path_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let buf_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: buf_ptr,
        src: MirValue::StackSlot(buf_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_path_d_path".to_string(),
        btf_id: None,
        args: vec![path_ptr, buf_ptr, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        path_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(
        buf_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected path_d_path bounded-size error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("size must have bounded upper range")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_path_d_path_requires_stack_slot_base_buffer() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let path_ptr = func.alloc_vreg();
    let buf_base = func.alloc_vreg();
    let buf_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: buf_base,
        src: MirValue::StackSlot(buf_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: buf_ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(buf_base),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(16),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_path_d_path".to_string(),
        btf_id: None,
        args: vec![path_ptr, buf_ptr, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        path_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        buf_base,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        buf_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected path_d_path stack-slot-base error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects stack slot base pointer")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_path_d_path_accepts_stack_buffer_rule() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 2;

    let path_ptr = func.alloc_vreg();
    let buf_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: buf_ptr,
        src: MirValue::StackSlot(buf_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(32),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_path_d_path".to_string(),
        btf_id: None,
        args: vec![path_ptr, buf_ptr, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        path_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        buf_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected path_d_path stack-buffer rule to verify");
}

#[test]
fn test_verify_mir_kfunc_copy_from_user_str_src_requires_user_pointer() {
    let (mut func, entry) = new_mir_function();

    let dst = func.alloc_vreg();
    let size = func.alloc_vreg();
    let src = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let dst_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: src,
        src: MirValue::StackSlot(src_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_copy_from_user_str".to_string(),
        btf_id: None,
        args: vec![dst, size, src, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(
        src,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected copy_from_user_str user-source error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc bpf_copy_from_user_str src expects pointer in [User], got Stack")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_copy_from_user_str_requires_stack_slot_base_dst() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let src = func.alloc_vreg();
    let dst_base = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let size = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let dst_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dst_base,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(dst_base),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_copy_from_user_str".to_string(),
        btf_id: None,
        args: vec![dst, size, src, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        src,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::User,
        },
    );
    types.insert(
        dst_base,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(flags, MirType::I64);
    types.insert(ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected copy_from_user_str stack-slot-base error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack slot base pointer")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_copy_from_user_task_str_rejects_cgroup_task_argument() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let src = func.alloc_vreg();
    let cgid = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let size = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let dst_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
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
        dst,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_copy_from_user_task_str".to_string(),
        btf_id: None,
        args: vec![dst, size, src, cgroup, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        src,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::User,
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
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(flags, MirType::I64);
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected copy_from_user_task_str ref mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_copy_from_user_task_str' arg3 expects task reference")),
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_events_buffer_requires_stack_or_map_space() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let events_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_events_requires_positive_size() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let events_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_events_requires_bounded_size_for_stack_buffer() {
    let (mut func, entry) = new_mir_function();
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
            .any(|e| e.message.contains("size must have bounded upper range")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_events_accepts_stack_buffer_rule() {
    let (mut func, entry) = new_mir_function();
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
fn test_verify_mir_kfunc_scx_dump_bstr_fmt_requires_stack_or_map_space() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let fmt_ptr = func.alloc_vreg();
    let data_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_dump_bstr_requires_positive_data_size() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let fmt_ptr = func.alloc_vreg();
    let data_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_dump_bstr_requires_stack_slot_base_data() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_dump_bstr_accepts_stack_fmt_and_data() {
    let (mut func, entry) = new_mir_function();
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
fn test_verify_mir_kfunc_scx_exit_bstr_requires_positive_data_size() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let code = func.alloc_vreg();
    let fmt_ptr = func.alloc_vreg();
    let data_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: code,
        src: MirValue::Const(-1),
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_rbtree_first_requires_kernel_space() {
    let (mut func, entry) = new_mir_function();
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

    let err = verify_mir(&func, &types).expect_err("expected kernel-pointer kfunc arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects pointer in [Kernel]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_cpumask_and_requires_pointer_args() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| {
            e.message.contains("arg1 expects pointer")
                || e.message.contains("expected pointer value")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_events_requires_pointer_arg0() {
    let (mut func, entry) = new_mir_function();

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
        err.iter().any(|e| {
            e.message
                .contains("kfunc 'scx_bpf_events' arg0 expects pointer")
                || e.message.contains("expected pointer value")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_task_acquire_rejects_cgroup_reference_argument() {
    let (mut func, entry) = new_mir_function();

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
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_get_task_exe_file_rejects_cgroup_reference_argument() {
    let (mut func, entry) = new_mir_function();

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
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_task_cgroup_rejects_cgroup_reference_argument() {
    let (mut func, entry) = new_mir_function();

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
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_put_cpumask_rejects_task_reference_argument() {
    let (mut func, entry) = new_mir_function();

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
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_dsq_move_requires_stack_iterator_pointer_arg0() {
    let (mut func, entry) = new_mir_function();

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
        err.iter()
            .any(|e| e.message.contains("arg0 expects pointer in [Stack]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_dsq_move_vtime_requires_stack_iterator_pointer_arg0() {
    let (mut func, entry) = new_mir_function();

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
        err.iter()
            .any(|e| e.message.contains("arg0 expects pointer in [Stack]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_dsq_move_requires_matching_iter_scx_dsq_slot() {
    let (mut func, entry) = new_mir_function();

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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_dsq_move_vtime_requires_matching_iter_scx_dsq_slot() {
    let (mut func, entry) = new_mir_function();

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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_dsq_move_rejects_cgroup_task_argument() {
    let (mut func, entry) = new_mir_function();

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
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_dsq_move_set_slice_requires_stack_iterator_pointer_arg0() {
    let (mut func, entry) = new_mir_function();

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
        err.iter()
            .any(|e| e.message.contains("arg0 expects pointer in [Stack]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_dsq_move_set_vtime_requires_stack_iterator_pointer_arg0() {
    let (mut func, entry) = new_mir_function();

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
        err.iter()
            .any(|e| e.message.contains("arg0 expects pointer in [Stack]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_dsq_move_set_slice_requires_matching_iter_scx_dsq_slot() {
    let (mut func, entry) = new_mir_function();

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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_dsq_move_set_vtime_requires_matching_iter_scx_dsq_slot() {
    let (mut func, entry) = new_mir_function();

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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_scx_select_cpu_dfl_rejects_task_reference_for_cpumask_arg3() {
    let (mut func, entry) = new_mir_function();

    let cpu = func.alloc_vreg();
    let rq = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let prev_cpu = func.alloc_vreg();
    let wake_flags = func.alloc_vreg();
    let selected_cpu = func.alloc_vreg();

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
        args: vec![rq, prev_cpu, wake_flags, task],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cpu, MirType::I64);
    types.insert(
        rq,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
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
    types.insert(prev_cpu, MirType::I64);
    types.insert(wake_flags, MirType::I64);
    types.insert(selected_cpu, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected scx select_cpu_dfl cpumask mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_select_cpu_dfl' arg3 expects cpumask reference")),
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_get_task_exe_file_requires_null_check_for_tracked_task_reference() {
    let (mut func, entry) = new_mir_function();

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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_task_under_cgroup_rejects_task_reference_for_cgroup_arg() {
    let (mut func, entry) = new_mir_function();

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
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_task_vma_new_rejects_cgroup_reference_for_task_arg() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_task_new_rejects_cgroup_reference_for_task_arg() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_task_vma_new_requires_stack_iterator_pointer() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| {
            e.message.contains("arg0 expects pointer in [Stack]")
                || e.message.contains("arg0 expects stack slot pointer")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_task_vma_new_requires_stack_slot_base_pointer() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_scx_dsq_new_requires_stack_iterator_pointer() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| {
            e.message.contains("arg0 expects pointer in [Stack]")
                || e.message.contains("arg0 expects stack slot pointer")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_scx_dsq_new_requires_stack_slot_base_pointer() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_num_new_requires_stack_iterator_pointer() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| {
            e.message.contains("arg0 expects pointer in [Stack]")
                || e.message.contains("arg0 expects stack slot pointer")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_num_new_requires_stack_slot_base_pointer() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_bits_new_requires_stack_iterator_pointer() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| {
            e.message.contains("arg0 expects pointer in [Stack]")
                || e.message.contains("arg0 expects stack slot pointer")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_bits_new_requires_stack_slot_base_pointer() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_dmabuf_new_requires_stack_iterator_pointer() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| {
            e.message.contains("arg0 expects pointer in [Stack]")
                || e.message.contains("arg0 expects stack slot pointer")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_dmabuf_new_requires_stack_slot_base_pointer() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_kmem_cache_new_requires_stack_iterator_pointer() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| {
            e.message.contains("arg0 expects pointer in [Stack]")
                || e.message.contains("arg0 expects stack slot pointer")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_kmem_cache_new_requires_stack_slot_base_pointer() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_css_new_requires_stack_iterator_pointer() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| {
            e.message.contains("arg0 expects pointer in [Stack]")
                || e.message.contains("arg0 expects stack slot pointer")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_css_new_requires_stack_slot_base_pointer() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_css_task_new_requires_stack_iterator_pointer() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| {
            e.message.contains("arg0 expects pointer in [Stack]")
                || e.message.contains("arg0 expects stack slot pointer")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_css_task_new_requires_stack_slot_base_pointer() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_css_new_requires_kernel_css_pointer_arg1() {
    let (mut func, entry) = new_mir_function();
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
            .any(|e| e.message.contains("arg1 expects pointer in [Kernel]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_css_task_new_requires_kernel_css_pointer_arg1() {
    let (mut func, entry) = new_mir_function();
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
            .any(|e| e.message.contains("arg1 expects pointer in [Kernel]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_css_new_rejects_task_reference_for_css_arg() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_css_task_new_rejects_task_reference_for_css_arg() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_task_new_requires_stack_iterator_pointer() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| {
            e.message.contains("arg0 expects pointer in [Stack]")
                || e.message.contains("arg0 expects stack slot pointer")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_task_new_requires_stack_slot_base_pointer() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let task = func.alloc_vreg();
    let iter = func.alloc_vreg();
    let shifted_iter = func.alloc_vreg();
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
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_task_new".to_string(),
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
        .expect_err("expected iter_task_new stack-slot-base pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack slot base pointer")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_task_vma_lifecycle_balanced() {
    let (mut func, entry) = new_mir_function();
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
fn test_verify_mir_kfunc_iter_task_vma_next_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_task_vma_next_rejected_after_mixed_join() {
    let (mut func, entry) = new_mir_function();
    let new_path = func.alloc_block();
    let no_new_path = func.alloc_block();
    let join = func.alloc_block();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_task_vma_destroy_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_task_vma_new_must_be_destroyed_at_exit() {
    let (mut func, entry) = new_mir_function();
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_scx_dsq_lifecycle_balanced() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let dsq_id = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let next_ret = func.alloc_vreg();
    let destroy_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
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
        dst: new_ret,
        kfunc: "bpf_iter_scx_dsq_new".to_string(),
        btf_id: None,
        args: vec![iter, dsq_id, flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_scx_dsq_next".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_scx_dsq_destroy".to_string(),
        btf_id: None,
        args: vec![iter],
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
    types.insert(dsq_id, MirType::I64);
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(destroy_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected balanced iter_scx_dsq new/next/destroy to verify");
}

#[test]
fn test_verify_mir_kfunc_iter_scx_dsq_next_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter_new = func.alloc_vreg();
    let iter_next = func.alloc_vreg();
    let dsq_id = func.alloc_vreg();
    let flags = func.alloc_vreg();
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
        dst: dsq_id,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_scx_dsq_new".to_string(),
        btf_id: None,
        args: vec![iter_new, dsq_id, flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_scx_dsq_next".to_string(),
        btf_id: None,
        args: vec![iter_next],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(dsq_id, MirType::I64);
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected iter_scx_dsq_next slot mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires a matching bpf_iter_scx_dsq_new")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_scx_dsq_destroy_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter_new = func.alloc_vreg();
    let iter_destroy = func.alloc_vreg();
    let dsq_id = func.alloc_vreg();
    let flags = func.alloc_vreg();
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
        dst: dsq_id,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_scx_dsq_new".to_string(),
        btf_id: None,
        args: vec![iter_new, dsq_id, flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_scx_dsq_destroy".to_string(),
        btf_id: None,
        args: vec![iter_destroy],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(dsq_id, MirType::I64);
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected iter_scx_dsq_destroy slot mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires a matching bpf_iter_scx_dsq_new")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_scx_dsq_new_must_be_destroyed_at_exit() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let dsq_id = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
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
        dst: new_ret,
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
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dsq_id, MirType::I64);
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unreleased iter_scx_dsq iterator");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased iter_scx_dsq iterator")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_num_lifecycle_balanced() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let start = func.alloc_vreg();
    let end = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let next_ret = func.alloc_vreg();
    let destroy_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
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
        dst: new_ret,
        kfunc: "bpf_iter_num_new".to_string(),
        btf_id: None,
        args: vec![iter, start, end],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_num_next".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_num_destroy".to_string(),
        btf_id: None,
        args: vec![iter],
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
    types.insert(start, MirType::I64);
    types.insert(end, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(destroy_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected balanced iter_num new/next/destroy to verify");
}

#[test]
fn test_verify_mir_kfunc_iter_num_next_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter_new = func.alloc_vreg();
    let iter_next = func.alloc_vreg();
    let start = func.alloc_vreg();
    let end = func.alloc_vreg();
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
        dst: start,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: end,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_num_new".to_string(),
        btf_id: None,
        args: vec![iter_new, start, end],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_num_next".to_string(),
        btf_id: None,
        args: vec![iter_next],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(start, MirType::I64);
    types.insert(end, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected iter_num_next slot mismatch");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_iter_num_new")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_num_destroy_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter_new = func.alloc_vreg();
    let iter_destroy = func.alloc_vreg();
    let start = func.alloc_vreg();
    let end = func.alloc_vreg();
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
        dst: start,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: end,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_num_new".to_string(),
        btf_id: None,
        args: vec![iter_new, start, end],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_num_destroy".to_string(),
        btf_id: None,
        args: vec![iter_destroy],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(start, MirType::I64);
    types.insert(end, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected iter_num_destroy slot mismatch");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_iter_num_new")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_num_new_must_be_destroyed_at_exit() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let start = func.alloc_vreg();
    let end = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
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
        dst: new_ret,
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
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(start, MirType::I64);
    types.insert(end, MirType::I64);
    types.insert(new_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unreleased iter_num iterator");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased iter_num iterator")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_bits_lifecycle_balanced() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let words = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let next_ret = func.alloc_vreg();
    let destroy_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
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
        dst: new_ret,
        kfunc: "bpf_iter_bits_new".to_string(),
        btf_id: None,
        args: vec![iter, ptr, words],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_bits_next".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_bits_destroy".to_string(),
        btf_id: None,
        args: vec![iter],
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
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(words, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(destroy_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected balanced iter_bits new/next/destroy to verify");
}

#[test]
fn test_verify_mir_kfunc_iter_bits_next_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter_new = func.alloc_vreg();
    let iter_next = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let words = func.alloc_vreg();
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
        dst: words,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::VReg(iter_new),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_bits_new".to_string(),
        btf_id: None,
        args: vec![iter_new, ptr, words],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_bits_next".to_string(),
        btf_id: None,
        args: vec![iter_next],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(words, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected iter_bits_next slot mismatch");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_iter_bits_new")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_bits_destroy_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter_new = func.alloc_vreg();
    let iter_destroy = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let words = func.alloc_vreg();
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
        dst: words,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::VReg(iter_new),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_bits_new".to_string(),
        btf_id: None,
        args: vec![iter_new, ptr, words],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_bits_destroy".to_string(),
        btf_id: None,
        args: vec![iter_destroy],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(words, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected iter_bits_destroy slot mismatch");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_iter_bits_new")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_bits_new_must_be_destroyed_at_exit() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let words = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
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
        dst: new_ret,
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
    types.insert(new_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unreleased iter_bits iterator");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased iter_bits iterator")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_dmabuf_lifecycle_balanced() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let next_ret = func.alloc_vreg();
    let destroy_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_dmabuf_new".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_dmabuf_next".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_dmabuf_destroy".to_string(),
        btf_id: None,
        args: vec![iter],
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
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(destroy_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected balanced iter_dmabuf new/next/destroy to verify");
}

#[test]
fn test_verify_mir_kfunc_iter_dmabuf_next_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter_new = func.alloc_vreg();
    let iter_next = func.alloc_vreg();
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
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_dmabuf_new".to_string(),
        btf_id: None,
        args: vec![iter_new],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_dmabuf_next".to_string(),
        btf_id: None,
        args: vec![iter_next],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected iter_dmabuf_next slot mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires a matching bpf_iter_dmabuf_new")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_dmabuf_destroy_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter_new = func.alloc_vreg();
    let iter_destroy = func.alloc_vreg();
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
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_dmabuf_new".to_string(),
        btf_id: None,
        args: vec![iter_new],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_dmabuf_destroy".to_string(),
        btf_id: None,
        args: vec![iter_destroy],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(new_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected iter_dmabuf_destroy slot mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires a matching bpf_iter_dmabuf_new")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_dmabuf_new_must_be_destroyed_at_exit() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_dmabuf_new".to_string(),
        btf_id: None,
        args: vec![iter],
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
    types.insert(new_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unreleased iter_dmabuf iterator");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased iter_dmabuf iterator")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_kmem_cache_lifecycle_balanced() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let next_ret = func.alloc_vreg();
    let destroy_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_kmem_cache_new".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_kmem_cache_next".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_kmem_cache_destroy".to_string(),
        btf_id: None,
        args: vec![iter],
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
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(destroy_ret, MirType::I64);

    verify_mir(&func, &types)
        .expect("expected balanced iter_kmem_cache new/next/destroy to verify");
}

#[test]
fn test_verify_mir_kfunc_iter_kmem_cache_next_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter_new = func.alloc_vreg();
    let iter_next = func.alloc_vreg();
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
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_kmem_cache_new".to_string(),
        btf_id: None,
        args: vec![iter_new],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_kmem_cache_next".to_string(),
        btf_id: None,
        args: vec![iter_next],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected iter_kmem_cache_next slot mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires a matching bpf_iter_kmem_cache_new")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_kmem_cache_destroy_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter_new = func.alloc_vreg();
    let iter_destroy = func.alloc_vreg();
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
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_kmem_cache_new".to_string(),
        btf_id: None,
        args: vec![iter_new],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_kmem_cache_destroy".to_string(),
        btf_id: None,
        args: vec![iter_destroy],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(new_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected iter_kmem_cache_destroy slot mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires a matching bpf_iter_kmem_cache_new")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_kmem_cache_new_must_be_destroyed_at_exit() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_kmem_cache_new".to_string(),
        btf_id: None,
        args: vec![iter],
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
    types.insert(new_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unreleased iter_kmem_cache iterator");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased iter_kmem_cache iterator")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_css_lifecycle_balanced() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let cpu = func.alloc_vreg();
    let rq = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let next_ret = func.alloc_vreg();
    let destroy_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
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
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_css_new".to_string(),
        btf_id: None,
        args: vec![iter, rq, flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_css_next".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_css_destroy".to_string(),
        btf_id: None,
        args: vec![iter],
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
    types.insert(cpu, MirType::I64);
    types.insert(
        rq,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(destroy_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected balanced iter_css new/next/destroy to verify");
}

#[test]
fn test_verify_mir_kfunc_iter_css_next_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter_new = func.alloc_vreg();
    let iter_next = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
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
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_css_new".to_string(),
        btf_id: None,
        args: vec![iter_new, task, flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_css_next".to_string(),
        btf_id: None,
        args: vec![iter_next],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected iter_css_next slot mismatch");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_iter_css_new")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_css_destroy_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter_new = func.alloc_vreg();
    let iter_destroy = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
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
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_css_new".to_string(),
        btf_id: None,
        args: vec![iter_new, task, flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_css_destroy".to_string(),
        btf_id: None,
        args: vec![iter_destroy],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected iter_css_destroy slot mismatch");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_iter_css_new")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_css_new_must_be_destroyed_at_exit() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
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
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_css_new".to_string(),
        btf_id: None,
        args: vec![iter, task, flags],
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
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unreleased iter_css iterator");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased iter_css iterator")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_css_task_lifecycle_balanced() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let cpu = func.alloc_vreg();
    let rq = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let next_ret = func.alloc_vreg();
    let destroy_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
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
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_css_task_new".to_string(),
        btf_id: None,
        args: vec![iter, rq, flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_css_task_next".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_css_task_destroy".to_string(),
        btf_id: None,
        args: vec![iter],
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
    types.insert(cpu, MirType::I64);
    types.insert(
        rq,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(destroy_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected balanced iter_css_task new/next/destroy to verify");
}

#[test]
fn test_verify_mir_kfunc_iter_css_task_next_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter_new = func.alloc_vreg();
    let iter_next = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
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
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_css_task_new".to_string(),
        btf_id: None,
        args: vec![iter_new, task, flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_css_task_next".to_string(),
        btf_id: None,
        args: vec![iter_next],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected iter_css_task_next slot mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires a matching bpf_iter_css_task_new")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_css_task_destroy_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter_new = func.alloc_vreg();
    let iter_destroy = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
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
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_css_task_new".to_string(),
        btf_id: None,
        args: vec![iter_new, task, flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_css_task_destroy".to_string(),
        btf_id: None,
        args: vec![iter_destroy],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected iter_css_task_destroy slot mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires a matching bpf_iter_css_task_new")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_css_task_new_must_be_destroyed_at_exit() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
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
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_css_task_new".to_string(),
        btf_id: None,
        args: vec![iter, task, flags],
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
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unreleased iter_css_task iterator");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased iter_css_task iterator")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_task_lifecycle_balanced() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let task = func.alloc_vreg();
    let iter = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let next_ret = func.alloc_vreg();
    let destroy_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_task_new".to_string(),
        btf_id: None,
        args: vec![iter, task, flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_task_next".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_task_destroy".to_string(),
        btf_id: None,
        args: vec![iter],
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
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(destroy_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected balanced iter_task new/next/destroy to verify");
}

#[test]
fn test_verify_mir_kfunc_iter_task_next_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let task = func.alloc_vreg();
    let iter_new = func.alloc_vreg();
    let iter_next = func.alloc_vreg();
    let flags = func.alloc_vreg();
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
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_task_new".to_string(),
        btf_id: None,
        args: vec![iter_new, task, flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_task_next".to_string(),
        btf_id: None,
        args: vec![iter_next],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected iter_task_next slot mismatch");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_iter_task_new")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_task_destroy_requires_matching_new_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let task = func.alloc_vreg();
    let iter_new = func.alloc_vreg();
    let iter_destroy = func.alloc_vreg();
    let flags = func.alloc_vreg();
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
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_task_new".to_string(),
        btf_id: None,
        args: vec![iter_new, task, flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_task_destroy".to_string(),
        btf_id: None,
        args: vec![iter_destroy],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected iter_task_destroy slot mismatch");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_iter_task_new")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_task_new_must_be_destroyed_at_exit() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let task = func.alloc_vreg();
    let iter = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: new_ret,
        kfunc: "bpf_iter_task_new".to_string(),
        btf_id: None,
        args: vec![iter, task, flags],
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
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unreleased iter_task iterator");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased iter_task iterator")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_task_acquire_release_semantics() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let task = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: acquired,
        kfunc: "bpf_task_acquire".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(acquired),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![acquired],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        acquired,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected kfunc reference to be released");
}

#[test]
fn test_verify_mir_kfunc_task_acquire_leak_rejected() {
    let (mut func, entry) = new_mir_function();
    let leak = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let task = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    let cond = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: acquired,
        kfunc: "bpf_task_acquire".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(acquired),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: leak,
        if_false: done,
    };

    func.block_mut(leak).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        acquired,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected kfunc leak error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased kfunc reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_task_from_pid_release_semantics() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

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
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
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
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected task_from_pid reference to be released");
}

#[test]
fn test_verify_mir_kfunc_task_from_pid_release_semantics_via_copied_cond_with_join() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();
    let join = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond0 = func.alloc_vreg();
    let cond1 = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let then_val = func.alloc_vreg();
    let else_val = func.alloc_vreg();
    let result = func.alloc_vreg();

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
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond0,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cond1,
        src: MirValue::VReg(cond0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cond1,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).instructions.push(MirInst::Copy {
        dst: then_val,
        src: MirValue::Const(0),
    });
    func.block_mut(release).terminator = MirInst::Jump { target: join };

    func.block_mut(done).instructions.push(MirInst::Copy {
        dst: else_val,
        src: MirValue::Const(0),
    });
    func.block_mut(done).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::Phi {
        dst: result,
        args: vec![(release, then_val), (done, else_val)],
    });
    func.block_mut(join).terminator = MirInst::Return {
        val: Some(MirValue::VReg(result)),
    };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond0, MirType::Bool);
    types.insert(cond1, MirType::Bool);
    types.insert(release_ret, MirType::I64);
    types.insert(then_val, MirType::I64);
    types.insert(else_val, MirType::I64);
    types.insert(result, MirType::I64);

    verify_mir(&func, &types).expect("expected copied guard to preserve release semantics");
}

#[test]
fn test_verify_mir_kfunc_task_from_pid_release_semantics_via_negated_cond() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let negated = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

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
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::UnaryOp {
        dst: negated,
        op: super::UnaryOpKind::Not,
        src: MirValue::VReg(cond),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: negated,
        if_true: done,
        if_false: release,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).terminator = MirInst::Jump { target: done };
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
    types.insert(cond, MirType::Bool);
    types.insert(negated, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected negated guard to preserve release semantics");
}

#[test]
fn test_verify_mir_kfunc_cgroup_from_id_release_semantics() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let cgid = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cgid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![cgid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(cgroup),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_cgroup_release".to_string(),
            btf_id: None,
            args: vec![cgroup],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cgid, MirType::I64);
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected cgroup_from_id reference to be released");
}

#[test]
fn test_verify_mir_kfunc_scx_task_cgroup_release_semantics() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let task = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "scx_bpf_task_cgroup".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(cgroup),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_cgroup_release".to_string(),
            btf_id: None,
            args: vec![cgroup],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected scx task_cgroup reference to be released");
}

#[test]
fn test_verify_mir_kfunc_scx_task_cgroup_requires_release() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let task = func.alloc_vreg();
    let cgroup = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "scx_bpf_task_cgroup".to_string(),
        btf_id: None,
        args: vec![task],
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
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected scx task_cgroup leak without release");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased kfunc reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_cgroup_release_rejects_task_reference() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

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
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_cgroup_release".to_string(),
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
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-reference error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("expects cgroup reference")),
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_get_task_exe_file_put_file_semantics() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let task = func.alloc_vreg();
    let file = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: file,
        kfunc: "bpf_get_task_exe_file".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(file),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_put_file".to_string(),
            btf_id: None,
            args: vec![file],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected file reference to be released");
}

#[test]
fn test_verify_mir_kfunc_put_file_rejects_task_reference() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

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
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_put_file".to_string(),
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
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-reference error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("expects file reference")),
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_cpumask_create_release_semantics() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let cpumask = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cpumask,
        kfunc: "bpf_cpumask_create".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(cpumask),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_cpumask_release".to_string(),
            btf_id: None,
            args: vec![cpumask],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        cpumask,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected cpumask reference to be released");
}

#[test]
fn test_verify_mir_kfunc_cpumask_create_release_dtor_semantics() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let cpumask = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cpumask,
        kfunc: "bpf_cpumask_create".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(cpumask),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_cpumask_release_dtor".to_string(),
            btf_id: None,
            args: vec![cpumask],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        cpumask,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected cpumask reference to be released via release_dtor");
}

#[test]
fn test_verify_mir_kfunc_scx_get_online_cpumask_put_release_semantics() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let cpumask = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cpumask,
        kfunc: "scx_bpf_get_online_cpumask".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(cpumask),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "scx_bpf_put_cpumask".to_string(),
            btf_id: None,
            args: vec![cpumask],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        cpumask,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected scx cpumask reference to be released");
}

#[test]
fn test_verify_mir_kfunc_scx_get_online_cpumask_requires_release() {
    let (mut func, entry) = new_mir_function();

    let cpumask = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cpumask,
        kfunc: "scx_bpf_get_online_cpumask".to_string(),
        btf_id: None,
        args: vec![],
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

    let err = verify_mir(&func, &types).expect_err("expected scx cpumask leak without put_cpumask");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased kfunc reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_cpumask_release_rejects_task_reference() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

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
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_cpumask_release".to_string(),
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
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-reference error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("expects cpumask reference")),
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_cpumask_release_dtor_rejects_task_reference() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

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
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_cpumask_release_dtor".to_string(),
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
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-reference error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("expects cpumask reference")),
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_list_push_front_consumes_object_reference() {
    let (mut func, entry) = new_mir_function();
    let push = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let list = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let off = func.alloc_vreg();
    let type_id = func.alloc_vreg();
    let obj = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let push_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: type_id,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: obj,
        kfunc: "bpf_obj_new_impl".to_string(),
        btf_id: None,
        args: vec![type_id, meta],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(obj),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: push,
        if_false: done,
    };

    func.block_mut(push).instructions.push(MirInst::CallKfunc {
        dst: push_ret,
        kfunc: "bpf_list_push_front_impl".to_string(),
        btf_id: None,
        args: vec![list, obj, meta, off],
    });
    func.block_mut(push).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        list,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(meta, MirType::I64);
    types.insert(off, MirType::I64);
    types.insert(type_id, MirType::I64);
    types.insert(
        obj,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(push_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected list_push_front to consume object reference");
}

#[test]
fn test_verify_mir_kfunc_list_push_front_rejects_task_reference_on_arg1() {
    let (mut func, entry) = new_mir_function();
    let push = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let list = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let off = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let push_ret = func.alloc_vreg();
    let task_release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
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
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: push,
        if_false: done,
    };

    func.block_mut(push).instructions.push(MirInst::CallKfunc {
        dst: push_ret,
        kfunc: "bpf_list_push_front_impl".to_string(),
        btf_id: None,
        args: vec![list, task, meta, off],
    });
    func.block_mut(push).instructions.push(MirInst::CallKfunc {
        dst: task_release_ret,
        kfunc: "bpf_task_release".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(push).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        list,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(meta, MirType::I64);
    types.insert(off, MirType::I64);
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(push_ret, MirType::I64);
    types.insert(task_release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected object-ref arg1 mismatch");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects object reference")),
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_list_pop_front_acquires_object_reference() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let list = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let popped = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: popped,
        kfunc: "bpf_list_pop_front".to_string(),
        btf_id: None,
        args: vec![list],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(popped),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_obj_drop_impl".to_string(),
            btf_id: None,
            args: vec![popped, meta],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        list,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(meta, MirType::I64);
    types.insert(
        popped,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected list_pop_front object release to verify");
}

#[test]
fn test_verify_mir_kfunc_list_push_back_consumes_object_reference() {
    let (mut func, entry) = new_mir_function();
    let push = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let list = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let off = func.alloc_vreg();
    let type_id = func.alloc_vreg();
    let obj = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let push_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: type_id,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: obj,
        kfunc: "bpf_obj_new_impl".to_string(),
        btf_id: None,
        args: vec![type_id, meta],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(obj),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: push,
        if_false: done,
    };

    func.block_mut(push).instructions.push(MirInst::CallKfunc {
        dst: push_ret,
        kfunc: "bpf_list_push_back_impl".to_string(),
        btf_id: None,
        args: vec![list, obj, meta, off],
    });
    func.block_mut(push).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        list,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(meta, MirType::I64);
    types.insert(off, MirType::I64);
    types.insert(type_id, MirType::I64);
    types.insert(
        obj,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(push_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected list_push_back to consume object reference");
}

#[test]
fn test_verify_mir_kfunc_list_push_back_rejects_task_reference_on_arg1() {
    let (mut func, entry) = new_mir_function();
    let push = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let list = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let off = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let push_ret = func.alloc_vreg();
    let task_release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
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
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: push,
        if_false: done,
    };

    func.block_mut(push).instructions.push(MirInst::CallKfunc {
        dst: push_ret,
        kfunc: "bpf_list_push_back_impl".to_string(),
        btf_id: None,
        args: vec![list, task, meta, off],
    });
    func.block_mut(push).instructions.push(MirInst::CallKfunc {
        dst: task_release_ret,
        kfunc: "bpf_task_release".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(push).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        list,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(meta, MirType::I64);
    types.insert(off, MirType::I64);
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(push_ret, MirType::I64);
    types.insert(task_release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected object-ref arg1 mismatch");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects object reference")),
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_list_pop_back_acquires_object_reference() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let list = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let popped = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: popped,
        kfunc: "bpf_list_pop_back".to_string(),
        btf_id: None,
        args: vec![list],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(popped),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_obj_drop_impl".to_string(),
            btf_id: None,
            args: vec![popped, meta],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        list,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(meta, MirType::I64);
    types.insert(
        popped,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected list_pop_back object release to verify");
}

#[test]
fn test_verify_mir_kfunc_rbtree_add_consumes_object_reference() {
    let (mut func, entry) = new_mir_function();
    let add = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let tree = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let off = func.alloc_vreg();
    let less = func.alloc_vreg();
    let type_id = func.alloc_vreg();
    let obj = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let add_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: less,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: type_id,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: obj,
        kfunc: "bpf_obj_new_impl".to_string(),
        btf_id: None,
        args: vec![type_id, meta],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(obj),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: add,
        if_false: done,
    };

    func.block_mut(add).instructions.push(MirInst::CallKfunc {
        dst: add_ret,
        kfunc: "bpf_rbtree_add_impl".to_string(),
        btf_id: None,
        args: vec![tree, obj, less, meta, off],
    });
    func.block_mut(add).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        tree,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(meta, MirType::I64);
    types.insert(off, MirType::I64);
    types.insert(less, MirType::I64);
    types.insert(type_id, MirType::I64);
    types.insert(
        obj,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(add_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected rbtree_add to consume object reference");
}

#[test]
fn test_verify_mir_kfunc_rbtree_add_rejects_task_reference_on_arg1() {
    let (mut func, entry) = new_mir_function();
    let add = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let tree = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let off = func.alloc_vreg();
    let less = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let add_ret = func.alloc_vreg();
    let task_release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: less,
        src: MirValue::Const(0),
    });
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
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: add,
        if_false: done,
    };

    func.block_mut(add).instructions.push(MirInst::CallKfunc {
        dst: add_ret,
        kfunc: "bpf_rbtree_add_impl".to_string(),
        btf_id: None,
        args: vec![tree, task, less, meta, off],
    });
    func.block_mut(add).instructions.push(MirInst::CallKfunc {
        dst: task_release_ret,
        kfunc: "bpf_task_release".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(add).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        tree,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(meta, MirType::I64);
    types.insert(off, MirType::I64);
    types.insert(less, MirType::I64);
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(add_ret, MirType::I64);
    types.insert(task_release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected object-ref arg1 mismatch");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects object reference")),
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_rbtree_remove_acquires_object_reference() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 2;

    let tree = func.alloc_vreg();
    let node = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let removed = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: removed,
        kfunc: "bpf_rbtree_remove".to_string(),
        btf_id: None,
        args: vec![tree, node],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(removed),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_obj_drop_impl".to_string(),
            btf_id: None,
            args: vec![removed, meta],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        tree,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        node,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(meta, MirType::I64);
    types.insert(
        removed,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected rbtree_remove object release to verify");
}

#[test]
fn test_verify_mir_kfunc_obj_new_release_semantics() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let meta = func.alloc_vreg();
    let type_id = func.alloc_vreg();
    let obj = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: type_id,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: obj,
        kfunc: "bpf_obj_new_impl".to_string(),
        btf_id: None,
        args: vec![type_id, meta],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(obj),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_obj_drop_impl".to_string(),
            btf_id: None,
            args: vec![obj, meta],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(meta, MirType::I64);
    types.insert(type_id, MirType::I64);
    types.insert(
        obj,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected object reference to be released");
}

#[test]
fn test_verify_mir_kfunc_obj_drop_rejects_task_reference() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let meta = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
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
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_obj_drop_impl".to_string(),
            btf_id: None,
            args: vec![task, meta],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(meta, MirType::I64);
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-reference error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("expects object reference")),
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_percpu_obj_new_release_semantics() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let meta = func.alloc_vreg();
    let type_id = func.alloc_vreg();
    let obj = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: type_id,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: obj,
        kfunc: "bpf_percpu_obj_new_impl".to_string(),
        btf_id: None,
        args: vec![type_id, meta],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(obj),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_percpu_obj_drop_impl".to_string(),
            btf_id: None,
            args: vec![obj, meta],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(meta, MirType::I64);
    types.insert(type_id, MirType::I64);
    types.insert(
        obj,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected percpu object reference to be released");
}

#[test]
fn test_verify_mir_kfunc_percpu_obj_drop_rejects_task_reference() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let meta = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
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
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_percpu_obj_drop_impl".to_string(),
            btf_id: None,
            args: vec![task, meta],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(meta, MirType::I64);
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-reference error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("expects object reference")),
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_refcount_acquire_rejects_task_reference() {
    let (mut func, entry) = new_mir_function();

    let meta = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
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
        dst: acquired,
        kfunc: "bpf_refcount_acquire_impl".to_string(),
        btf_id: None,
        args: vec![task, meta],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(meta, MirType::I64);
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        acquired,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected kfunc provenance mismatch error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects object reference")),
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_task_release_requires_tracked_reference() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected tracked-reference error");
    assert!(
        err.iter().any(|e| {
            e.message.contains("kfunc arg0 pointer is not tracked")
                || e.message.contains("expects acquired task reference")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_task_release_rejects_cgroup_reference() {
    let (mut func, entry) = new_mir_function();
    let release = func.alloc_block();
    let done = func.alloc_block();

    let cgid = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cgid,
        src: MirValue::Const(42),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![cgid],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(cgroup),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![cgroup],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(cgid, MirType::I64);
    types.insert(
        cgroup,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-reference error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("expects task reference")),
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_task_release_rejects_mixed_reference_kinds_after_join() {
    let (mut func, entry) = new_mir_function();
    let task_path = func.alloc_block();
    let cgroup_path = func.alloc_block();
    let join = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let select_cond = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let cgid = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    let release_cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: select_cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: select_cond,
        if_true: task_path,
        if_false: cgroup_path,
    };

    func.block_mut(task_path).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(task_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: acquired,
            kfunc: "bpf_task_from_pid".to_string(),
            btf_id: None,
            args: vec![pid],
        });
    func.block_mut(task_path).terminator = MirInst::Jump { target: join };

    func.block_mut(cgroup_path)
        .instructions
        .push(MirInst::Copy {
            dst: cgid,
            src: MirValue::Const(42),
        });
    func.block_mut(cgroup_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: acquired,
            kfunc: "bpf_cgroup_from_id".to_string(),
            btf_id: None,
            args: vec![cgid],
        });
    func.block_mut(cgroup_path).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: release_cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(acquired),
        rhs: MirValue::Const(0),
    });
    func.block_mut(join).terminator = MirInst::Branch {
        cond: release_cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![acquired],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(select_cond, MirType::Bool);
    types.insert(pid, MirType::I64);
    types.insert(cgid, MirType::I64);
    types.insert(
        acquired,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-kind join release validation");
    assert!(
        err.iter()
            .any(|e| e.message.contains("expects task reference")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_rcu_read_lock_unlock_balanced() {
    let (mut func, entry) = new_mir_function();
    let lock_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: lock_ret,
        kfunc: "bpf_rcu_read_lock".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: unlock_ret,
        kfunc: "bpf_rcu_read_unlock".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(lock_ret, MirType::I64);
    types.insert(unlock_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected balanced rcu read lock/unlock to verify");
}

#[test]
fn test_verify_mir_kfunc_rcu_read_unlock_requires_matching_lock() {
    let (mut func, entry) = new_mir_function();
    let unlock_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: unlock_ret,
        kfunc: "bpf_rcu_read_unlock".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(unlock_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unmatched rcu read unlock error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_rcu_read_lock")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_rcu_read_lock_must_be_released_at_exit() {
    let (mut func, entry) = new_mir_function();
    let lock_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: lock_ret,
        kfunc: "bpf_rcu_read_lock".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(lock_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unreleased rcu read lock error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased RCU read lock")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_rcu_read_unlock_rejected_after_mixed_join() {
    let (mut func, entry) = new_mir_function();
    let lock_path = func.alloc_block();
    let no_lock_path = func.alloc_block();
    let join = func.alloc_block();
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: lock_path,
        if_false: no_lock_path,
    };

    func.block_mut(lock_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: lock_ret,
            kfunc: "bpf_rcu_read_lock".to_string(),
            btf_id: None,
            args: vec![],
        });
    func.block_mut(lock_path).terminator = MirInst::Jump { target: join };
    func.block_mut(no_lock_path).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::CallKfunc {
        dst: unlock_ret,
        kfunc: "bpf_rcu_read_unlock".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(cond, MirType::Bool);
    types.insert(lock_ret, MirType::I64);
    types.insert(unlock_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-path rcu read unlock error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_rcu_read_lock")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_map_sum_elem_count_requires_kernel_pointer_arg() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let map_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_map_sum_elem_count".to_string(),
        btf_id: None,
        args: vec![map_ptr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected kernel-pointer kfunc arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects pointer in [Kernel]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_map_sum_elem_count_accepts_kernel_pointer_arg() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let map_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_map_sum_elem_count".to_string(),
        btf_id: None,
        args: vec![map_ptr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected map_sum_elem_count kernel-pointer call to verify");
}

#[test]
fn test_verify_mir_kfunc_rbtree_root_requires_kernel_pointer_arg() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let root = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_rbtree_root".to_string(),
        btf_id: None,
        args: vec![root],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        root,
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

    let err = verify_mir(&func, &types).expect_err("expected kernel-pointer kfunc arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects pointer in [Kernel]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_rbtree_root_accepts_kernel_pointer_arg() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let root = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_rbtree_root".to_string(),
        btf_id: None,
        args: vec![root],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        root,
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

    verify_mir(&func, &types).expect("expected rbtree_root kernel-pointer call to verify");
}

#[test]
fn test_verify_mir_kfunc_preempt_disable_enable_balanced() {
    let (mut func, entry) = new_mir_function();
    let disable_ret = func.alloc_vreg();
    let enable_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: disable_ret,
        kfunc: "bpf_preempt_disable".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: enable_ret,
        kfunc: "bpf_preempt_enable".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(disable_ret, MirType::I64);
    types.insert(enable_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected balanced preempt disable/enable to verify");
}

#[test]
fn test_verify_mir_kfunc_preempt_enable_requires_matching_disable() {
    let (mut func, entry) = new_mir_function();
    let enable_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: enable_ret,
        kfunc: "bpf_preempt_enable".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(enable_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unmatched preempt_enable error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires a matching bpf_preempt_disable")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_preempt_disable_must_be_released_at_exit() {
    let (mut func, entry) = new_mir_function();
    let disable_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: disable_ret,
        kfunc: "bpf_preempt_disable".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(disable_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unreleased preempt disable error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased preempt disable")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_preempt_enable_rejected_after_mixed_join() {
    let (mut func, entry) = new_mir_function();
    let disable_path = func.alloc_block();
    let no_disable_path = func.alloc_block();
    let join = func.alloc_block();
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let disable_ret = func.alloc_vreg();
    let enable_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: disable_path,
        if_false: no_disable_path,
    };

    func.block_mut(disable_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: disable_ret,
            kfunc: "bpf_preempt_disable".to_string(),
            btf_id: None,
            args: vec![],
        });
    func.block_mut(disable_path).terminator = MirInst::Jump { target: join };
    func.block_mut(no_disable_path).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::CallKfunc {
        dst: enable_ret,
        kfunc: "bpf_preempt_enable".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(cond, MirType::Bool);
    types.insert(disable_ret, MirType::I64);
    types.insert(enable_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-path preempt_enable error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires a matching bpf_preempt_disable")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_local_irq_save_restore_balanced() {
    let (mut func, entry) = new_mir_function();
    let flags = func.alloc_vreg();
    let save_ret = func.alloc_vreg();
    let restore_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::StackSlot(slot),
    });

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: save_ret,
        kfunc: "bpf_local_irq_save".to_string(),
        btf_id: None,
        args: vec![flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: restore_ret,
        kfunc: "bpf_local_irq_restore".to_string(),
        btf_id: None,
        args: vec![flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        flags,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(save_ret, MirType::I64);
    types.insert(restore_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected balanced local irq save/restore to verify");
}

#[test]
fn test_verify_mir_kfunc_local_irq_restore_requires_matching_save() {
    let (mut func, entry) = new_mir_function();
    let flags = func.alloc_vreg();
    let restore_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: restore_ret,
        kfunc: "bpf_local_irq_restore".to_string(),
        btf_id: None,
        args: vec![flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        flags,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(restore_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unmatched local_irq_restore error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_local_irq_save")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_local_irq_restore_requires_matching_save_slot() {
    let (mut func, entry) = new_mir_function();
    let save_flags = func.alloc_vreg();
    let restore_flags = func.alloc_vreg();
    let save_ret = func.alloc_vreg();
    let restore_ret = func.alloc_vreg();
    let save_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let restore_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: save_flags,
        src: MirValue::StackSlot(save_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: restore_flags,
        src: MirValue::StackSlot(restore_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: save_ret,
        kfunc: "bpf_local_irq_save".to_string(),
        btf_id: None,
        args: vec![save_flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: restore_ret,
        kfunc: "bpf_local_irq_restore".to_string(),
        btf_id: None,
        args: vec![restore_flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        save_flags,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        restore_flags,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(save_ret, MirType::I64);
    types.insert(restore_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected local_irq_restore slot mismatch");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_local_irq_save")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_local_irq_save_must_be_released_at_exit() {
    let (mut func, entry) = new_mir_function();
    let flags = func.alloc_vreg();
    let save_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::StackSlot(slot),
    });

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: save_ret,
        kfunc: "bpf_local_irq_save".to_string(),
        btf_id: None,
        args: vec![flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        flags,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(save_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unreleased local irq disable error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased local irq disable")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_local_irq_restore_rejected_after_mixed_join() {
    let (mut func, entry) = new_mir_function();
    let save_path = func.alloc_block();
    let no_save_path = func.alloc_block();
    let join = func.alloc_block();
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let save_ret = func.alloc_vreg();
    let restore_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::StackSlot(slot),
    });

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: save_path,
        if_false: no_save_path,
    };

    func.block_mut(save_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: save_ret,
            kfunc: "bpf_local_irq_save".to_string(),
            btf_id: None,
            args: vec![flags],
        });
    func.block_mut(save_path).terminator = MirInst::Jump { target: join };
    func.block_mut(no_save_path).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::CallKfunc {
        dst: restore_ret,
        kfunc: "bpf_local_irq_restore".to_string(),
        btf_id: None,
        args: vec![flags],
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(cond, MirType::Bool);
    types.insert(
        flags,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(save_ret, MirType::I64);
    types.insert(restore_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-path local_irq_restore error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_local_irq_save")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_res_spin_lock_unlock_balanced() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let lock = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: lock_ret,
        kfunc: "bpf_res_spin_lock".to_string(),
        btf_id: None,
        args: vec![lock],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: unlock_ret,
        kfunc: "bpf_res_spin_unlock".to_string(),
        btf_id: None,
        args: vec![lock],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        lock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(lock_ret, MirType::I64);
    types.insert(unlock_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected balanced res spin lock/unlock to verify");
}

#[test]
fn test_verify_mir_kfunc_res_spin_unlock_requires_matching_lock() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let lock = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: unlock_ret,
        kfunc: "bpf_res_spin_unlock".to_string(),
        btf_id: None,
        args: vec![lock],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        lock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(unlock_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unmatched res_spin_unlock error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_res_spin_lock")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_res_spin_lock_must_be_released_at_exit() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let lock = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: lock_ret,
        kfunc: "bpf_res_spin_lock".to_string(),
        btf_id: None,
        args: vec![lock],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        lock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(lock_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected unreleased res spin lock error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased res spin lock")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_res_spin_unlock_rejected_after_mixed_join() {
    let (mut func, entry) = new_mir_function();
    let lock_path = func.alloc_block();
    let no_lock_path = func.alloc_block();
    let join = func.alloc_block();
    func.param_count = 2;

    let lock = func.alloc_vreg();
    let selector = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: lock_path,
        if_false: no_lock_path,
    };

    func.block_mut(lock_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: lock_ret,
            kfunc: "bpf_res_spin_lock".to_string(),
            btf_id: None,
            args: vec![lock],
        });
    func.block_mut(lock_path).terminator = MirInst::Jump { target: join };
    func.block_mut(no_lock_path).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::CallKfunc {
        dst: unlock_ret,
        kfunc: "bpf_res_spin_unlock".to_string(),
        btf_id: None,
        args: vec![lock],
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        lock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(selector, MirType::I64);
    types.insert(cond, MirType::Bool);
    types.insert(lock_ret, MirType::I64);
    types.insert(unlock_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-path res_spin_unlock error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_res_spin_lock")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_res_spin_lock_irqsave_unlock_irqrestore_balanced() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let lock = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: lock_ret,
        kfunc: "bpf_res_spin_lock_irqsave".to_string(),
        btf_id: None,
        args: vec![lock, flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: unlock_ret,
        kfunc: "bpf_res_spin_unlock_irqrestore".to_string(),
        btf_id: None,
        args: vec![lock, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        lock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        flags,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(lock_ret, MirType::I64);
    types.insert(unlock_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected balanced res spin irqsave/irqrestore to verify");
}

#[test]
fn test_verify_mir_kfunc_res_spin_unlock_irqrestore_requires_matching_lock_irqsave() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let lock = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: unlock_ret,
        kfunc: "bpf_res_spin_unlock_irqrestore".to_string(),
        btf_id: None,
        args: vec![lock, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        lock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        flags,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(unlock_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected unmatched res_spin_unlock_irqrestore error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires a matching bpf_res_spin_lock_irqsave")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_res_spin_unlock_irqrestore_requires_matching_lock_irqsave_slot() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let lock = func.alloc_vreg();
    let save_flags = func.alloc_vreg();
    let restore_flags = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();
    let save_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let restore_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: save_flags,
        src: MirValue::StackSlot(save_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: restore_flags,
        src: MirValue::StackSlot(restore_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: lock_ret,
        kfunc: "bpf_res_spin_lock_irqsave".to_string(),
        btf_id: None,
        args: vec![lock, save_flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: unlock_ret,
        kfunc: "bpf_res_spin_unlock_irqrestore".to_string(),
        btf_id: None,
        args: vec![lock, restore_flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        lock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        save_flags,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        restore_flags,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(lock_ret, MirType::I64);
    types.insert(unlock_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected res_spin irqrestore slot mismatch error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires a matching bpf_res_spin_lock_irqsave")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_res_spin_lock_irqsave_must_be_released_at_exit() {
    let (mut func, entry) = new_mir_function();
    func.param_count = 1;

    let lock = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: lock_ret,
        kfunc: "bpf_res_spin_lock_irqsave".to_string(),
        btf_id: None,
        args: vec![lock, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        lock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        flags,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(lock_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected unreleased res spin irqsave lock error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased res spin lock irqsave")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_res_spin_unlock_irqrestore_rejected_after_mixed_join() {
    let (mut func, entry) = new_mir_function();
    let lock_path = func.alloc_block();
    let no_lock_path = func.alloc_block();
    let join = func.alloc_block();
    func.param_count = 2;

    let lock = func.alloc_vreg();
    let selector = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: lock_path,
        if_false: no_lock_path,
    };

    func.block_mut(lock_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: lock_ret,
            kfunc: "bpf_res_spin_lock_irqsave".to_string(),
            btf_id: None,
            args: vec![lock, flags],
        });
    func.block_mut(lock_path).terminator = MirInst::Jump { target: join };
    func.block_mut(no_lock_path).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::CallKfunc {
        dst: unlock_ret,
        kfunc: "bpf_res_spin_unlock_irqrestore".to_string(),
        btf_id: None,
        args: vec![lock, flags],
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        lock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(selector, MirType::I64);
    types.insert(cond, MirType::Bool);
    types.insert(
        flags,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(lock_ret, MirType::I64);
    types.insert(unlock_ret, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected mixed-path res_spin_unlock_irqrestore error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires a matching bpf_res_spin_lock_irqsave")),
        "unexpected error messages: {:?}",
        err
    );
}
