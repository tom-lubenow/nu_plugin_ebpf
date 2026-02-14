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
