#[test]
fn test_kfunc_crypto_encrypt_siv_allows_const_zero_scalar() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let use_ctx = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let src = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let siv = func.alloc_vreg();
    let crypto_ctx = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let encrypt_ret = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: src,
        src: MirValue::StackSlot(src_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: siv,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: crypto_ctx,
        kfunc: "bpf_crypto_ctx_acquire".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(crypto_ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: use_ctx,
        if_false: done,
    };

    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: encrypt_ret,
            kfunc: "bpf_crypto_encrypt".to_string(),
            btf_id: None,
            args: vec![crypto_ctx, src, dst, siv],
        });
    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_crypto_ctx_release".to_string(),
            btf_id: None,
            args: vec![crypto_ctx],
        });
    func.block_mut(use_ctx).terminator = MirInst::Return { val: None };
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
        src,
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
    types.insert(siv, MirType::I64);
    types.insert(
        crypto_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(encrypt_ret, MirType::I64);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types)
        .expect("expected nullable bpf_crypto_encrypt siv argument to allow scalar const zero");
}

#[test]
fn test_kfunc_crypto_encrypt_siv_rejects_non_zero_scalar() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let use_ctx = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let src = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let siv = func.alloc_vreg();
    let crypto_ctx = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let encrypt_ret = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: src,
        src: MirValue::StackSlot(src_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: siv,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: crypto_ctx,
        kfunc: "bpf_crypto_ctx_acquire".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(crypto_ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: use_ctx,
        if_false: done,
    };

    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: encrypt_ret,
            kfunc: "bpf_crypto_encrypt".to_string(),
            btf_id: None,
            args: vec![crypto_ctx, src, dst, siv],
        });
    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_crypto_ctx_release".to_string(),
            btf_id: None,
            args: vec![crypto_ctx],
        });
    func.block_mut(use_ctx).terminator = MirInst::Return { val: None };
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
        src,
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
    types.insert(siv, MirType::I64);
    types.insert(
        crypto_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(encrypt_ret, MirType::I64);
    types.insert(release_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected non-zero scalar crypto_encrypt siv error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_crypto_encrypt' arg3 expects null (0) or pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_crypto_encrypt_siv_allows_known_zero_vreg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let use_ctx = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let src = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let siv = func.alloc_vreg();
    let crypto_ctx = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let encrypt_ret = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: src,
        src: MirValue::StackSlot(src_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: siv,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: crypto_ctx,
        kfunc: "bpf_crypto_ctx_acquire".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(crypto_ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: use_ctx,
        if_false: done,
    };

    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: encrypt_ret,
            kfunc: "bpf_crypto_encrypt".to_string(),
            btf_id: None,
            args: vec![crypto_ctx, src, dst, siv],
        });
    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_crypto_ctx_release".to_string(),
            btf_id: None,
            args: vec![crypto_ctx],
        });
    func.block_mut(use_ctx).terminator = MirInst::Return { val: None };
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
        src,
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
    types.insert(siv, MirType::I64);
    types.insert(
        crypto_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(encrypt_ret, MirType::I64);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types)
        .expect("expected nullable bpf_crypto_encrypt siv argument to allow known-zero vreg");
}

#[test]
fn test_kfunc_crypto_encrypt_siv_rejects_non_zero_vreg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let use_ctx = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let src = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let siv = func.alloc_vreg();
    let crypto_ctx = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let encrypt_ret = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: src,
        src: MirValue::StackSlot(src_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: siv,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: crypto_ctx,
        kfunc: "bpf_crypto_ctx_acquire".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(crypto_ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: use_ctx,
        if_false: done,
    };

    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: encrypt_ret,
            kfunc: "bpf_crypto_encrypt".to_string(),
            btf_id: None,
            args: vec![crypto_ctx, src, dst, siv],
        });
    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_crypto_ctx_release".to_string(),
            btf_id: None,
            args: vec![crypto_ctx],
        });
    func.block_mut(use_ctx).terminator = MirInst::Return { val: None };
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
        src,
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
    types.insert(siv, MirType::I64);
    types.insert(
        crypto_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(encrypt_ret, MirType::I64);
    types.insert(release_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected non-zero vreg crypto_encrypt siv error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("kfunc 'bpf_crypto_encrypt' arg3 expects null (0) or pointer")
    }));
}

#[test]
fn test_kfunc_crypto_decrypt_siv_allows_const_zero_scalar() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let use_ctx = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let src = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let siv = func.alloc_vreg();
    let crypto_ctx = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let decrypt_ret = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: src,
        src: MirValue::StackSlot(src_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: siv,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: crypto_ctx,
        kfunc: "bpf_crypto_ctx_acquire".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(crypto_ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: use_ctx,
        if_false: done,
    };

    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: decrypt_ret,
            kfunc: "bpf_crypto_decrypt".to_string(),
            btf_id: None,
            args: vec![crypto_ctx, src, dst, siv],
        });
    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_crypto_ctx_release".to_string(),
            btf_id: None,
            args: vec![crypto_ctx],
        });
    func.block_mut(use_ctx).terminator = MirInst::Return { val: None };
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
        src,
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
    types.insert(siv, MirType::I64);
    types.insert(
        crypto_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(decrypt_ret, MirType::I64);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types)
        .expect("expected nullable bpf_crypto_decrypt siv argument to allow scalar const zero");
}

#[test]
fn test_kfunc_crypto_decrypt_siv_rejects_non_zero_scalar() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let use_ctx = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let src = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let siv = func.alloc_vreg();
    let crypto_ctx = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let decrypt_ret = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: src,
        src: MirValue::StackSlot(src_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: siv,
        src: MirValue::Const(9),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: crypto_ctx,
        kfunc: "bpf_crypto_ctx_acquire".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(crypto_ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: use_ctx,
        if_false: done,
    };

    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: decrypt_ret,
            kfunc: "bpf_crypto_decrypt".to_string(),
            btf_id: None,
            args: vec![crypto_ctx, src, dst, siv],
        });
    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_crypto_ctx_release".to_string(),
            btf_id: None,
            args: vec![crypto_ctx],
        });
    func.block_mut(use_ctx).terminator = MirInst::Return { val: None };
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
        src,
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
    types.insert(siv, MirType::I64);
    types.insert(
        crypto_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(decrypt_ret, MirType::I64);
    types.insert(release_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected non-zero scalar crypto_decrypt siv error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_crypto_decrypt' arg3 expects null (0) or pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_task_new_task_allows_const_zero_scalar() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let iter = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let destroy_ret = func.alloc_vreg();
    let iter_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(iter_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: task,
        src: MirValue::Const(0),
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
    types.insert(task, MirType::I64);
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    verify_mir(&func, &types)
        .expect("expected nullable bpf_iter_task_new task arg to allow scalar const zero");
}

#[test]
fn test_kfunc_iter_task_new_task_rejects_non_zero_scalar() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let iter = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let new_ret = func.alloc_vreg();
    let destroy_ret = func.alloc_vreg();
    let iter_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(iter_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: task,
        src: MirValue::Const(7),
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
    types.insert(task, MirType::I64);
    types.insert(flags, MirType::I64);
    types.insert(new_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected non-zero scalar iter_task_new task error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_iter_task_new' arg1 expects null (0) or pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_res_spin_unlock_irqrestore_requires_matching_lock_irqsave_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_res_spin_lock_irqsave_must_be_released_at_exit() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_res_spin_unlock_irqrestore_rejected_after_mixed_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let lock_path = func.alloc_block();
    let no_lock_path = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_dynptr_slice_buffer_allows_const_zero_scalar() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dptr = func.alloc_vreg();
    let off = func.alloc_vreg();
    let buffer = func.alloc_vreg();
    let size = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.entry_initialized_dynptr_slots.insert(dptr_slot);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dptr,
        src: MirValue::StackSlot(dptr_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: buffer,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_dynptr_slice".to_string(),
        btf_id: None,
        args: vec![dptr, off, buffer, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(off, MirType::I64);
    types.insert(buffer, MirType::I64);
    types.insert(size, MirType::I64);
    types.insert(
        ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    verify_mir(&func, &types)
        .expect("expected nullable bpf_dynptr_slice buffer arg to allow scalar const zero");
}

fn assert_dynptr_slice_requires_positive_size(kfunc: &str) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dptr = func.alloc_vreg();
    let off = func.alloc_vreg();
    let buffer = func.alloc_vreg();
    let size = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.entry_initialized_dynptr_slots.insert(dptr_slot);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dptr,
        src: MirValue::StackSlot(dptr_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: buffer,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: kfunc.to_string(),
        btf_id: None,
        args: vec![dptr, off, buffer, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(off, MirType::I64);
    types.insert(buffer, MirType::I64);
    types.insert(size, MirType::I64);
    types.insert(
        ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected zero-size dynptr_slice error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains(&format!("kfunc '{kfunc}' arg3 must be > 0"))),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_dynptr_slice_requires_positive_size() {
    assert_dynptr_slice_requires_positive_size("bpf_dynptr_slice");
}

#[test]
fn test_kfunc_dynptr_slice_rdwr_requires_positive_size() {
    assert_dynptr_slice_requires_positive_size("bpf_dynptr_slice_rdwr");
}

#[test]
fn test_kfunc_dynptr_slice_buffer_rejects_non_zero_scalar() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dptr = func.alloc_vreg();
    let off = func.alloc_vreg();
    let buffer = func.alloc_vreg();
    let size = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.entry_initialized_dynptr_slots.insert(dptr_slot);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dptr,
        src: MirValue::StackSlot(dptr_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: buffer,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_dynptr_slice".to_string(),
        btf_id: None,
        args: vec![dptr, off, buffer, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(off, MirType::I64);
    types.insert(buffer, MirType::I64);
    types.insert(size, MirType::I64);
    types.insert(
        ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err =
        verify_mir(&func, &types).expect_err("expected non-zero scalar dynptr_slice buffer error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_dynptr_slice' arg2 expects null (0) or pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_dynptr_slice_buffer_allows_known_zero_vreg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dptr = func.alloc_vreg();
    let off = func.alloc_vreg();
    let buffer = func.alloc_vreg();
    let size = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.entry_initialized_dynptr_slots.insert(dptr_slot);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dptr,
        src: MirValue::StackSlot(dptr_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: buffer,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_dynptr_slice".to_string(),
        btf_id: None,
        args: vec![dptr, off, buffer, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(off, MirType::I64);
    types.insert(buffer, MirType::I64);
    types.insert(size, MirType::I64);
    types.insert(
        ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    verify_mir(&func, &types)
        .expect("expected nullable bpf_dynptr_slice buffer arg to allow known-zero vreg");
}

#[test]
fn test_kfunc_dynptr_slice_buffer_rejects_non_zero_vreg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dptr = func.alloc_vreg();
    let off = func.alloc_vreg();
    let buffer = func.alloc_vreg();
    let size = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.entry_initialized_dynptr_slots.insert(dptr_slot);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dptr,
        src: MirValue::StackSlot(dptr_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: buffer,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_dynptr_slice".to_string(),
        btf_id: None,
        args: vec![dptr, off, buffer, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(off, MirType::I64);
    types.insert(buffer, MirType::I64);
    types.insert(size, MirType::I64);
    types.insert(
        ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err =
        verify_mir(&func, &types).expect_err("expected non-zero vreg dynptr_slice buffer error");
    assert!(err.iter().any(|e| {
        e.message
            .contains("kfunc 'bpf_dynptr_slice' arg2 expects null (0) or pointer")
    }));
}

#[test]
fn test_kfunc_dynptr_slice_requires_constant_size_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let size = func.alloc_vreg();
    let dptr = func.alloc_vreg();
    let off = func.alloc_vreg();
    let buffer = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dptr,
        src: MirValue::StackSlot(dptr_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: buffer,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_dynptr_slice".to_string(),
        btf_id: None,
        args: vec![dptr, off, buffer, size],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(size, MirType::I64);
    types.insert(
        dptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(off, MirType::I64);
    types.insert(buffer, MirType::I64);
    types.insert(
        ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err =
        verify_mir(&func, &types).expect_err("expected dynptr_slice constant-size verifier error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_dynptr_slice' arg3 must be known constant")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_xdp_metadata_kfunc_verify_function(
    kfunc: &str,
    outputs: &[(usize, MirType)],
    packet_output_idx: Option<usize>,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let output_vregs = (0..outputs.len())
        .map(|_| func.alloc_vreg())
        .collect::<Vec<_>>();
    let ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    for (idx, (output, (size, _))) in output_vregs.iter().zip(outputs.iter()).enumerate() {
        if packet_output_idx == Some(idx) {
            func.block_mut(entry)
                .instructions
                .push(MirInst::LoadCtxField {
                    dst: *output,
                    field: CtxField::Data,
                    slot: None,
                });
        } else {
            let slot = func.alloc_stack_slot(*size, 8, StackSlotKind::StringBuffer);
            func.block_mut(entry).instructions.push(MirInst::Copy {
                dst: *output,
                src: MirValue::StackSlot(slot),
            });
        }
    }
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: kfunc.to_string(),
        btf_id: None,
        args: std::iter::once(ctx)
            .chain(output_vregs.iter().copied())
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
    for (idx, (output, (_, pointee))) in output_vregs.iter().zip(outputs.iter()).enumerate() {
        types.insert(
            *output,
            MirType::Ptr {
                pointee: Box::new(if packet_output_idx == Some(idx) {
                    MirType::U8
                } else {
                    pointee.clone()
                }),
                address_space: if packet_output_idx == Some(idx) {
                    AddressSpace::Packet
                } else {
                    AddressSpace::Stack
                },
            },
        );
    }
    types.insert(ret, MirType::I64);

    (func, types)
}

fn assert_xdp_metadata_kfunc_accepts_stack_outputs(kfunc: &str, outputs: &[(usize, MirType)]) {
    let (func, types) = make_xdp_metadata_kfunc_verify_function(kfunc, outputs, None);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .unwrap_or_else(|err| panic!("expected {kfunc} to accept stack output buffers: {err:?}"));
}

fn assert_xdp_metadata_kfunc_rejects_packet_output(kfunc: &str, outputs: &[(usize, MirType)]) {
    for packet_idx in 0..outputs.len() {
        let (func, types) =
            make_xdp_metadata_kfunc_verify_function(kfunc, outputs, Some(packet_idx));
        let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
        let err = match verify_mir_for_probe_context(&func, &types, &probe_ctx) {
            Ok(()) => panic!("expected {kfunc} output {packet_idx} to reject packet buffer"),
            Err(err) => err,
        };
        assert!(
            err.iter().any(|e| e.message.contains("got Packet")),
            "unexpected errors for {kfunc} output {packet_idx}: {:?}",
            err
        );
    }
}

#[test]
fn test_xdp_metadata_rx_timestamp_accepts_stack_output_buffer() {
    assert_xdp_metadata_kfunc_accepts_stack_outputs(
        "bpf_xdp_metadata_rx_timestamp",
        &[(8, MirType::U64)],
    );
}

#[test]
fn test_xdp_metadata_rx_timestamp_rejects_packet_output_buffer() {
    assert_xdp_metadata_kfunc_rejects_packet_output(
        "bpf_xdp_metadata_rx_timestamp",
        &[(8, MirType::U64)],
    );
}

#[test]
fn test_xdp_metadata_rx_hash_accepts_stack_output_buffers() {
    assert_xdp_metadata_kfunc_accepts_stack_outputs(
        "bpf_xdp_metadata_rx_hash",
        &[(4, MirType::U32), (4, MirType::U32)],
    );
}

#[test]
fn test_xdp_metadata_rx_hash_rejects_packet_output_buffers() {
    assert_xdp_metadata_kfunc_rejects_packet_output(
        "bpf_xdp_metadata_rx_hash",
        &[(4, MirType::U32), (4, MirType::U32)],
    );
}

#[test]
fn test_xdp_metadata_rx_vlan_tag_accepts_stack_output_buffers() {
    assert_xdp_metadata_kfunc_accepts_stack_outputs(
        "bpf_xdp_metadata_rx_vlan_tag",
        &[(2, MirType::U16), (2, MirType::U16)],
    );
}

#[test]
fn test_xdp_metadata_rx_vlan_tag_rejects_packet_output_buffers() {
    assert_xdp_metadata_kfunc_rejects_packet_output(
        "bpf_xdp_metadata_rx_vlan_tag",
        &[(2, MirType::U16), (2, MirType::U16)],
    );
}

fn make_xdp_metadata_rx_timestamp_verify_function_with_copied_arg0(
    arg0_field: CtxField,
    arg0_type: MirType,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let ctx_alias = func.alloc_vreg();
    let timestamp = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let timestamp_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: arg0_field,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ctx_alias,
        src: MirValue::VReg(ctx),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: timestamp,
        src: MirValue::StackSlot(timestamp_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_xdp_metadata_rx_timestamp".to_string(),
        btf_id: None,
        args: vec![ctx_alias, timestamp],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ctx, arg0_type.clone());
    types.insert(ctx_alias, arg0_type);
    types.insert(
        timestamp,
        MirType::Ptr {
            pointee: Box::new(MirType::U64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(ret, MirType::I64);

    (func, types)
}

#[test]
fn test_xdp_metadata_rx_timestamp_accepts_copied_raw_context_arg0() {
    let (func, types) = make_xdp_metadata_rx_timestamp_verify_function_with_copied_arg0(
        CtxField::Context,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected copied raw xdp context to satisfy metadata kfunc arg0");
}

#[test]
fn test_xdp_metadata_rx_timestamp_rejects_copied_packet_arg0() {
    let (func, types) = make_xdp_metadata_rx_timestamp_verify_function_with_copied_arg0(
        CtxField::Data,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        },
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected copied packet pointer to fail metadata kfunc arg0");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_xdp_metadata_rx_timestamp' arg0 expects xdp_md pointer")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_sock_ops_enable_tx_tstamp_verify_function_with_copied_arg0(
    arg0_field: CtxField,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let ctx_alias = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: arg0_field,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ctx_alias,
        src: MirValue::VReg(ctx),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_sock_ops_enable_tx_tstamp".to_string(),
        btf_id: None,
        args: vec![ctx_alias, flags],
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
        ctx_alias,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(ret, MirType::I64);

    (func, types)
}

#[test]
fn test_sock_ops_enable_tx_tstamp_accepts_copied_raw_context_arg0() {
    let (func, types) =
        make_sock_ops_enable_tx_tstamp_verify_function_with_copied_arg0(CtxField::Context);
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected copied raw sock_ops context to satisfy tx timestamp kfunc arg0");
}

#[test]
fn test_sock_ops_enable_tx_tstamp_rejects_copied_socket_arg0() {
    let (func, types) =
        make_sock_ops_enable_tx_tstamp_verify_function_with_copied_arg0(CtxField::Socket);
    let probe_ctx = ProbeContext::new(EbpfProgramType::SockOps, "/sys/fs/cgroup");

    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected copied socket pointer to fail tx timestamp kfunc arg0");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_sock_ops_enable_tx_tstamp' arg0 expects bpf_sock_ops pointer")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_sock_addr_set_sun_path_verify_function_with_copied_arg0(
    arg0_field: CtxField,
) -> (MirFunction, HashMap<VReg, MirType>) {
    make_sock_addr_set_sun_path_verify_function_with_size(arg0_field, 17)
}

fn make_sock_addr_set_sun_path_verify_function_with_size(
    arg0_field: CtxField,
    size_value: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let ctx_alias = func.alloc_vreg();
    let path = func.alloc_vreg();
    let size = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let path_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: arg0_field,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ctx_alias,
        src: MirValue::VReg(ctx),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: path,
        src: MirValue::StackSlot(path_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(size_value),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_sock_addr_set_sun_path".to_string(),
        btf_id: None,
        args: vec![ctx_alias, path, size],
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
        ctx_alias,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        path,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(ret, MirType::I64);

    (func, types)
}

#[test]
fn test_sock_addr_set_sun_path_rejects_zero_size() {
    let (func, types) = make_sock_addr_set_sun_path_verify_function_with_size(CtxField::Context, 0);
    let probe_ctx = ProbeContext::new(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect_unix",
    );

    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected zero-size sun_path kfunc arg2 to fail");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_sock_addr_set_sun_path' arg2 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_sock_addr_set_sun_path_accepts_copied_raw_context_arg0() {
    let (func, types) =
        make_sock_addr_set_sun_path_verify_function_with_copied_arg0(CtxField::Context);
    let probe_ctx = ProbeContext::new(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect_unix",
    );

    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected copied raw cgroup_sock_addr context to satisfy sun_path kfunc arg0");
}

#[test]
fn test_sock_addr_set_sun_path_rejects_copied_socket_arg0() {
    let (func, types) =
        make_sock_addr_set_sun_path_verify_function_with_copied_arg0(CtxField::Socket);
    let probe_ctx = ProbeContext::new(
        EbpfProgramType::CgroupSockAddr,
        "/sys/fs/cgroup:connect_unix",
    );

    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected copied socket pointer to fail sun_path kfunc arg0");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_sock_addr_set_sun_path' arg0 expects bpf_sock_addr pointer")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_xdp_get_xfrm_state_verify_function(
    opts_size: i64,
    buffer_size: usize,
    release_state: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    make_xdp_get_xfrm_state_verify_function_with_arg0(
        CtxField::Context,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
        opts_size,
        buffer_size,
        release_state,
    )
}

fn make_xdp_get_xfrm_state_verify_function_with_arg0(
    arg0_field: CtxField,
    arg0_type: MirType,
    opts_size: i64,
    buffer_size: usize,
    release_state: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    make_xdp_get_xfrm_state_verify_function_with_arg0_copy(
        arg0_field,
        arg0_type,
        opts_size,
        buffer_size,
        release_state,
        false,
    )
}

fn make_xdp_get_xfrm_state_verify_function_with_copied_arg0(
    arg0_field: CtxField,
    arg0_type: MirType,
    opts_size: i64,
    buffer_size: usize,
    release_state: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    make_xdp_get_xfrm_state_verify_function_with_arg0_copy(
        arg0_field,
        arg0_type,
        opts_size,
        buffer_size,
        release_state,
        true,
    )
}

fn make_xdp_get_xfrm_state_verify_function_with_arg0_copy(
    arg0_field: CtxField,
    arg0_type: MirType,
    opts_size: i64,
    buffer_size: usize,
    release_state: bool,
    copy_arg0: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let call_ctx = if copy_arg0 { func.alloc_vreg() } else { ctx };
    let opts = func.alloc_vreg();
    let size = func.alloc_vreg();
    let state = func.alloc_vreg();
    let state_non_null = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let opts_slot = func.alloc_stack_slot(buffer_size, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: arg0_field,
            slot: None,
        });
    if copy_arg0 {
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: call_ctx,
            src: MirValue::VReg(ctx),
        });
    }
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: opts,
        src: MirValue::StackSlot(opts_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(opts_size),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: state,
        kfunc: "bpf_xdp_get_xfrm_state".to_string(),
        btf_id: None,
        args: vec![call_ctx, opts, size],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: state_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(state),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: state_non_null,
        if_true: release,
        if_false: done,
    };

    if release_state {
        func.block_mut(release)
            .instructions
            .push(MirInst::CallKfunc {
                dst: release_ret,
                kfunc: "bpf_xdp_xfrm_state_release".to_string(),
                btf_id: None,
                args: vec![state],
            });
    }
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ctx, arg0_type.clone());
    if copy_arg0 {
        types.insert(call_ctx, arg0_type);
    }
    types.insert(
        opts,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(
        state,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(state_non_null, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    (func, types)
}

#[test]
fn test_xdp_get_xfrm_state_release_accepts_xdp() {
    let (func, types) = make_xdp_get_xfrm_state_verify_function(32, 32, true);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected bpf_xdp_get_xfrm_state reference to be released");
}

#[test]
fn test_xdp_get_xfrm_state_rejects_non_xdp_program() {
    let (func, types) = make_xdp_get_xfrm_state_verify_function(32, 32, true);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_xdp_get_xfrm_state to be rejected outside xdp");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_xdp_get_xfrm_state' is only valid in xdp programs")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_xdp_get_xfrm_state_requires_release() {
    let (func, types) = make_xdp_get_xfrm_state_verify_function(32, 32, false);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected unreleased bpf_xdp_get_xfrm_state reference");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased kfunc reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_xdp_get_xfrm_state_rejects_small_opts_buffer() {
    let (func, types) = make_xdp_get_xfrm_state_verify_function(32, 16, true);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_xdp_get_xfrm_state opts bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc bpf_xdp_get_xfrm_state opts out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_xdp_get_xfrm_state_rejects_zero_opts_size() {
    let (func, types) = make_xdp_get_xfrm_state_verify_function(0, 32, true);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_xdp_get_xfrm_state zero-size opts error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_xdp_get_xfrm_state' arg2 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_xdp_get_xfrm_state_rejects_packet_pointer_arg0() {
    let (func, types) = make_xdp_get_xfrm_state_verify_function_with_arg0(
        CtxField::Data,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        },
        32,
        32,
        true,
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_xdp_get_xfrm_state arg0 context pointer error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_xdp_get_xfrm_state' arg0 expects xdp_md pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_xdp_get_xfrm_state_accepts_copied_raw_context_arg0() {
    let (func, types) = make_xdp_get_xfrm_state_verify_function_with_copied_arg0(
        CtxField::Context,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
        32,
        32,
        true,
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected copied raw xdp context to satisfy xfrm kfunc arg0");
}

#[test]
fn test_xdp_get_xfrm_state_rejects_copied_packet_arg0() {
    let (func, types) = make_xdp_get_xfrm_state_verify_function_with_copied_arg0(
        CtxField::Data,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        },
        32,
        32,
        true,
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected copied packet pointer to fail bpf_xdp_get_xfrm_state arg0");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_xdp_get_xfrm_state' arg0 expects xdp_md pointer")),
        "unexpected errors: {:?}",
        err
    );
}
