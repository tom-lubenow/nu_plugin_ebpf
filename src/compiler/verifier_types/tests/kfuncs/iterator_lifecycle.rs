#[test]
fn test_kfunc_iter_scx_dsq_lifecycle_balanced() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
fn test_kfunc_iter_scx_dsq_next_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_scx_dsq_destroy_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_scx_dsq_new_must_be_destroyed_at_exit() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_num_lifecycle_balanced() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
fn test_kfunc_iter_num_subfn_new_destroy_balanced() {
    let mut new = MirFunction::new();
    let new_entry = new.alloc_block();
    new.entry = new_entry;
    new.param_count = 3;
    new.vreg_count = 3;
    let new_slot = new.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    new.param_stack_slots.insert(0, new_slot);
    let new_ret = new.alloc_vreg();
    new.block_mut(new_entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst: new_ret,
            kfunc: "bpf_iter_num_new".to_string(),
            btf_id: None,
            args: vec![VReg(0), VReg(1), VReg(2)],
        });
    new.block_mut(new_entry).terminator = MirInst::Return { val: None };

    let mut destroy = MirFunction::new();
    let destroy_entry = destroy.alloc_block();
    destroy.entry = destroy_entry;
    destroy.param_count = 1;
    destroy.vreg_count = 1;
    let destroy_slot = destroy.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    destroy.param_stack_slots.insert(0, destroy_slot);
    let destroy_ret = destroy.alloc_vreg();
    destroy
        .block_mut(destroy_entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst: destroy_ret,
            kfunc: "bpf_iter_num_destroy".to_string(),
            btf_id: None,
            args: vec![VReg(0)],
        });
    destroy.block_mut(destroy_entry).terminator = MirInst::Return { val: None };

    let summaries = infer_subfunction_summaries(&[new.clone(), destroy.clone()]);
    let new_summary = summaries
        .get(&SubfunctionId(0))
        .cloned()
        .expect("expected iter new summary");
    let destroy_summary = summaries
        .get(&SubfunctionId(1))
        .cloned()
        .expect("expected iter destroy summary");
    let iter_ty = MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::Stack,
    };
    let mut new_types = HashMap::new();
    new_types.insert(VReg(0), iter_ty.clone());
    new_types.insert(VReg(1), MirType::I64);
    new_types.insert(VReg(2), MirType::I64);
    new_types.insert(new_ret, MirType::I64);
    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &new,
        &new_types,
        &summaries,
        Some(new_summary),
        None,
        None,
    )
    .expect("expected iter new wrapper to verify");
    let mut destroy_types = HashMap::new();
    destroy_types.insert(VReg(0), iter_ty.clone());
    destroy_types.insert(destroy_ret, MirType::I64);
    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &destroy,
        &destroy_types,
        &summaries,
        Some(destroy_summary),
        None,
        None,
    )
    .expect("expected iter destroy wrapper to verify");

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let iter = func.alloc_vreg();
    let start = func.alloc_vreg();
    let end = func.alloc_vreg();
    let call_new_ret = func.alloc_vreg();
    let next_ret = func.alloc_vreg();
    let call_destroy_ret = func.alloc_vreg();
    let iter_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(iter_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: start,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: end,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst: call_new_ret,
        subfn: SubfunctionId(0),
        args: vec![iter, start, end],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: next_ret,
        kfunc: "bpf_iter_num_next".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst: call_destroy_ret,
        subfn: SubfunctionId(1),
        args: vec![iter],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(iter, iter_ty);
    types.insert(start, MirType::I64);
    types.insert(end, MirType::I64);
    types.insert(call_new_ret, MirType::I64);
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(call_destroy_ret, MirType::I64);
    verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect("expected iter_num new/destroy wrappers to balance");
}

#[test]
fn test_kfunc_iter_num_new_rejects_reinit_live_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let iter = func.alloc_vreg();
    let start = func.alloc_vreg();
    let mid = func.alloc_vreg();
    let end = func.alloc_vreg();
    let first_new_ret = func.alloc_vreg();
    let second_new_ret = func.alloc_vreg();
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
        dst: mid,
        src: MirValue::Const(4),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: end,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: first_new_ret,
        kfunc: "bpf_iter_num_new".to_string(),
        btf_id: None,
        args: vec![iter, start, mid],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: second_new_ret,
        kfunc: "bpf_iter_num_new".to_string(),
        btf_id: None,
        args: vec![iter, mid, end],
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
    types.insert(mid, MirType::I64);
    types.insert(end, MirType::I64);
    types.insert(first_new_ret, MirType::I64);
    types.insert(second_new_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected iter_num_new reinit error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires uninitialized bpf_iter_num stack object slot")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_num_new_rejects_reinit_after_mixed_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let new_path = func.alloc_block();
    let no_new_path = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let iter = func.alloc_vreg();
    let start = func.alloc_vreg();
    let mid = func.alloc_vreg();
    let end = func.alloc_vreg();
    let first_new_ret = func.alloc_vreg();
    let second_new_ret = func.alloc_vreg();
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
        dst: mid,
        src: MirValue::Const(4),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: end,
        src: MirValue::Const(8),
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
            dst: first_new_ret,
            kfunc: "bpf_iter_num_new".to_string(),
            btf_id: None,
            args: vec![iter, start, mid],
        });
    func.block_mut(new_path).terminator = MirInst::Jump { target: join };
    func.block_mut(no_new_path).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::CallKfunc {
        dst: second_new_ret,
        kfunc: "bpf_iter_num_new".to_string(),
        btf_id: None,
        args: vec![iter, mid, end],
    });
    func.block_mut(join).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_num_destroy".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(cond, MirType::Bool);
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(start, MirType::I64);
    types.insert(mid, MirType::I64);
    types.insert(end, MirType::I64);
    types.insert(first_new_ret, MirType::I64);
    types.insert(second_new_ret, MirType::I64);
    types.insert(destroy_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mixed-path iter_num_new reinit error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires uninitialized bpf_iter_num stack object slot")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_num_next_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_num_destroy_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_num_new_must_be_destroyed_at_exit() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_bits_lifecycle_balanced() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
fn test_kfunc_iter_bits_next_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_bits_destroy_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_bits_new_must_be_destroyed_at_exit() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_dmabuf_lifecycle_balanced() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
fn test_kfunc_iter_dmabuf_next_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_dmabuf_destroy_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_dmabuf_new_must_be_destroyed_at_exit() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_kmem_cache_lifecycle_balanced() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
fn test_kfunc_iter_kmem_cache_next_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_kmem_cache_destroy_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_kmem_cache_new_must_be_destroyed_at_exit() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_css_lifecycle_balanced() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
fn test_kfunc_iter_css_next_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_css_destroy_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_css_new_must_be_destroyed_at_exit() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_css_task_lifecycle_balanced() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
fn test_kfunc_iter_css_task_next_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_css_task_destroy_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_css_task_new_must_be_destroyed_at_exit() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_task_lifecycle_balanced() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
fn test_kfunc_iter_task_next_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_task_destroy_requires_matching_new_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_iter_task_new_must_be_destroyed_at_exit() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

