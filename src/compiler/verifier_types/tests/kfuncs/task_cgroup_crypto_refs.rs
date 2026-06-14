#[test]
fn test_kfunc_task_acquire_release_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
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
fn test_kfunc_task_subfn_release_releases_caller_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let call_ret = func.alloc_vreg();

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
        .push(MirInst::CallSubfn {
            dst: call_ret,
            subfn: crate::compiler::mir::SubfunctionId(0),
            args: vec![acquired],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut subfn = MirFunction::new();
    let sub_entry = subfn.alloc_block();
    subfn.entry = sub_entry;
    subfn.param_count = 1;
    subfn.vreg_count = 1;
    let release_ret = subfn.alloc_vreg();
    subfn
        .block_mut(sub_entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![VReg(0)],
        });
    subfn.block_mut(sub_entry).terminator = MirInst::Return { val: None };

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
    types.insert(call_ret, MirType::I64);
    let summaries = infer_subfunction_summaries(&[subfn]);

    verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect("expected subfunction release to consume caller kfunc reference");
}

#[test]
fn test_kfunc_task_subfn_acquire_return_releases_caller_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst: acquired,
        subfn: SubfunctionId(0),
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

    let mut subfn = MirFunction::new();
    let sub_entry = subfn.alloc_block();
    subfn.entry = sub_entry;
    subfn.param_count = 1;
    subfn.vreg_count = 1;
    let sub_acquired = subfn.alloc_vreg();
    subfn
        .block_mut(sub_entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst: sub_acquired,
            kfunc: "bpf_task_acquire".to_string(),
            btf_id: None,
            args: vec![VReg(0)],
        });
    subfn.block_mut(sub_entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(sub_acquired)),
    };

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

    let mut sub_types = HashMap::new();
    sub_types.insert(
        VReg(0),
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    sub_types.insert(
        sub_acquired,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let summaries = infer_subfunction_summaries(&[subfn.clone()]);
    let summary = summaries
        .get(&SubfunctionId(0))
        .cloned()
        .expect("expected summary");
    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &subfn,
        &sub_types,
        &summaries,
        Some(summary),
        None,
        None,
    )
    .expect("expected subfunction to return acquired reference");

    verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect("expected caller to release subfunction-acquired kfunc reference");
}

#[test]
fn test_kfunc_task_acquire_return_allows_trusted_btf_load() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let pid = func.alloc_vreg();
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

    func.block_mut(release).instructions.push(MirInst::Load {
        dst: pid,
        ptr: acquired,
        offset: 0,
        ty: MirType::I32,
    });
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
    types.insert(task, MirType::named_kernel_struct_ptr("task_struct"));
    types.insert(acquired, MirType::named_kernel_struct_ptr("task_struct"));
    types.insert(pid, MirType::I32);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types)
        .expect("typed kfunc pointer return should preserve trusted BTF load provenance");
}

#[test]
fn test_kfunc_task_acquire_leak_rejected() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let leak = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
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

    let err = verify_mir(&func, &types).expect_err("expected kfunc reference leak error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased kfunc reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_task_from_pid_release_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
fn test_kfunc_task_from_pid_release_semantics_via_copied_cond_with_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;

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
fn test_kfunc_task_from_pid_release_semantics_via_negated_cond() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
        op: crate::compiler::mir::UnaryOpKind::Not,
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
fn test_kfunc_cgroup_from_id_release_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
fn test_kfunc_scx_task_cgroup_release_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
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
fn test_kfunc_scx_task_cgroup_requires_release() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_cgroup_release_rejects_task_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
            .any(|e| e.message.contains("expects acquired cgroup reference")),
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
fn test_kfunc_get_task_exe_file_put_file_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
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
fn test_kfunc_put_file_rejects_task_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
            .any(|e| e.message.contains("expects acquired file reference")),
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
fn test_kfunc_crypto_ctx_acquire_release_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let crypto_ctx = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

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
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_crypto_ctx_release".to_string(),
            btf_id: None,
            args: vec![crypto_ctx],
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
        crypto_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected crypto_ctx reference to be released");
}

#[test]
fn test_kfunc_crypto_ctx_release_rejects_task_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
            kfunc: "bpf_crypto_ctx_release".to_string(),
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
            .any(|e| e.message.contains("expects acquired crypto_ctx reference")),
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
fn test_kfunc_crypto_ctx_create_release_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let params = func.alloc_vreg();
    let params_sz = func.alloc_vreg();
    let err = func.alloc_vreg();
    let crypto_ctx = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let params_slot = func.alloc_stack_slot(512, 8, StackSlotKind::StringBuffer);
    let err_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: params,
        src: MirValue::StackSlot(params_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: params_sz,
        src: MirValue::Const(408),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: err,
        src: MirValue::StackSlot(err_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: crypto_ctx,
        kfunc: "bpf_crypto_ctx_create".to_string(),
        btf_id: None,
        args: vec![params, params_sz, err],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(crypto_ctx),
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
            kfunc: "bpf_crypto_ctx_release".to_string(),
            btf_id: None,
            args: vec![crypto_ctx],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        params,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(params_sz, MirType::I64);
    types.insert(
        err,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        crypto_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected crypto_ctx_create reference to be released");
}

#[test]
fn test_kfunc_crypto_ctx_create_leak_rejected() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let leak = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let params = func.alloc_vreg();
    let params_sz = func.alloc_vreg();
    let err = func.alloc_vreg();
    let crypto_ctx = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let params_slot = func.alloc_stack_slot(512, 8, StackSlotKind::StringBuffer);
    let err_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: params,
        src: MirValue::StackSlot(params_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: params_sz,
        src: MirValue::Const(408),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: err,
        src: MirValue::StackSlot(err_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: crypto_ctx,
        kfunc: "bpf_crypto_ctx_create".to_string(),
        btf_id: None,
        args: vec![params, params_sz, err],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(crypto_ctx),
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
        params,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(params_sz, MirType::I64);
    types.insert(
        err,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        crypto_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);

    let err = verify_mir(&func, &types).expect_err("expected crypto_ctx_create leak error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased kfunc reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_crypto_encrypt_accepts_tracked_crypto_ctx_reference() {
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
    let siv_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

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
        src: MirValue::StackSlot(siv_slot),
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
    types.insert(
        siv,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
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

    verify_mir(&func, &types).expect("expected tracked crypto_ctx to pass bpf_crypto_encrypt");
}

#[test]
fn test_kfunc_crypto_encrypt_rejects_task_reference_argument() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let use_ctx = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let src = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let siv = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let encrypt_ret = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let siv_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

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
        src: MirValue::StackSlot(siv_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
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
            args: vec![task, src, dst, siv],
        });
    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![task],
        });
    func.block_mut(use_ctx).terminator = MirInst::Return { val: None };
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
    types.insert(
        siv,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(encrypt_ret, MirType::I64);
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected crypto_ctx ref-kind mismatch error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects crypto_ctx reference")),
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
fn test_kfunc_crypto_encrypt_src_requires_stack_or_map_space() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let src_ok = func.alloc_block();
    let use_ctx = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let kernel_src = func.alloc_vreg();
    let params = func.alloc_vreg();
    let params_sz = func.alloc_vreg();
    let err = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let siv = func.alloc_vreg();
    let crypto_ctx = func.alloc_vreg();
    let cond_src = func.alloc_vreg();
    let cond_ctx = func.alloc_vreg();
    let encrypt_ret = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let params_slot = func.alloc_stack_slot(512, 8, StackSlotKind::StringBuffer);
    let err_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let siv_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: params,
        src: MirValue::StackSlot(params_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: params_sz,
        src: MirValue::Const(408),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: err,
        src: MirValue::StackSlot(err_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: siv,
        src: MirValue::StackSlot(siv_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond_src,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(kernel_src),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cond_src,
        if_true: src_ok,
        if_false: done,
    };

    func.block_mut(src_ok)
        .instructions
        .push(MirInst::CallKfunc {
            dst: crypto_ctx,
            kfunc: "bpf_crypto_ctx_create".to_string(),
            btf_id: None,
            args: vec![params, params_sz, err],
        });
    func.block_mut(src_ok).instructions.push(MirInst::BinOp {
        dst: cond_ctx,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(crypto_ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(src_ok).terminator = MirInst::Branch {
        cond: cond_ctx,
        if_true: use_ctx,
        if_false: done,
    };

    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: encrypt_ret,
            kfunc: "bpf_crypto_encrypt".to_string(),
            btf_id: None,
            args: vec![crypto_ctx, kernel_src, dst, siv],
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
        kernel_src,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        params,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(params_sz, MirType::I64);
    types.insert(
        err,
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
    types.insert(
        siv,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        crypto_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond_src, MirType::Bool);
    types.insert(cond_ctx, MirType::Bool);
    types.insert(encrypt_ret, MirType::I64);
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected crypto_encrypt src-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc bpf_crypto_encrypt src expects pointer in [Stack, Map], got Kernel")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_crypto_decrypt_src_requires_stack_or_map_space() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let src_ok = func.alloc_block();
    let use_ctx = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let kernel_src = func.alloc_vreg();
    let params = func.alloc_vreg();
    let params_sz = func.alloc_vreg();
    let err = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let siv = func.alloc_vreg();
    let crypto_ctx = func.alloc_vreg();
    let cond_src = func.alloc_vreg();
    let cond_ctx = func.alloc_vreg();
    let decrypt_ret = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let params_slot = func.alloc_stack_slot(512, 8, StackSlotKind::StringBuffer);
    let err_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let siv_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: params,
        src: MirValue::StackSlot(params_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: params_sz,
        src: MirValue::Const(408),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: err,
        src: MirValue::StackSlot(err_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: siv,
        src: MirValue::StackSlot(siv_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond_src,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(kernel_src),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cond_src,
        if_true: src_ok,
        if_false: done,
    };

    func.block_mut(src_ok)
        .instructions
        .push(MirInst::CallKfunc {
            dst: crypto_ctx,
            kfunc: "bpf_crypto_ctx_create".to_string(),
            btf_id: None,
            args: vec![params, params_sz, err],
        });
    func.block_mut(src_ok).instructions.push(MirInst::BinOp {
        dst: cond_ctx,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(crypto_ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(src_ok).terminator = MirInst::Branch {
        cond: cond_ctx,
        if_true: use_ctx,
        if_false: done,
    };

    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: decrypt_ret,
            kfunc: "bpf_crypto_decrypt".to_string(),
            btf_id: None,
            args: vec![crypto_ctx, kernel_src, dst, siv],
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
        kernel_src,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        params,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(params_sz, MirType::I64);
    types.insert(
        err,
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
    types.insert(
        siv,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        crypto_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond_src, MirType::Bool);
    types.insert(cond_ctx, MirType::Bool);
    types.insert(decrypt_ret, MirType::I64);
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected crypto_decrypt src-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc bpf_crypto_decrypt src expects pointer in [Stack, Map], got Kernel")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_crypto_encrypt_dst_requires_stack_slot_base_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let use_ctx = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let params = func.alloc_vreg();
    let params_sz = func.alloc_vreg();
    let err = func.alloc_vreg();
    let src = func.alloc_vreg();
    let dst_base = func.alloc_vreg();
    let dst_shifted = func.alloc_vreg();
    let siv = func.alloc_vreg();
    let crypto_ctx = func.alloc_vreg();
    let cond_ctx = func.alloc_vreg();
    let encrypt_ret = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let params_slot = func.alloc_stack_slot(512, 8, StackSlotKind::StringBuffer);
    let err_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let siv_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: params,
        src: MirValue::StackSlot(params_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: params_sz,
        src: MirValue::Const(408),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: err,
        src: MirValue::StackSlot(err_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: src,
        src: MirValue::StackSlot(src_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dst_base,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: dst_shifted,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(dst_base),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: siv,
        src: MirValue::StackSlot(siv_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: crypto_ctx,
        kfunc: "bpf_crypto_ctx_create".to_string(),
        btf_id: None,
        args: vec![params, params_sz, err],
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond_ctx,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(crypto_ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cond_ctx,
        if_true: use_ctx,
        if_false: done,
    };

    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: encrypt_ret,
            kfunc: "bpf_crypto_encrypt".to_string(),
            btf_id: None,
            args: vec![crypto_ctx, src, dst_shifted, siv],
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
        params,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(params_sz, MirType::I64);
    types.insert(
        err,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
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
        dst_base,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        dst_shifted,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        siv,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        crypto_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond_ctx, MirType::Bool);
    types.insert(encrypt_ret, MirType::I64);
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected crypto_encrypt stack-slot-base error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg2 expects stack slot base pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_crypto_ctx_create_params_requires_stack_or_map_space() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let use_ctx = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let kernel_params = func.alloc_vreg();
    let params_sz = func.alloc_vreg();
    let err = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let crypto_ctx = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let err_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(123),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: kernel_params,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: params_sz,
        src: MirValue::Const(408),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: err,
        src: MirValue::StackSlot(err_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(kernel_params),
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
            dst: crypto_ctx,
            kfunc: "bpf_crypto_ctx_create".to_string(),
            btf_id: None,
            args: vec![kernel_params, params_sz, err],
        });
    func.block_mut(use_ctx)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_task_release".to_string(),
            btf_id: None,
            args: vec![kernel_params],
        });
    func.block_mut(use_ctx).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        kernel_params,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(params_sz, MirType::I64);
    types.insert(
        err,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        crypto_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected crypto_ctx_create params-space error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "kfunc bpf_crypto_ctx_create params expects pointer in [Stack, Map], got Kernel"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_crypto_ctx_create_rejects_zero_params_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let params = func.alloc_vreg();
    let params_sz = func.alloc_vreg();
    let err_ptr = func.alloc_vreg();
    let crypto_ctx = func.alloc_vreg();
    let params_slot = func.alloc_stack_slot(512, 8, StackSlotKind::StringBuffer);
    let err_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: params,
        src: MirValue::StackSlot(params_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: params_sz,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: err_ptr,
        src: MirValue::StackSlot(err_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: crypto_ctx,
        kfunc: "bpf_crypto_ctx_create".to_string(),
        btf_id: None,
        args: vec![params, params_sz, err_ptr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        params,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(params_sz, MirType::I64);
    types.insert(
        err_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        crypto_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected crypto_ctx_create zero-size error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_crypto_ctx_create' arg1 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_crypto_ctx_create_err_requires_stack_slot_base_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let params = func.alloc_vreg();
    let params_sz = func.alloc_vreg();
    let err_base = func.alloc_vreg();
    let err_shifted = func.alloc_vreg();
    let crypto_ctx = func.alloc_vreg();
    let params_slot = func.alloc_stack_slot(512, 8, StackSlotKind::StringBuffer);
    let err_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: params,
        src: MirValue::StackSlot(params_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: params_sz,
        src: MirValue::Const(408),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: err_base,
        src: MirValue::StackSlot(err_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: err_shifted,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(err_base),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: crypto_ctx,
        kfunc: "bpf_crypto_ctx_create".to_string(),
        btf_id: None,
        args: vec![params, params_sz, err_shifted],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        params,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(params_sz, MirType::I64);
    types.insert(
        err_base,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        err_shifted,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        crypto_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    let err =
        verify_mir(&func, &types).expect_err("expected crypto_ctx_create stack-slot-base error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg2 expects stack slot base pointer")),
        "unexpected errors: {:?}",
        err
    );
}

