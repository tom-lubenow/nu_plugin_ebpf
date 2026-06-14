#[test]
fn test_kfunc_cpumask_create_release_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
fn test_kfunc_cpumask_create_release_dtor_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
fn test_kfunc_scx_get_online_cpumask_put_release_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
fn test_kfunc_scx_get_online_cpumask_requires_release() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_cpumask_release_rejects_task_reference() {
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
            .any(|e| e.message.contains("expects acquired cpumask reference")),
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
fn test_kfunc_cpumask_release_dtor_rejects_task_reference() {
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
            .any(|e| e.message.contains("expects acquired cpumask reference")),
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
fn test_kfunc_list_push_front_consumes_object_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let push = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let list = func.alloc_vreg();
    func.param_non_null.insert(list.0 as usize);
    let lock = func.alloc_vreg();
    func.param_non_null.insert(lock.0 as usize);
    let meta = func.alloc_vreg();
    let off = func.alloc_vreg();
    let type_id = func.alloc_vreg();
    let obj = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let push_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();

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

    push_bpf_spin_lock_call(&mut func, push, lock_ret, lock);
    func.block_mut(push).instructions.push(MirInst::CallKfunc {
        dst: push_ret,
        kfunc: "bpf_list_push_front_impl".to_string(),
        btf_id: None,
        args: vec![list, obj, meta, off],
    });
    push_bpf_spin_unlock_call(&mut func, push, unlock_ret, lock);
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
    insert_bpf_spin_lock_types(&mut types, lock, lock_ret, unlock_ret);

    verify_mir(&func, &types).expect("expected list_push_front to consume object reference");
}

#[test]
fn test_kfunc_list_push_front_rejects_task_reference_on_arg1() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let push = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
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
            .any(|e| e.message.contains("arg1 expects acquired object reference")),
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
fn test_kfunc_list_pop_front_acquires_object_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let list = func.alloc_vreg();
    func.param_non_null.insert(list.0 as usize);
    let lock = func.alloc_vreg();
    func.param_non_null.insert(lock.0 as usize);
    let meta = func.alloc_vreg();
    let popped = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    push_bpf_spin_lock_call(&mut func, entry, lock_ret, lock);
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: popped,
        kfunc: "bpf_list_pop_front".to_string(),
        btf_id: None,
        args: vec![list],
    });
    push_bpf_spin_unlock_call(&mut func, entry, unlock_ret, lock);
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
    insert_bpf_spin_lock_types(&mut types, lock, lock_ret, unlock_ret);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected list_pop_front object release to verify");
}

#[test]
fn test_kfunc_list_push_back_consumes_object_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let push = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let list = func.alloc_vreg();
    func.param_non_null.insert(list.0 as usize);
    let lock = func.alloc_vreg();
    func.param_non_null.insert(lock.0 as usize);
    let meta = func.alloc_vreg();
    let off = func.alloc_vreg();
    let type_id = func.alloc_vreg();
    let obj = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let push_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();

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

    push_bpf_spin_lock_call(&mut func, push, lock_ret, lock);
    func.block_mut(push).instructions.push(MirInst::CallKfunc {
        dst: push_ret,
        kfunc: "bpf_list_push_back_impl".to_string(),
        btf_id: None,
        args: vec![list, obj, meta, off],
    });
    push_bpf_spin_unlock_call(&mut func, push, unlock_ret, lock);
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
    insert_bpf_spin_lock_types(&mut types, lock, lock_ret, unlock_ret);

    verify_mir(&func, &types).expect("expected list_push_back to consume object reference");
}

#[test]
fn test_kfunc_list_push_rejects_nonzero_meta() {
    for kfunc in ["bpf_list_push_front_impl", "bpf_list_push_back_impl"] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let push = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;
        func.param_count = 2;

        let list = func.alloc_vreg();
        func.param_non_null.insert(list.0 as usize);
        let lock = func.alloc_vreg();
        func.param_non_null.insert(lock.0 as usize);
        let new_meta = func.alloc_vreg();
        let push_meta = func.alloc_vreg();
        let off = func.alloc_vreg();
        let type_id = func.alloc_vreg();
        let obj = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let lock_ret = func.alloc_vreg();
        let push_ret = func.alloc_vreg();
        let unlock_ret = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: new_meta,
            src: MirValue::Const(0),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: push_meta,
            src: MirValue::Const(1),
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
            args: vec![type_id, new_meta],
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

        push_bpf_spin_lock_call(&mut func, push, lock_ret, lock);
        func.block_mut(push).instructions.push(MirInst::CallKfunc {
            dst: push_ret,
            kfunc: kfunc.to_string(),
            btf_id: None,
            args: vec![list, obj, push_meta, off],
        });
        push_bpf_spin_unlock_call(&mut func, push, unlock_ret, lock);
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
        types.insert(new_meta, MirType::I64);
        types.insert(push_meta, MirType::I64);
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
        insert_bpf_spin_lock_types(&mut types, lock, lock_ret, unlock_ret);

        let err =
            verify_mir(&func, &types).expect_err(&format!("expected {kfunc} nonzero meta error"));
        assert!(
            err.iter().any(|e| e
                .message
                .contains(&format!("kfunc '{kfunc}' arg2 must be known zero"))),
            "unexpected errors for {kfunc}: {:?}",
            err
        );
    }
}

#[test]
fn test_kfunc_list_push_rejects_dynamic_meta() {
    for kfunc in ["bpf_list_push_front_impl", "bpf_list_push_back_impl"] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let push = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;
        func.param_count = 2;

        let list = func.alloc_vreg();
        func.param_non_null.insert(list.0 as usize);
        let lock = func.alloc_vreg();
        func.param_non_null.insert(lock.0 as usize);
        let new_meta = func.alloc_vreg();
        let push_meta = func.alloc_vreg();
        let off = func.alloc_vreg();
        let type_id = func.alloc_vreg();
        let obj = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let lock_ret = func.alloc_vreg();
        let push_ret = func.alloc_vreg();
        let unlock_ret = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: new_meta,
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
            args: vec![type_id, new_meta],
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

        push_bpf_spin_lock_call(&mut func, push, lock_ret, lock);
        func.block_mut(push).instructions.push(MirInst::CallKfunc {
            dst: push_ret,
            kfunc: kfunc.to_string(),
            btf_id: None,
            args: vec![list, obj, push_meta, off],
        });
        push_bpf_spin_unlock_call(&mut func, push, unlock_ret, lock);
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
        types.insert(new_meta, MirType::I64);
        types.insert(push_meta, MirType::I64);
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
        insert_bpf_spin_lock_types(&mut types, lock, lock_ret, unlock_ret);

        let err =
            verify_mir(&func, &types).expect_err(&format!("expected {kfunc} dynamic meta error"));
        assert!(
            err.iter().any(|e| e
                .message
                .contains(&format!("kfunc '{kfunc}' arg2 must be known zero"))),
            "unexpected errors for {kfunc}: {:?}",
            err
        );
    }
}

#[test]
fn test_kfunc_list_push_back_rejects_task_reference_on_arg1() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let push = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
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
            .any(|e| e.message.contains("arg1 expects acquired object reference")),
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
fn test_kfunc_list_pop_back_acquires_object_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let list = func.alloc_vreg();
    func.param_non_null.insert(list.0 as usize);
    let lock = func.alloc_vreg();
    func.param_non_null.insert(lock.0 as usize);
    let meta = func.alloc_vreg();
    let popped = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    push_bpf_spin_lock_call(&mut func, entry, lock_ret, lock);
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: popped,
        kfunc: "bpf_list_pop_back".to_string(),
        btf_id: None,
        args: vec![list],
    });
    push_bpf_spin_unlock_call(&mut func, entry, unlock_ret, lock);
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
    insert_bpf_spin_lock_types(&mut types, lock, lock_ret, unlock_ret);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected list_pop_back object release to verify");
}

#[test]
fn test_kfunc_rbtree_add_consumes_object_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let add = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let tree = func.alloc_vreg();
    func.param_non_null.insert(tree.0 as usize);
    let lock = func.alloc_vreg();
    func.param_non_null.insert(lock.0 as usize);
    let meta = func.alloc_vreg();
    let off = func.alloc_vreg();
    let less = func.alloc_vreg();
    let type_id = func.alloc_vreg();
    let obj = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let add_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: less,
            subfn: SubfunctionId(0),
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

    push_bpf_spin_lock_call(&mut func, add, lock_ret, lock);
    func.block_mut(add).instructions.push(MirInst::CallKfunc {
        dst: add_ret,
        kfunc: "bpf_rbtree_add_impl".to_string(),
        btf_id: None,
        args: vec![tree, obj, less, meta, off],
    });
    push_bpf_spin_unlock_call(&mut func, add, unlock_ret, lock);
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
    types.insert(
        less,
        MirType::Subprogram {
            args: vec![
                MirType::Ptr {
                    pointee: Box::new(MirType::bpf_rb_node_struct()),
                    address_space: AddressSpace::Kernel,
                },
                MirType::Ptr {
                    pointee: Box::new(MirType::bpf_rb_node_struct()),
                    address_space: AddressSpace::Kernel,
                },
            ],
            ret: Box::new(MirType::I64),
        },
    );
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
    insert_bpf_spin_lock_types(&mut types, lock, lock_ret, unlock_ret);

    verify_mir(&func, &types).expect("expected rbtree_add to consume object reference");
}

#[test]
fn test_kfunc_rbtree_add_rejects_nonzero_meta() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let add = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let tree = func.alloc_vreg();
    func.param_non_null.insert(tree.0 as usize);
    let lock = func.alloc_vreg();
    func.param_non_null.insert(lock.0 as usize);
    let new_meta = func.alloc_vreg();
    let add_meta = func.alloc_vreg();
    let off = func.alloc_vreg();
    let less = func.alloc_vreg();
    let type_id = func.alloc_vreg();
    let obj = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let add_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: new_meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: add_meta,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: less,
            subfn: SubfunctionId(0),
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: type_id,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: obj,
        kfunc: "bpf_obj_new_impl".to_string(),
        btf_id: None,
        args: vec![type_id, new_meta],
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

    push_bpf_spin_lock_call(&mut func, add, lock_ret, lock);
    func.block_mut(add).instructions.push(MirInst::CallKfunc {
        dst: add_ret,
        kfunc: "bpf_rbtree_add_impl".to_string(),
        btf_id: None,
        args: vec![tree, obj, less, add_meta, off],
    });
    push_bpf_spin_unlock_call(&mut func, add, unlock_ret, lock);
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
    types.insert(new_meta, MirType::I64);
    types.insert(add_meta, MirType::I64);
    types.insert(off, MirType::I64);
    types.insert(
        less,
        MirType::Subprogram {
            args: vec![
                MirType::Ptr {
                    pointee: Box::new(MirType::bpf_rb_node_struct()),
                    address_space: AddressSpace::Kernel,
                },
                MirType::Ptr {
                    pointee: Box::new(MirType::bpf_rb_node_struct()),
                    address_space: AddressSpace::Kernel,
                },
            ],
            ret: Box::new(MirType::I64),
        },
    );
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
    insert_bpf_spin_lock_types(&mut types, lock, lock_ret, unlock_ret);

    let err = verify_mir(&func, &types).expect_err("expected rbtree_add nonzero meta error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_rbtree_add_impl' arg3 must be known zero")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_rbtree_add_rejects_dynamic_meta() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let add = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let tree = func.alloc_vreg();
    func.param_non_null.insert(tree.0 as usize);
    let lock = func.alloc_vreg();
    func.param_non_null.insert(lock.0 as usize);
    let new_meta = func.alloc_vreg();
    let add_meta = func.alloc_vreg();
    let off = func.alloc_vreg();
    let less = func.alloc_vreg();
    let type_id = func.alloc_vreg();
    let obj = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let add_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: new_meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: less,
            subfn: SubfunctionId(0),
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: type_id,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: obj,
        kfunc: "bpf_obj_new_impl".to_string(),
        btf_id: None,
        args: vec![type_id, new_meta],
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

    push_bpf_spin_lock_call(&mut func, add, lock_ret, lock);
    func.block_mut(add).instructions.push(MirInst::CallKfunc {
        dst: add_ret,
        kfunc: "bpf_rbtree_add_impl".to_string(),
        btf_id: None,
        args: vec![tree, obj, less, add_meta, off],
    });
    push_bpf_spin_unlock_call(&mut func, add, unlock_ret, lock);
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
    types.insert(new_meta, MirType::I64);
    types.insert(add_meta, MirType::I64);
    types.insert(off, MirType::I64);
    types.insert(
        less,
        MirType::Subprogram {
            args: vec![
                MirType::Ptr {
                    pointee: Box::new(MirType::bpf_rb_node_struct()),
                    address_space: AddressSpace::Kernel,
                },
                MirType::Ptr {
                    pointee: Box::new(MirType::bpf_rb_node_struct()),
                    address_space: AddressSpace::Kernel,
                },
            ],
            ret: Box::new(MirType::I64),
        },
    );
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
    insert_bpf_spin_lock_types(&mut types, lock, lock_ret, unlock_ret);

    let err = verify_mir(&func, &types).expect_err("expected rbtree_add dynamic meta error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_rbtree_add_impl' arg3 must be known zero")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_rbtree_add_rejects_task_reference_on_arg1() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let add = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
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
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: less,
            subfn: SubfunctionId(0),
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
    types.insert(
        less,
        MirType::Subprogram {
            args: vec![
                MirType::Ptr {
                    pointee: Box::new(MirType::bpf_rb_node_struct()),
                    address_space: AddressSpace::Kernel,
                },
                MirType::Ptr {
                    pointee: Box::new(MirType::bpf_rb_node_struct()),
                    address_space: AddressSpace::Kernel,
                },
            ],
            ret: Box::new(MirType::I64),
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
    types.insert(cond, MirType::Bool);
    types.insert(add_ret, MirType::I64);
    types.insert(task_release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected object-ref arg1 mismatch");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects acquired object reference")),
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
fn test_kfunc_rbtree_remove_acquires_object_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 3;

    let tree = func.alloc_vreg();
    func.param_non_null.insert(tree.0 as usize);
    let node = func.alloc_vreg();
    func.param_non_null.insert(node.0 as usize);
    let lock = func.alloc_vreg();
    func.param_non_null.insert(lock.0 as usize);
    let meta = func.alloc_vreg();
    let removed = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();
    let release_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    push_bpf_spin_lock_call(&mut func, entry, lock_ret, lock);
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: removed,
        kfunc: "bpf_rbtree_remove".to_string(),
        btf_id: None,
        args: vec![tree, node],
    });
    push_bpf_spin_unlock_call(&mut func, entry, unlock_ret, lock);
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
    insert_bpf_spin_lock_types(&mut types, lock, lock_ret, unlock_ret);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected rbtree_remove object release to verify");
}

#[test]
fn test_kfunc_object_new_rejects_nonzero_meta() {
    for kfunc in ["bpf_obj_new_impl", "bpf_percpu_obj_new_impl"] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let type_id = func.alloc_vreg();
        let meta = func.alloc_vreg();
        let obj = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: type_id,
            src: MirValue::Const(1),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: meta,
            src: MirValue::Const(1),
        });
        func.block_mut(entry).instructions.push(MirInst::CallKfunc {
            dst: obj,
            kfunc: kfunc.to_string(),
            btf_id: None,
            args: vec![type_id, meta],
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(type_id, MirType::I64);
        types.insert(meta, MirType::I64);
        types.insert(
            obj,
            MirType::Ptr {
                pointee: Box::new(MirType::Unknown),
                address_space: AddressSpace::Kernel,
            },
        );

        let err =
            verify_mir(&func, &types).expect_err(&format!("expected {kfunc} nonzero meta error"));
        assert!(
            err.iter().any(|e| e
                .message
                .contains(&format!("kfunc '{kfunc}' arg1 must be known zero"))),
            "unexpected errors for {kfunc}: {:?}",
            err
        );
    }
}

#[test]
fn test_kfunc_object_new_rejects_dynamic_meta() {
    for kfunc in ["bpf_obj_new_impl", "bpf_percpu_obj_new_impl"] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let type_id = func.alloc_vreg();
        let meta = func.alloc_vreg();
        let obj = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: type_id,
            src: MirValue::Const(1),
        });
        func.block_mut(entry).instructions.push(MirInst::CallKfunc {
            dst: obj,
            kfunc: kfunc.to_string(),
            btf_id: None,
            args: vec![type_id, meta],
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(type_id, MirType::I64);
        types.insert(meta, MirType::I64);
        types.insert(
            obj,
            MirType::Ptr {
                pointee: Box::new(MirType::Unknown),
                address_space: AddressSpace::Kernel,
            },
        );

        let err =
            verify_mir(&func, &types).expect_err(&format!("expected {kfunc} dynamic meta error"));
        assert!(
            err.iter().any(|e| e
                .message
                .contains(&format!("kfunc '{kfunc}' arg1 must be known zero"))),
            "unexpected errors for {kfunc}: {:?}",
            err
        );
    }
}

#[test]
fn test_kfunc_obj_new_release_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
fn test_kfunc_object_drop_rejects_nonzero_meta() {
    for (new_kfunc, drop_kfunc) in [
        ("bpf_obj_new_impl", "bpf_obj_drop_impl"),
        ("bpf_percpu_obj_new_impl", "bpf_percpu_obj_drop_impl"),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let release = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let new_meta = func.alloc_vreg();
        let drop_meta = func.alloc_vreg();
        let type_id = func.alloc_vreg();
        let obj = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let release_ret = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: new_meta,
            src: MirValue::Const(0),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: drop_meta,
            src: MirValue::Const(1),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: type_id,
            src: MirValue::Const(1),
        });
        func.block_mut(entry).instructions.push(MirInst::CallKfunc {
            dst: obj,
            kfunc: new_kfunc.to_string(),
            btf_id: None,
            args: vec![type_id, new_meta],
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
                kfunc: drop_kfunc.to_string(),
                btf_id: None,
                args: vec![obj, drop_meta],
            });
        func.block_mut(release).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(new_meta, MirType::I64);
        types.insert(drop_meta, MirType::I64);
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

        let err = verify_mir(&func, &types)
            .expect_err(&format!("expected {drop_kfunc} nonzero meta error"));
        assert!(
            err.iter().any(|e| e
                .message
                .contains(&format!("kfunc '{drop_kfunc}' arg1 must be known zero"))),
            "unexpected errors for {drop_kfunc}: {:?}",
            err
        );
    }
}

#[test]
fn test_kfunc_object_drop_rejects_dynamic_meta() {
    for (new_kfunc, drop_kfunc) in [
        ("bpf_obj_new_impl", "bpf_obj_drop_impl"),
        ("bpf_percpu_obj_new_impl", "bpf_percpu_obj_drop_impl"),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let release = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let new_meta = func.alloc_vreg();
        let drop_meta = func.alloc_vreg();
        let type_id = func.alloc_vreg();
        let obj = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let release_ret = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: new_meta,
            src: MirValue::Const(0),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: type_id,
            src: MirValue::Const(1),
        });
        func.block_mut(entry).instructions.push(MirInst::CallKfunc {
            dst: obj,
            kfunc: new_kfunc.to_string(),
            btf_id: None,
            args: vec![type_id, new_meta],
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
                kfunc: drop_kfunc.to_string(),
                btf_id: None,
                args: vec![obj, drop_meta],
            });
        func.block_mut(release).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(new_meta, MirType::I64);
        types.insert(drop_meta, MirType::I64);
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

        let err = verify_mir(&func, &types)
            .expect_err(&format!("expected {drop_kfunc} dynamic meta error"));
        assert!(
            err.iter().any(|e| e
                .message
                .contains(&format!("kfunc '{drop_kfunc}' arg1 must be known zero"))),
            "unexpected errors for {drop_kfunc}: {:?}",
            err
        );
    }
}

#[test]
fn test_kfunc_obj_drop_rejects_task_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
            .any(|e| e.message.contains("expects acquired object reference")),
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
fn test_kfunc_percpu_obj_new_release_semantics() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
fn test_kfunc_percpu_obj_drop_rejects_task_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

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
            .any(|e| e.message.contains("expects acquired object reference")),
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
fn test_kfunc_refcount_acquire_rejects_task_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
fn test_kfunc_refcount_acquire_rejects_object_without_refcount_payload() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let type_id = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let object = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: type_id,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: object,
        kfunc: "bpf_obj_new_impl".to_string(),
        btf_id: None,
        args: vec![type_id, meta],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: acquired,
        kfunc: "bpf_refcount_acquire_impl".to_string(),
        btf_id: None,
        args: vec![object, meta],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let object_ty = MirType::Struct {
        name: Some("plain_object".to_string()),
        kernel_btf_type_id: None,
        fields: vec![StructField {
            name: "cookie".to_string(),
            ty: MirType::U64,
            offset: 0,
            synthetic: false,
            bitfield: None,
        }],
    };
    let object_ptr_ty = MirType::Ptr {
        pointee: Box::new(object_ty),
        address_space: AddressSpace::Kernel,
    };
    let mut types = HashMap::new();
    types.insert(type_id, MirType::I64);
    types.insert(meta, MirType::I64);
    types.insert(object, object_ptr_ty.clone());
    types.insert(acquired, object_ptr_ty);

    let err = verify_mir(&func, &types).expect_err("expected refcount payload error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("arg0 expects object pointer containing bpf_refcount")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_task_release_requires_tracked_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
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
            e.message.contains("expects acquired task reference")
                || e.message.contains("expects acquired reference")
                || e.message.contains("reference already released")
        }),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_task_release_rejects_double_release() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let release_ret = func.alloc_vreg();
    let double_release_ret = func.alloc_vreg();

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
    func.block_mut(release)
        .instructions
        .push(MirInst::CallKfunc {
            dst: double_release_ret,
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
    types.insert(cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);
    types.insert(double_release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected task double-release rejection");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_task_release' arg0 reference already released")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_task_release_rejects_cgroup_reference() {
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
            .any(|e| e.message.contains("expects acquired task reference")),
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
fn test_kfunc_task_release_rejects_mixed_reference_kinds_after_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let task_path = func.alloc_block();
    let cgroup_path = func.alloc_block();
    let join = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
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
            .any(|e| e.message.contains("expects acquired task reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_task_release_accepts_explicit_null_after_acquire_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let acquire_path = func.alloc_block();
    let null_path = func.alloc_block();
    let join = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let select_cond = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
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
        if_true: acquire_path,
        if_false: null_path,
    };

    func.block_mut(acquire_path)
        .instructions
        .push(MirInst::Copy {
            dst: pid,
            src: MirValue::Const(123),
        });
    func.block_mut(acquire_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: task,
            kfunc: "bpf_task_from_pid".to_string(),
            btf_id: None,
            args: vec![pid],
        });
    func.block_mut(acquire_path).terminator = MirInst::Jump { target: join };

    func.block_mut(null_path).instructions.push(MirInst::Copy {
        dst: task,
        src: MirValue::Const(0),
    });
    func.block_mut(null_path).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: release_cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
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
            args: vec![task],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(select_cond, MirType::Bool);
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types)
        .expect("explicit null/ref join should preserve kfunc ref identity until null guard");
}

#[test]
fn test_kfunc_task_release_accepts_explicit_null_phi_after_acquire_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let acquire_path = func.alloc_block();
    let null_path = func.alloc_block();
    let join = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let select_cond = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let acquired = func.alloc_vreg();
    let null_task = func.alloc_vreg();
    let task = func.alloc_vreg();
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
        if_true: acquire_path,
        if_false: null_path,
    };

    func.block_mut(acquire_path)
        .instructions
        .push(MirInst::Copy {
            dst: pid,
            src: MirValue::Const(123),
        });
    func.block_mut(acquire_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: acquired,
            kfunc: "bpf_task_from_pid".to_string(),
            btf_id: None,
            args: vec![pid],
        });
    func.block_mut(acquire_path).terminator = MirInst::Jump { target: join };

    func.block_mut(null_path).instructions.push(MirInst::Copy {
        dst: null_task,
        src: MirValue::Const(0),
    });
    func.block_mut(null_path).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::Phi {
        dst: task,
        args: vec![(acquire_path, acquired), (null_path, null_task)],
    });
    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: release_cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
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
            args: vec![task],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(select_cond, MirType::Bool);
    types.insert(pid, MirType::I64);
    types.insert(null_task, MirType::I64);
    for reg in [acquired, task] {
        types.insert(
            reg,
            MirType::Ptr {
                pointee: Box::new(MirType::Unknown),
                address_space: AddressSpace::Kernel,
            },
        );
    }
    types.insert(release_cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    verify_mir(&func, &types)
        .expect("explicit null/ref phi should preserve kfunc ref identity until null guard");
}

#[test]
fn test_kfunc_task_release_rejected_after_partial_acquire_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let acquire_path = func.alloc_block();
    let join = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let select_cond = func.alloc_vreg();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
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
        if_true: acquire_path,
        if_false: join,
    };

    func.block_mut(acquire_path)
        .instructions
        .push(MirInst::Copy {
            dst: pid,
            src: MirValue::Const(123),
        });
    func.block_mut(acquire_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: task,
            kfunc: "bpf_task_from_pid".to_string(),
            btf_id: None,
            args: vec![pid],
        });
    func.block_mut(acquire_path).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: release_cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(task),
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
            args: vec![task],
        });
    func.block_mut(release).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(select_cond, MirType::Bool);
    types.insert(pid, MirType::I64);
    types.insert(
        task,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(release_cond, MirType::Bool);
    types.insert(release_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected partial-join release rejection");
    assert!(
        err.iter().any(|e| {
            e.message.contains("expects acquired task reference")
                || e.message.contains("pointer is not tracked")
                || e.message.contains("uninitialized")
        }),
        "unexpected errors: {:?}",
        err
    );
}

