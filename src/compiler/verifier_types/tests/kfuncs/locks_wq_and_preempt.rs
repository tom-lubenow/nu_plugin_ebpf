#[test]
fn test_kfunc_rcu_read_lock_unlock_balanced() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
fn test_kfunc_rcu_subfn_lock_unlock_balanced() {
    let mut acquire = MirFunction::new();
    let acquire_entry = acquire.alloc_block();
    acquire.entry = acquire_entry;
    let acquire_ret = acquire.alloc_vreg();
    acquire
        .block_mut(acquire_entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst: acquire_ret,
            kfunc: "bpf_rcu_read_lock".to_string(),
            btf_id: None,
            args: vec![],
        });
    acquire.block_mut(acquire_entry).terminator = MirInst::Return { val: None };

    let mut release = MirFunction::new();
    let release_entry = release.alloc_block();
    release.entry = release_entry;
    let release_ret = release.alloc_vreg();
    release
        .block_mut(release_entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst: release_ret,
            kfunc: "bpf_rcu_read_unlock".to_string(),
            btf_id: None,
            args: vec![],
        });
    release.block_mut(release_entry).terminator = MirInst::Return { val: None };

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let call_acquire_ret = func.alloc_vreg();
    let call_release_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst: call_acquire_ret,
        subfn: SubfunctionId(0),
        args: vec![],
    });
    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst: call_release_ret,
        subfn: SubfunctionId(1),
        args: vec![],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let summaries = infer_subfunction_summaries(&[acquire.clone(), release.clone()]);
    let acquire_summary = summaries
        .get(&SubfunctionId(0))
        .cloned()
        .expect("expected acquire summary");
    let release_summary = summaries
        .get(&SubfunctionId(1))
        .cloned()
        .expect("expected release summary");
    let mut acquire_types = HashMap::new();
    acquire_types.insert(acquire_ret, MirType::I64);
    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &acquire,
        &acquire_types,
        &summaries,
        Some(acquire_summary),
        None,
        None,
    )
    .expect("expected RCU acquire wrapper to verify");
    let mut release_types = HashMap::new();
    release_types.insert(release_ret, MirType::I64);
    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &release,
        &release_types,
        &summaries,
        Some(release_summary),
        None,
        None,
    )
    .expect("expected RCU release wrapper to verify");

    let mut types = HashMap::new();
    types.insert(call_acquire_ret, MirType::I64);
    types.insert(call_release_ret, MirType::I64);
    verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect("expected RCU subfunction lock/unlock wrappers to balance");
}

#[test]
fn test_kfunc_rcu_read_unlock_requires_matching_lock() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_rcu_read_lock_must_be_released_at_exit() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_rcu_read_unlock_rejected_after_mixed_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let lock_path = func.alloc_block();
    let no_lock_path = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_map_sum_elem_count_requires_kernel_pointer_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_map_sum_elem_count_accepts_kernel_pointer_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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

fn wq_init_test_map(name: &str) -> MapRef {
    MapRef {
        name: name.to_string(),
        kind: MapKind::Array,
    }
}

fn wq_init_test_value_ty() -> MirType {
    MirType::Struct {
        name: Some("wq_value".to_string()),
        kernel_btf_type_id: None,
        fields: vec![StructField {
            name: "work".to_string(),
            ty: MirType::bpf_wq_struct(),
            offset: 0,
            synthetic: false,
            bitfield: None,
        }],
    }
}

fn wq_init_test_map_ptr_ty(value_ty: MirType) -> MirType {
    MirType::Ptr {
        pointee: Box::new(value_ty),
        address_space: AddressSpace::Map,
    }
}

fn wq_init_test_map_ref_ty(value_ty: MirType) -> MirType {
    MirType::MapRef {
        key_ty: Box::new(MirType::U32),
        val_ty: Box::new(value_ty),
    }
}

fn wq_init_subfunction() -> MirFunction {
    let mut subfn = MirFunction::new();
    let entry = subfn.alloc_block();
    subfn.entry = entry;
    subfn.param_count = 3;
    subfn.vreg_count = 3;
    let dst = subfn.alloc_vreg();
    subfn
        .block_mut(entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst,
            kfunc: "bpf_wq_init".to_string(),
            btf_id: None,
            args: vec![VReg(0), VReg(1), VReg(2)],
        });
    subfn.block_mut(entry).terminator = MirInst::Return { val: None };
    subfn
}

fn wq_init_fixed_map_subfunction() -> MirFunction {
    let mut subfn = MirFunction::new();
    let entry = subfn.alloc_block();
    subfn.entry = entry;
    subfn.param_count = 1;
    subfn.vreg_count = 1;
    let map_fd = subfn.alloc_vreg();
    let flags = subfn.alloc_vreg();
    let dst = subfn.alloc_vreg();
    subfn
        .block_mut(entry)
        .instructions
        .push(MirInst::LoadMapFd {
            dst: map_fd,
            map: wq_init_test_map("work_items"),
        });
    subfn.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    subfn
        .block_mut(entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst,
            kfunc: "bpf_wq_init".to_string(),
            btf_id: None,
            args: vec![VReg(0), map_fd, flags],
        });
    subfn.block_mut(entry).terminator = MirInst::Return { val: None };
    subfn
}

#[test]
fn test_kfunc_bpf_wq_init_accepts_map_backed_wq_and_map_fd() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let wq = func.alloc_vreg();
    func.param_non_null.insert(wq.0 as usize);
    let map_fd = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let map_ref = MapRef {
        name: "work_items".to_string(),
        kind: MapKind::Array,
    };
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map_fd,
        map: map_ref,
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_wq_init".to_string(),
        btf_id: None,
        args: vec![wq, map_fd, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let value_ty = MirType::Struct {
        name: Some("wq_value".to_string()),
        kernel_btf_type_id: None,
        fields: vec![StructField {
            name: "work".to_string(),
            ty: MirType::bpf_wq_struct(),
            offset: 0,
            synthetic: false,
            bitfield: None,
        }],
    };
    let mut types = HashMap::new();
    types.insert(
        wq,
        MirType::Ptr {
            pointee: Box::new(value_ty.clone()),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(
        map_fd,
        MirType::MapRef {
            key_ty: Box::new(MirType::U32),
            val_ty: Box::new(value_ty),
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected bpf_wq_init map-backed call to verify");
}

#[test]
fn test_kfunc_bpf_wq_init_rejects_nonzero_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let wq = func.alloc_vreg();
    func.param_non_null.insert(wq.0 as usize);
    let map_fd = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map_fd,
        map: MapRef {
            name: "work_items".to_string(),
            kind: MapKind::Array,
        },
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_wq_init".to_string(),
        btf_id: None,
        args: vec![wq, map_fd, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let value_ty = wq_init_test_value_ty();
    let mut types = HashMap::new();
    types.insert(wq, wq_init_test_map_ptr_ty(value_ty.clone()));
    types.insert(map_fd, wq_init_test_map_ref_ty(value_ty));
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bpf_wq_init nonzero flags error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_wq_init' arg2 must be known zero")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_bpf_wq_init_rejects_dynamic_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let wq = func.alloc_vreg();
    func.param_non_null.insert(wq.0 as usize);
    let map_fd = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map_fd,
        map: MapRef {
            name: "work_items".to_string(),
            kind: MapKind::Array,
        },
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_wq_init".to_string(),
        btf_id: None,
        args: vec![wq, map_fd, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let value_ty = wq_init_test_value_ty();
    let mut types = HashMap::new();
    types.insert(wq, wq_init_test_map_ptr_ty(value_ty.clone()));
    types.insert(map_fd, wq_init_test_map_ref_ty(value_ty));
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bpf_wq_init dynamic flags error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_wq_init' arg2 must be known zero")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_bpf_wq_init_rejects_mismatched_map_fd() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let wq_loaded = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let wq = func.alloc_vreg();
    let wq_non_null = func.alloc_vreg();
    let map_fd = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: wq,
        map: MapRef {
            name: "work_items".to_string(),
            kind: MapKind::Array,
        },
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: wq_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(wq),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: wq_non_null,
        if_true: wq_loaded,
        if_false: done,
    };
    func.block_mut(wq_loaded)
        .instructions
        .push(MirInst::LoadMapFd {
            dst: map_fd,
            map: MapRef {
                name: "other_work_items".to_string(),
                kind: MapKind::Array,
            },
        });
    func.block_mut(wq_loaded).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(wq_loaded)
        .instructions
        .push(MirInst::CallKfunc {
            dst,
            kfunc: "bpf_wq_init".to_string(),
            btf_id: None,
            args: vec![wq, map_fd, flags],
        });
    func.block_mut(wq_loaded).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let value_ty = MirType::Struct {
        name: Some("wq_value".to_string()),
        kernel_btf_type_id: None,
        fields: vec![StructField {
            name: "work".to_string(),
            ty: MirType::bpf_wq_struct(),
            offset: 0,
            synthetic: false,
            bitfield: None,
        }],
    };
    let mut types = HashMap::new();
    types.insert(key, MirType::I64);
    types.insert(
        wq,
        MirType::Ptr {
            pointee: Box::new(value_ty.clone()),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(wq_non_null, MirType::Bool);
    types.insert(
        map_fd,
        MirType::MapRef {
            key_ty: Box::new(MirType::U32),
            val_ty: Box::new(value_ty),
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mismatched bpf_wq_init map fd error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "kfunc 'bpf_wq_init' arg1 map 'other_work_items' does not match arg0 map value 'work_items'"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_bpf_wq_init_subfn_accepts_matching_map_fd() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let wq_loaded = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let wq = func.alloc_vreg();
    let wq_non_null = func.alloc_vreg();
    let map_fd = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let subfn_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: wq,
        map: wq_init_test_map("work_items"),
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: wq_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(wq),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: wq_non_null,
        if_true: wq_loaded,
        if_false: done,
    };
    func.block_mut(wq_loaded)
        .instructions
        .push(MirInst::LoadMapFd {
            dst: map_fd,
            map: wq_init_test_map("work_items"),
        });
    func.block_mut(wq_loaded).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(wq_loaded)
        .instructions
        .push(MirInst::CallSubfn {
            dst: subfn_ret,
            subfn: SubfunctionId(0),
            args: vec![wq, map_fd, flags],
        });
    func.block_mut(wq_loaded).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let value_ty = wq_init_test_value_ty();
    let mut types = HashMap::new();
    types.insert(key, MirType::I64);
    types.insert(wq, wq_init_test_map_ptr_ty(value_ty.clone()));
    types.insert(wq_non_null, MirType::Bool);
    types.insert(map_fd, wq_init_test_map_ref_ty(value_ty));
    types.insert(flags, MirType::I64);
    types.insert(subfn_ret, MirType::I64);

    let summaries = infer_subfunction_summaries(&[wq_init_subfunction()]);
    assert_eq!(
        summaries[&SubfunctionId(0)]
            .map_value_map_fd_requirements()
            .len(),
        1
    );
    verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect("expected bpf_wq_init subfunction with matching map fd to verify");
}

#[test]
fn test_kfunc_bpf_wq_init_subfn_rejects_mismatched_map_fd() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let wq_loaded = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let wq = func.alloc_vreg();
    let wq_non_null = func.alloc_vreg();
    let map_fd = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let subfn_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: wq,
        map: wq_init_test_map("work_items"),
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: wq_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(wq),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: wq_non_null,
        if_true: wq_loaded,
        if_false: done,
    };
    func.block_mut(wq_loaded)
        .instructions
        .push(MirInst::LoadMapFd {
            dst: map_fd,
            map: wq_init_test_map("other_work_items"),
        });
    func.block_mut(wq_loaded).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(wq_loaded)
        .instructions
        .push(MirInst::CallSubfn {
            dst: subfn_ret,
            subfn: SubfunctionId(0),
            args: vec![wq, map_fd, flags],
        });
    func.block_mut(wq_loaded).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let value_ty = wq_init_test_value_ty();
    let mut types = HashMap::new();
    types.insert(key, MirType::I64);
    types.insert(wq, wq_init_test_map_ptr_ty(value_ty.clone()));
    types.insert(wq_non_null, MirType::Bool);
    types.insert(map_fd, wq_init_test_map_ref_ty(value_ty));
    types.insert(flags, MirType::I64);
    types.insert(subfn_ret, MirType::I64);

    let summaries = infer_subfunction_summaries(&[wq_init_subfunction()]);
    let err = verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect_err("expected bpf_wq_init subfunction map fd mismatch");
    assert!(
        err.iter().any(|e| e.message.contains(
            "kfunc 'bpf_wq_init' arg1 map 'other_work_items' does not match arg0 map value 'work_items'"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_bpf_wq_init_fixed_map_subfn_accepts_matching_map_value() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let wq_loaded = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let wq = func.alloc_vreg();
    let wq_non_null = func.alloc_vreg();
    let subfn_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: wq,
        map: wq_init_test_map("work_items"),
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: wq_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(wq),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: wq_non_null,
        if_true: wq_loaded,
        if_false: done,
    };
    func.block_mut(wq_loaded)
        .instructions
        .push(MirInst::CallSubfn {
            dst: subfn_ret,
            subfn: SubfunctionId(0),
            args: vec![wq],
        });
    func.block_mut(wq_loaded).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let value_ty = wq_init_test_value_ty();
    let mut types = HashMap::new();
    types.insert(key, MirType::I64);
    types.insert(wq, wq_init_test_map_ptr_ty(value_ty));
    types.insert(wq_non_null, MirType::Bool);
    types.insert(subfn_ret, MirType::I64);

    let summaries = infer_subfunction_summaries(&[wq_init_fixed_map_subfunction()]);
    assert_eq!(
        summaries[&SubfunctionId(0)]
            .map_value_map_fd_requirements()
            .len(),
        1
    );
    verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect("expected fixed-map bpf_wq_init subfunction with matching map value to verify");
}

#[test]
fn test_kfunc_bpf_wq_init_fixed_map_subfn_rejects_mismatched_map_value() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let wq_loaded = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let wq = func.alloc_vreg();
    let wq_non_null = func.alloc_vreg();
    let subfn_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: wq,
        map: wq_init_test_map("other_work_items"),
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: wq_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(wq),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: wq_non_null,
        if_true: wq_loaded,
        if_false: done,
    };
    func.block_mut(wq_loaded)
        .instructions
        .push(MirInst::CallSubfn {
            dst: subfn_ret,
            subfn: SubfunctionId(0),
            args: vec![wq],
        });
    func.block_mut(wq_loaded).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let value_ty = wq_init_test_value_ty();
    let mut types = HashMap::new();
    types.insert(key, MirType::I64);
    types.insert(wq, wq_init_test_map_ptr_ty(value_ty));
    types.insert(wq_non_null, MirType::Bool);
    types.insert(subfn_ret, MirType::I64);

    let summaries = infer_subfunction_summaries(&[wq_init_fixed_map_subfunction()]);
    let err = verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect_err("expected fixed-map bpf_wq_init subfunction map value mismatch");
    assert!(
        err.iter().any(|e| e.message.contains(
            "kfunc 'bpf_wq_init' map 'work_items' does not match arg0 map value 'other_work_items'"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_bpf_wq_set_callback_accepts_callback_and_zero_aux() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let wq = func.alloc_vreg();
    func.param_non_null.insert(wq.0 as usize);
    let callback = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let aux = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback,
            subfn: crate::compiler::mir::SubfunctionId(0),
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: aux,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_wq_set_callback_impl".to_string(),
        btf_id: None,
        args: vec![wq, callback, flags, aux],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        wq,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_wq_struct()),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(callback, bpf_wq_callback_type());
    types.insert(flags, MirType::I64);
    types.insert(aux, MirType::I64);
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected bpf_wq_set_callback_impl call to verify");
}

#[test]
fn test_kfunc_bpf_wq_set_callback_rejects_nonzero_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let wq = func.alloc_vreg();
    func.param_non_null.insert(wq.0 as usize);
    let callback = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let aux = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback,
            subfn: crate::compiler::mir::SubfunctionId(0),
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: aux,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_wq_set_callback_impl".to_string(),
        btf_id: None,
        args: vec![wq, callback, flags, aux],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        wq,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_wq_struct()),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(callback, bpf_wq_callback_type());
    types.insert(flags, MirType::I64);
    types.insert(aux, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected bpf_wq_set_callback nonzero flags error");
    assert!(
        err.iter().any(|e| {
            e.message
                .contains("kfunc 'bpf_wq_set_callback_impl' arg2 must be known zero")
        }),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_bpf_wq_set_callback_rejects_dynamic_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let wq = func.alloc_vreg();
    func.param_non_null.insert(wq.0 as usize);
    let callback = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let aux = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback,
            subfn: crate::compiler::mir::SubfunctionId(0),
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: aux,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_wq_set_callback_impl".to_string(),
        btf_id: None,
        args: vec![wq, callback, flags, aux],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        wq,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_wq_struct()),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(callback, bpf_wq_callback_type());
    types.insert(flags, MirType::I64);
    types.insert(aux, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected bpf_wq_set_callback dynamic flags error");
    assert!(
        err.iter().any(|e| {
            e.message
                .contains("kfunc 'bpf_wq_set_callback_impl' arg2 must be known zero")
        }),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_bpf_wq_set_callback_rejects_nonzero_aux() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let wq = func.alloc_vreg();
    func.param_non_null.insert(wq.0 as usize);
    let callback = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let aux = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback,
            subfn: crate::compiler::mir::SubfunctionId(0),
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: aux,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_wq_set_callback_impl".to_string(),
        btf_id: None,
        args: vec![wq, callback, flags, aux],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        wq,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_wq_struct()),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(callback, bpf_wq_callback_type());
    types.insert(flags, MirType::I64);
    types.insert(aux, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected bpf_wq_set_callback nonzero aux error");
    assert!(
        err.iter().any(|e| {
            e.message
                .contains("kfunc 'bpf_wq_set_callback_impl' arg3 must be known zero")
        }),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_bpf_wq_set_callback_rejects_dynamic_aux() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let wq = func.alloc_vreg();
    func.param_non_null.insert(wq.0 as usize);
    let callback = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let aux = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback,
            subfn: crate::compiler::mir::SubfunctionId(0),
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_wq_set_callback_impl".to_string(),
        btf_id: None,
        args: vec![wq, callback, flags, aux],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        wq,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_wq_struct()),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(callback, bpf_wq_callback_type());
    types.insert(flags, MirType::I64);
    types.insert(aux, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected bpf_wq_set_callback dynamic aux error");
    assert!(
        err.iter().any(|e| {
            e.message
                .contains("kfunc 'bpf_wq_set_callback_impl' arg3 must be known zero")
        }),
        "unexpected errors: {:?}",
        err
    );
}

fn bpf_wq_callback_type() -> MirType {
    MirType::Subprogram {
        args: vec![
            MirType::named_kernel_struct_ptr("bpf_map"),
            MirType::Ptr {
                pointee: Box::new(MirType::U32),
                address_space: AddressSpace::Map,
            },
            MirType::Ptr {
                pointee: Box::new(MirType::bpf_wq_struct()),
                address_space: AddressSpace::Map,
            },
        ],
        ret: Box::new(MirType::I64),
    }
}

#[test]
fn test_kfunc_bpf_wq_set_callback_rejects_stack_wq() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let wq = func.alloc_vreg();
    let callback = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let aux = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback,
            subfn: crate::compiler::mir::SubfunctionId(0),
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: aux,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_wq_set_callback_impl".to_string(),
        btf_id: None,
        args: vec![wq, callback, flags, aux],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        wq,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_wq_struct()),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(callback, bpf_wq_callback_type());
    types.insert(flags, MirType::I64);
    types.insert(aux, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected stack bpf_wq kfunc arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("bpf_wq field expects pointer in [Map]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_bpf_wq_set_callback_requires_null_checked_map_lookup() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let wq = func.alloc_vreg();
    let callback = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let aux = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: wq,
        map: MapRef {
            name: "work_items".to_string(),
            kind: MapKind::Array,
        },
        key,
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback,
            subfn: crate::compiler::mir::SubfunctionId(0),
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: aux,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_wq_set_callback_impl".to_string(),
        btf_id: None,
        args: vec![wq, callback, flags, aux],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let value_ty = MirType::Struct {
        name: Some("wq_value".to_string()),
        kernel_btf_type_id: None,
        fields: vec![StructField {
            name: "work".to_string(),
            ty: MirType::bpf_wq_struct(),
            offset: 0,
            synthetic: false,
            bitfield: None,
        }],
    };
    let mut types = HashMap::new();
    types.insert(key, MirType::I64);
    types.insert(
        wq,
        MirType::Ptr {
            pointee: Box::new(value_ty),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(callback, bpf_wq_callback_type());
    types.insert(flags, MirType::I64);
    types.insert(aux, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected unchecked map-backed bpf_wq pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("may dereference null pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_bpf_wq_start_rejects_nonzero_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let wq = func.alloc_vreg();
    func.param_non_null.insert(wq.0 as usize);
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_wq_start".to_string(),
        btf_id: None,
        args: vec![wq, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        wq,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_wq_struct()),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bpf_wq_start nonzero flags error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_wq_start' arg1 must be known zero")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_bpf_wq_start_rejects_dynamic_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let wq = func.alloc_vreg();
    func.param_non_null.insert(wq.0 as usize);
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_wq_start".to_string(),
        btf_id: None,
        args: vec![wq, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        wq,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_wq_struct()),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bpf_wq_start dynamic flags error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_wq_start' arg1 must be known zero")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_bpf_wq_start_rejects_stack_wq() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let wq = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_wq_start".to_string(),
        btf_id: None,
        args: vec![wq, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        wq,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_wq_struct()),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected stack bpf_wq kfunc arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("bpf_wq field expects pointer in [Map]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_bpf_wq_start_requires_null_checked_map_lookup() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let wq = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: wq,
        map: MapRef {
            name: "work_items".to_string(),
            kind: MapKind::Array,
        },
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_wq_start".to_string(),
        btf_id: None,
        args: vec![wq, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let value_ty = MirType::Struct {
        name: Some("wq_value".to_string()),
        kernel_btf_type_id: None,
        fields: vec![StructField {
            name: "work".to_string(),
            ty: MirType::bpf_wq_struct(),
            offset: 0,
            synthetic: false,
            bitfield: None,
        }],
    };
    let mut types = HashMap::new();
    types.insert(key, MirType::I64);
    types.insert(
        wq,
        MirType::Ptr {
            pointee: Box::new(value_ty),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected unchecked map-backed bpf_wq pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("may dereference null pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_rbtree_root_requires_kernel_pointer_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_rbtree_left_rejects_list_node_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let node = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_rbtree_left".to_string(),
        btf_id: None,
        args: vec![node],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        node,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_list_node_struct()),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_rb_node_struct()),
            address_space: AddressSpace::Kernel,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected graph node kind mismatch");
    assert!(
        err.iter()
            .any(|e| e.message.contains("expects bpf_rb_node pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_list_front_accepts_offset_zero_enclosing_root_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let root = func.alloc_vreg();
    func.param_non_null.insert(root.0 as usize);
    let lock = func.alloc_vreg();
    func.param_non_null.insert(lock.0 as usize);
    let lock_ret = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();
    push_bpf_spin_lock_call(&mut func, entry, lock_ret, lock);
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_list_front".to_string(),
        btf_id: None,
        args: vec![root],
    });
    push_bpf_spin_unlock_call(&mut func, entry, unlock_ret, lock);
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let enclosing_root = MirType::Struct {
        name: Some("list_value".to_string()),
        kernel_btf_type_id: None,
        fields: vec![
            crate::compiler::mir::StructField {
                name: "root".to_string(),
                ty: MirType::bpf_list_head_struct(),
                offset: 0,
                synthetic: false,
                bitfield: None,
            },
            crate::compiler::mir::StructField {
                name: "count".to_string(),
                ty: MirType::I64,
                offset: 16,
                synthetic: false,
                bitfield: None,
            },
        ],
    };

    let mut types = HashMap::new();
    types.insert(
        root,
        MirType::Ptr {
            pointee: Box::new(enclosing_root),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_list_node_struct()),
            address_space: AddressSpace::Kernel,
        },
    );
    insert_bpf_spin_lock_types(&mut types, lock, lock_ret, unlock_ret);

    verify_mir(&func, &types).expect("expected offset-zero list root pointer to verify");
}

#[test]
fn test_kfunc_rbtree_root_accepts_kernel_pointer_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let root = func.alloc_vreg();
    func.param_non_null.insert(root.0 as usize);
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
fn test_kfunc_preempt_disable_enable_balanced() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
fn test_kfunc_preempt_enable_requires_matching_disable() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_preempt_disable_must_be_released_at_exit() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_preempt_enable_rejected_after_mixed_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let disable_path = func.alloc_block();
    let no_disable_path = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_local_irq_save_restore_balanced() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
fn test_kfunc_local_irq_subfn_save_restore_balanced() {
    let mut save = MirFunction::new();
    let save_entry = save.alloc_block();
    save.entry = save_entry;
    save.param_count = 1;
    save.vreg_count = 1;
    let save_slot = save.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    save.param_stack_slots.insert(0, save_slot);
    let save_ret = save.alloc_vreg();
    save.block_mut(save_entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst: save_ret,
            kfunc: "bpf_local_irq_save".to_string(),
            btf_id: None,
            args: vec![VReg(0)],
        });
    save.block_mut(save_entry).terminator = MirInst::Return { val: None };

    let mut restore = MirFunction::new();
    let restore_entry = restore.alloc_block();
    restore.entry = restore_entry;
    restore.param_count = 1;
    restore.vreg_count = 1;
    let restore_slot = restore.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    restore.param_stack_slots.insert(0, restore_slot);
    let restore_ret = restore.alloc_vreg();
    restore
        .block_mut(restore_entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst: restore_ret,
            kfunc: "bpf_local_irq_restore".to_string(),
            btf_id: None,
            args: vec![VReg(0)],
        });
    restore.block_mut(restore_entry).terminator = MirInst::Return { val: None };

    let summaries = infer_subfunction_summaries(&[save.clone(), restore.clone()]);
    let save_summary = summaries
        .get(&SubfunctionId(0))
        .cloned()
        .expect("expected save summary");
    let restore_summary = summaries
        .get(&SubfunctionId(1))
        .cloned()
        .expect("expected restore summary");
    let stack_ptr_ty = MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::Stack,
    };
    let mut save_types = HashMap::new();
    save_types.insert(VReg(0), stack_ptr_ty.clone());
    save_types.insert(save_ret, MirType::I64);
    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &save,
        &save_types,
        &summaries,
        Some(save_summary),
        None,
        None,
    )
    .expect("expected local IRQ save wrapper to verify");
    let mut restore_types = HashMap::new();
    restore_types.insert(VReg(0), stack_ptr_ty.clone());
    restore_types.insert(restore_ret, MirType::I64);
    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &restore,
        &restore_types,
        &summaries,
        Some(restore_summary),
        None,
        None,
    )
    .expect("expected local IRQ restore wrapper to verify");

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let flags = func.alloc_vreg();
    let call_save_ret = func.alloc_vreg();
    let call_restore_ret = func.alloc_vreg();
    let flags_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::StackSlot(flags_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst: call_save_ret,
        subfn: SubfunctionId(0),
        args: vec![flags],
    });
    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst: call_restore_ret,
        subfn: SubfunctionId(1),
        args: vec![flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(flags, stack_ptr_ty);
    types.insert(call_save_ret, MirType::I64);
    types.insert(call_restore_ret, MirType::I64);
    verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect("expected local IRQ save/restore wrappers to balance");
}

#[test]
fn test_kfunc_local_irq_restore_requires_matching_save() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_local_irq_restore_requires_matching_save_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_local_irq_save_must_be_released_at_exit() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_local_irq_restore_rejected_after_mixed_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let save_path = func.alloc_block();
    let no_save_path = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_res_spin_lock_unlock_balanced() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
    types.insert(lock, res_spin_lock_kernel_ptr_ty());
    types.insert(lock_ret, MirType::I64);
    types.insert(unlock_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected balanced res spin lock/unlock to verify");
}

#[test]
fn test_kfunc_res_spin_lock_rejects_same_lock_twice() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let lock = func.alloc_vreg();
    let first_ret = func.alloc_vreg();
    let second_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: first_ret,
        kfunc: "bpf_res_spin_lock".to_string(),
        btf_id: None,
        args: vec![lock],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: second_ret,
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
    types.insert(first_ret, MirType::I64);
    types.insert(second_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected duplicate res spin lock error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("cannot acquire an already-held resource spin lock")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_res_spin_lock_rejects_calls_while_held() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let lock = func.alloc_vreg();
    let throw_code = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let kfunc_ret = func.alloc_vreg();
    let subfn_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: throw_code,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: lock_ret,
        kfunc: "bpf_res_spin_lock".to_string(),
        btf_id: None,
        args: vec![lock],
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::KtimeGetNs as u32,
            args: vec![],
        });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: kfunc_ret,
        kfunc: "bpf_throw".to_string(),
        btf_id: None,
        args: vec![throw_code],
    });
    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst: subfn_ret,
        subfn: crate::compiler::mir::SubfunctionId(0),
        args: vec![],
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
    types.insert(throw_code, MirType::I64);
    for ret in [lock_ret, helper_ret, kfunc_ret, subfn_ret, unlock_ret] {
        types.insert(ret, MirType::I64);
    }

    let err = verify_mir(&func, &types).expect_err("expected call-in-res-spin-lock errors");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_ktime_get_ns' cannot be called while resource spin lock is held"
        )),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_throw' cannot be called while resource spin lock is held")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("subfunction 'subfn0' cannot be called while resource spin lock is held")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_res_spin_unlock_rejects_out_of_order_lock() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let first_lock = func.alloc_vreg();
    let second_lock = func.alloc_vreg();
    let first_lock_ret = func.alloc_vreg();
    let second_lock_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: first_lock_ret,
        kfunc: "bpf_res_spin_lock".to_string(),
        btf_id: None,
        args: vec![first_lock],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: second_lock_ret,
        kfunc: "bpf_res_spin_lock".to_string(),
        btf_id: None,
        args: vec![second_lock],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: unlock_ret,
        kfunc: "bpf_res_spin_unlock".to_string(),
        btf_id: None,
        args: vec![first_lock],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    for lock in [first_lock, second_lock] {
        types.insert(
            lock,
            MirType::Ptr {
                pointee: Box::new(MirType::Unknown),
                address_space: AddressSpace::Kernel,
            },
        );
    }
    types.insert(first_lock_ret, MirType::I64);
    types.insert(second_lock_ret, MirType::I64);
    types.insert(unlock_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected out-of-order res spin unlock error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_res_spin_lock")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_res_spin_unlock_requires_matching_lock() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_res_spin_lock_must_be_released_at_exit() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_res_spin_unlock_rejected_after_mixed_join() {
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_res_spin_lock_irqsave_rejects_helper_while_held() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let lock = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();
    let flags_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::StackSlot(flags_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: lock_ret,
        kfunc: "bpf_res_spin_lock_irqsave".to_string(),
        btf_id: None,
        args: vec![lock, flags],
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::KtimeGetNs as u32,
            args: vec![],
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
    for ret in [lock_ret, helper_ret, unlock_ret] {
        types.insert(ret, MirType::I64);
    }

    let err = verify_mir(&func, &types).expect_err("expected helper-in-res-spin-irqsave error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_ktime_get_ns' cannot be called while resource spin lock irqsave is held"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_res_spin_lock_irqsave_unlock_irqrestore_balanced() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
fn test_kfunc_res_spin_unlock_irqrestore_requires_matching_lock_irqsave() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

