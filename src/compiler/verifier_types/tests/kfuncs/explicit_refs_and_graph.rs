fn push_bpf_spin_lock_call(func: &mut MirFunction, block: BlockId, dst: VReg, lock: VReg) {
    func.block_mut(block)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SpinLock as u32,
            args: vec![MirValue::VReg(lock)],
        });
}

fn push_bpf_spin_unlock_call(func: &mut MirFunction, block: BlockId, dst: VReg, lock: VReg) {
    func.block_mut(block)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::SpinUnlock as u32,
            args: vec![MirValue::VReg(lock)],
        });
}

fn insert_bpf_spin_lock_types(
    types: &mut HashMap<VReg, MirType>,
    lock: VReg,
    lock_ret: VReg,
    unlock_ret: VReg,
) {
    types.insert(
        lock,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_spin_lock_struct()),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(lock_ret, MirType::I64);
    types.insert(unlock_ret, MirType::I64);
}

fn res_spin_lock_kernel_ptr_ty() -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::bpf_res_spin_lock_struct()),
        address_space: AddressSpace::Kernel,
    }
}

fn assert_explicit_null_ref_join_release_accepts(case: ExplicitNullRefKfuncCase, use_phi: bool) {
    let (func, types) = explicit_null_ref_join_release_mir(case, use_phi);
    verify_mir(&func, &types).unwrap_or_else(|err| {
        panic!(
            "expected explicit null/{} ref join to preserve release identity: {err:?}",
            case.label()
        )
    });
}

#[test]
fn test_kfunc_cgroup_release_accepts_explicit_null_after_acquire_join() {
    assert_explicit_null_ref_join_release_accepts(ExplicitNullRefKfuncCase::CgroupFromId, false);
}

#[test]
fn test_kfunc_cgroup_release_accepts_explicit_null_phi_after_acquire_join() {
    assert_explicit_null_ref_join_release_accepts(ExplicitNullRefKfuncCase::CgroupFromId, true);
}

#[test]
fn test_kfunc_file_release_accepts_explicit_null_after_acquire_join() {
    assert_explicit_null_ref_join_release_accepts(ExplicitNullRefKfuncCase::TaskExeFile, false);
}

#[test]
fn test_kfunc_file_release_accepts_explicit_null_phi_after_acquire_join() {
    assert_explicit_null_ref_join_release_accepts(ExplicitNullRefKfuncCase::TaskExeFile, true);
}

#[test]
fn test_kfunc_cpumask_release_accepts_explicit_null_after_acquire_join() {
    assert_explicit_null_ref_join_release_accepts(ExplicitNullRefKfuncCase::CpumaskCreate, false);
}

#[test]
fn test_kfunc_cpumask_release_accepts_explicit_null_phi_after_acquire_join() {
    assert_explicit_null_ref_join_release_accepts(ExplicitNullRefKfuncCase::CpumaskCreate, true);
}

#[test]
fn test_kfunc_crypto_ctx_release_accepts_explicit_null_after_acquire_join() {
    assert_explicit_null_ref_join_release_accepts(
        ExplicitNullRefKfuncCase::CryptoCtxAcquire,
        false,
    );
}

#[test]
fn test_kfunc_crypto_ctx_release_accepts_explicit_null_phi_after_acquire_join() {
    assert_explicit_null_ref_join_release_accepts(ExplicitNullRefKfuncCase::CryptoCtxAcquire, true);
}

#[test]
fn test_kfunc_obj_drop_accepts_explicit_null_after_new_join() {
    assert_explicit_null_ref_join_release_accepts(ExplicitNullRefKfuncCase::ObjNewImpl, false);
}

#[test]
fn test_kfunc_obj_drop_accepts_explicit_null_phi_after_new_join() {
    assert_explicit_null_ref_join_release_accepts(ExplicitNullRefKfuncCase::ObjNewImpl, true);
}

#[test]
fn test_kfunc_percpu_obj_drop_accepts_explicit_null_after_new_join() {
    assert_explicit_null_ref_join_release_accepts(
        ExplicitNullRefKfuncCase::PerCpuObjNewImpl,
        false,
    );
}

#[test]
fn test_kfunc_percpu_obj_drop_accepts_explicit_null_phi_after_new_join() {
    assert_explicit_null_ref_join_release_accepts(ExplicitNullRefKfuncCase::PerCpuObjNewImpl, true);
}

fn assert_xdp_xfrm_explicit_null_ref_join_release_accepts(use_phi: bool) {
    let (func, types) = xdp_get_xfrm_state_explicit_null_join_mir(use_phi);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    verify_mir_for_probe_context(&func, &types, &probe_ctx).unwrap_or_else(|err| {
        panic!("expected explicit null/xfrm_state ref join to preserve release identity: {err:?}")
    });
}

#[test]
fn test_xdp_get_xfrm_state_release_accepts_explicit_null_after_acquire_join() {
    assert_xdp_xfrm_explicit_null_ref_join_release_accepts(false);
}

#[test]
fn test_xdp_get_xfrm_state_release_accepts_explicit_null_phi_after_acquire_join() {
    assert_xdp_xfrm_explicit_null_ref_join_release_accepts(true);
}

fn graph_value_with_lock_and_root_ty() -> MirType {
    graph_value_with_lock_and_graph_root_ty(MirType::bpf_list_head_root_struct("node_data", "node"))
}

fn graph_value_with_lock_and_graph_root_ty(root_ty: MirType) -> MirType {
    MirType::Struct {
        name: Some("graph_value".to_string()),
        kernel_btf_type_id: None,
        fields: vec![
            StructField {
                name: "lock".to_string(),
                ty: MirType::bpf_spin_lock_struct(),
                offset: 0,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "root".to_string(),
                ty: root_ty,
                offset: 8,
                synthetic: false,
                bitfield: None,
            },
        ],
    }
}

fn graph_lock_root_function(same_map_value: bool) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let lock_ready = func.alloc_block();
    let use_root = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let lock_value = func.alloc_vreg();
    let lock_value_non_null = func.alloc_vreg();
    let root_value = if same_map_value {
        lock_value
    } else {
        func.alloc_vreg()
    };
    let root_value_non_null = func.alloc_vreg();
    let lock = func.alloc_vreg();
    let root = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let node = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: lock_value,
        map: MapRef {
            name: "graph_items".to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: lock_value_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(lock_value),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: lock_value_non_null,
        if_true: lock_ready,
        if_false: done,
    };

    if same_map_value {
        func.block_mut(lock_ready).terminator = MirInst::Jump { target: use_root };
    } else {
        func.block_mut(lock_ready)
            .instructions
            .push(MirInst::MapLookup {
                dst: root_value,
                map: MapRef {
                    name: "graph_roots".to_string(),
                    kind: MapKind::Hash,
                },
                key,
            });
        func.block_mut(lock_ready)
            .instructions
            .push(MirInst::BinOp {
                dst: root_value_non_null,
                op: BinOpKind::Ne,
                lhs: MirValue::VReg(root_value),
                rhs: MirValue::Const(0),
            });
        func.block_mut(lock_ready).terminator = MirInst::Branch {
            cond: root_value_non_null,
            if_true: use_root,
            if_false: done,
        };
    }

    func.block_mut(use_root).instructions.push(MirInst::Copy {
        dst: lock,
        src: MirValue::VReg(lock_value),
    });
    if same_map_value {
        func.block_mut(use_root).instructions.push(MirInst::BinOp {
            dst: root,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(root_value),
            rhs: MirValue::Const(8),
        });
    } else {
        func.block_mut(use_root).instructions.push(MirInst::Copy {
            dst: root,
            src: MirValue::VReg(root_value),
        });
    }
    push_bpf_spin_lock_call(&mut func, use_root, lock_ret, lock);
    func.block_mut(use_root)
        .instructions
        .push(MirInst::CallKfunc {
            dst: node,
            kfunc: "bpf_list_front".to_string(),
            btf_id: None,
            args: vec![root],
        });
    push_bpf_spin_unlock_call(&mut func, use_root, unlock_ret, lock);
    func.block_mut(use_root).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    for i in 0..func.vreg_count {
        types.insert(VReg(i), MirType::I64);
    }
    let lock_value_ty = if same_map_value {
        graph_value_with_lock_and_root_ty()
    } else {
        MirType::bpf_spin_lock_struct()
    };
    types.insert(
        lock_value,
        MirType::Ptr {
            pointee: Box::new(lock_value_ty),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(
        lock,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_spin_lock_struct()),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(
        root_value,
        MirType::Ptr {
            pointee: Box::new(if same_map_value {
                graph_value_with_lock_and_root_ty()
            } else {
                MirType::bpf_list_head_root_struct("node_data", "node")
            }),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(
        root,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_list_head_root_struct("node_data", "node")),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(
        node,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_list_node_struct()),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(lock_value_non_null, MirType::Bool);
    types.insert(root_value_non_null, MirType::Bool);
    types.insert(lock_ret, MirType::I64);
    types.insert(unlock_ret, MirType::I64);

    (func, types)
}

fn graph_lock_root_repeated_lookup_function(
    same_key: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    graph_lock_root_repeated_lookup_for_kfunc(
        if same_key {
            RepeatedLookupKeyMode::SameConst
        } else {
            RepeatedLookupKeyMode::DifferentConst
        },
        "bpf_list_front",
        MirType::bpf_list_head_root_struct("node_data", "node"),
        MirType::bpf_list_node_struct(),
    )
}

fn graph_rbtree_lock_root_repeated_lookup_function(
    same_key: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    graph_lock_root_repeated_lookup_for_kfunc(
        if same_key {
            RepeatedLookupKeyMode::SameConst
        } else {
            RepeatedLookupKeyMode::DifferentConst
        },
        "bpf_rbtree_first",
        MirType::bpf_rb_root_struct_with_contains("rb_item", "rb"),
        MirType::bpf_rb_node_struct(),
    )
}

fn graph_lock_root_repeated_lookup_copied_key_function() -> (MirFunction, HashMap<VReg, MirType>) {
    graph_lock_root_repeated_lookup_for_kfunc(
        RepeatedLookupKeyMode::CopiedDynamic,
        "bpf_list_front",
        MirType::bpf_list_head_root_struct("node_data", "node"),
        MirType::bpf_list_node_struct(),
    )
}

fn graph_lock_root_repeated_lookup_phi_key_function() -> (MirFunction, HashMap<VReg, MirType>) {
    graph_lock_root_repeated_lookup_for_kfunc(
        RepeatedLookupKeyMode::PhiCopiedDynamic,
        "bpf_list_front",
        MirType::bpf_list_head_root_struct("node_data", "node"),
        MirType::bpf_list_node_struct(),
    )
}

fn graph_lock_root_repeated_lookup_ctx_field_key_function() -> (MirFunction, HashMap<VReg, MirType>)
{
    graph_lock_root_repeated_lookup_for_kfunc(
        RepeatedLookupKeyMode::SameCtxFieldReload,
        "bpf_list_front",
        MirType::bpf_list_head_root_struct("node_data", "node"),
        MirType::bpf_list_node_struct(),
    )
}

fn graph_lock_root_repeated_lookup_noop_key_function() -> (MirFunction, HashMap<VReg, MirType>) {
    graph_lock_root_repeated_lookup_for_kfunc(
        RepeatedLookupKeyMode::NoopDynamic,
        "bpf_list_front",
        MirType::bpf_list_head_root_struct("node_data", "node"),
        MirType::bpf_list_node_struct(),
    )
}

fn graph_lock_root_repeated_lookup_offset_key_function() -> (MirFunction, HashMap<VReg, MirType>) {
    graph_lock_root_repeated_lookup_for_kfunc(
        RepeatedLookupKeyMode::OffsetDynamic,
        "bpf_list_front",
        MirType::bpf_list_head_root_struct("node_data", "node"),
        MirType::bpf_list_node_struct(),
    )
}

fn graph_lock_root_repeated_lookup_equivalent_expr_key_function()
-> (MirFunction, HashMap<VReg, MirType>) {
    graph_lock_root_repeated_lookup_for_kfunc(
        RepeatedLookupKeyMode::EquivalentExprDynamic,
        "bpf_list_front",
        MirType::bpf_list_head_root_struct("node_data", "node"),
        MirType::bpf_list_node_struct(),
    )
}

fn graph_lock_root_repeated_lookup_different_expr_key_function()
-> (MirFunction, HashMap<VReg, MirType>) {
    graph_lock_root_repeated_lookup_for_kfunc(
        RepeatedLookupKeyMode::DifferentExprDynamic,
        "bpf_list_front",
        MirType::bpf_list_head_root_struct("node_data", "node"),
        MirType::bpf_list_node_struct(),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RepeatedLookupKeyMode {
    SameConst,
    CopiedDynamic,
    PhiCopiedDynamic,
    NoopDynamic,
    OffsetDynamic,
    EquivalentExprDynamic,
    DifferentExprDynamic,
    SameCtxFieldReload,
    DifferentConst,
}

fn graph_lock_root_repeated_lookup_for_kfunc(
    key_mode: RepeatedLookupKeyMode,
    kfunc: &str,
    root_ty: MirType,
    node_ty: MirType,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let lock_ready = func.alloc_block();
    let use_root = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let selector = if key_mode == RepeatedLookupKeyMode::PhiCopiedDynamic {
        Some(func.alloc_vreg())
    } else {
        None
    };
    let root_key = if key_mode == RepeatedLookupKeyMode::SameConst {
        key
    } else {
        func.alloc_vreg()
    };
    let lock_key = if matches!(
        key_mode,
        RepeatedLookupKeyMode::EquivalentExprDynamic | RepeatedLookupKeyMode::DifferentExprDynamic
    ) {
        func.alloc_vreg()
    } else {
        key
    };
    let lock_value = func.alloc_vreg();
    let lock_value_non_null = func.alloc_vreg();
    let root_value = func.alloc_vreg();
    let root_value_non_null = func.alloc_vreg();
    let lock = func.alloc_vreg();
    let root = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let node = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();
    let graph_items = MapRef {
        name: "graph_items".to_string(),
        kind: MapKind::Hash,
    };

    let lookup_entry = if key_mode == RepeatedLookupKeyMode::PhiCopiedDynamic {
        func.param_count = 2;
        let left = func.alloc_block();
        let right = func.alloc_block();
        let join = func.alloc_block();
        let left_key = func.alloc_vreg();
        let right_key = func.alloc_vreg();
        func.block_mut(entry).terminator = MirInst::Branch {
            cond: selector.expect("phi copied key mode has selector"),
            if_true: left,
            if_false: right,
        };
        for (block, copied_key) in [(left, left_key), (right, right_key)] {
            func.block_mut(block).instructions.push(MirInst::Copy {
                dst: copied_key,
                src: MirValue::VReg(key),
            });
            func.block_mut(block).terminator = MirInst::Jump { target: join };
        }
        func.block_mut(join).instructions.push(MirInst::Phi {
            dst: root_key,
            args: vec![(left, left_key), (right, right_key)],
        });
        join
    } else if key_mode == RepeatedLookupKeyMode::CopiedDynamic {
        func.param_count = 1;
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: root_key,
            src: MirValue::VReg(key),
        });
        entry
    } else if key_mode == RepeatedLookupKeyMode::NoopDynamic {
        func.param_count = 1;
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: root_key,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(key),
            rhs: MirValue::Const(0),
        });
        entry
    } else if key_mode == RepeatedLookupKeyMode::OffsetDynamic {
        func.param_count = 1;
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: root_key,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(key),
            rhs: MirValue::Const(1),
        });
        entry
    } else if matches!(
        key_mode,
        RepeatedLookupKeyMode::EquivalentExprDynamic | RepeatedLookupKeyMode::DifferentExprDynamic
    ) {
        func.param_count = 1;
        let root_offset = if key_mode == RepeatedLookupKeyMode::EquivalentExprDynamic {
            1
        } else {
            2
        };
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: lock_key,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(key),
            rhs: MirValue::Const(1),
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: root_key,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(key),
            rhs: MirValue::Const(root_offset),
        });
        entry
    } else if key_mode == RepeatedLookupKeyMode::SameCtxFieldReload {
        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: key,
                field: CtxField::PacketLen,
                slot: None,
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::LoadCtxField {
                dst: root_key,
                field: CtxField::PacketLen,
                slot: None,
            });
        entry
    } else {
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::Const(0),
        });
        if key_mode == RepeatedLookupKeyMode::DifferentConst {
            func.block_mut(entry).instructions.push(MirInst::Copy {
                dst: root_key,
                src: MirValue::Const(1),
            });
        }
        entry
    };
    func.block_mut(lookup_entry)
        .instructions
        .push(MirInst::MapLookup {
            dst: lock_value,
            map: graph_items.clone(),
            key: lock_key,
        });
    func.block_mut(lookup_entry)
        .instructions
        .push(MirInst::BinOp {
            dst: lock_value_non_null,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(lock_value),
            rhs: MirValue::Const(0),
        });
    func.block_mut(lookup_entry).terminator = MirInst::Branch {
        cond: lock_value_non_null,
        if_true: lock_ready,
        if_false: done,
    };

    func.block_mut(lock_ready)
        .instructions
        .push(MirInst::MapLookup {
            dst: root_value,
            map: graph_items,
            key: root_key,
        });
    func.block_mut(lock_ready)
        .instructions
        .push(MirInst::BinOp {
            dst: root_value_non_null,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(root_value),
            rhs: MirValue::Const(0),
        });
    func.block_mut(lock_ready).terminator = MirInst::Branch {
        cond: root_value_non_null,
        if_true: use_root,
        if_false: done,
    };

    func.block_mut(use_root).instructions.push(MirInst::Copy {
        dst: lock,
        src: MirValue::VReg(lock_value),
    });
    func.block_mut(use_root).instructions.push(MirInst::BinOp {
        dst: root,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(root_value),
        rhs: MirValue::Const(8),
    });
    push_bpf_spin_lock_call(&mut func, use_root, lock_ret, lock);
    func.block_mut(use_root)
        .instructions
        .push(MirInst::CallKfunc {
            dst: node,
            kfunc: kfunc.to_string(),
            btf_id: None,
            args: vec![root],
        });
    push_bpf_spin_unlock_call(&mut func, use_root, unlock_ret, lock);
    func.block_mut(use_root).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    for i in 0..func.vreg_count {
        types.insert(VReg(i), MirType::I64);
    }
    let graph_value = graph_value_with_lock_and_graph_root_ty(root_ty.clone());
    for value in [lock_value, root_value] {
        types.insert(
            value,
            MirType::Ptr {
                pointee: Box::new(graph_value.clone()),
                address_space: AddressSpace::Map,
            },
        );
    }
    types.insert(
        lock,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_spin_lock_struct()),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(
        root,
        MirType::Ptr {
            pointee: Box::new(root_ty),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(
        node,
        MirType::Ptr {
            pointee: Box::new(node_ty),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(lock_value_non_null, MirType::Bool);
    types.insert(root_value_non_null, MirType::Bool);
    types.insert(lock_ret, MirType::I64);
    types.insert(unlock_ret, MirType::I64);

    (func, types)
}

#[test]
fn test_verify_mir_for_probe_context_sched_ext_dispatch_only_kfunc_rejected_in_select_cpu() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_dispatch_nr_slots".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new_struct_ops_callback("sched_ext_ops", "select_cpu");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected dispatch-only sched_ext kfunc to be rejected outside dispatch");
    assert!(err.iter().any(|e| e.message.contains(
        "kfunc 'scx_bpf_dispatch_nr_slots' is only valid in sched_ext_ops.dispatch, not sched_ext_ops.select_cpu"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_sched_ext_dispatch_only_kfunc_allowed_in_dispatch() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_dispatch_nr_slots".to_string(),
        btf_id: None,
        args: vec![],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let probe_ctx = ProbeContext::new_struct_ops_callback("sched_ext_ops", "dispatch");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected dispatch-only sched_ext kfunc to verify in dispatch");
}

#[test]
fn test_verify_mir_for_probe_context_sched_ext_create_dsq_rejected_in_dispatch() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    let dsq_id = func.alloc_vreg();
    let node = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dsq_id,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: node,
        src: MirValue::Const(-1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_create_dsq".to_string(),
        btf_id: None,
        args: vec![dsq_id, node],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);
    types.insert(dsq_id, MirType::I64);
    types.insert(node, MirType::I64);

    let probe_ctx = ProbeContext::new_struct_ops_callback("sched_ext_ops", "dispatch");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected create_dsq to be rejected outside sleepable callbacks");
    assert!(err.iter().any(|e| e.message.contains(
        "kfunc 'scx_bpf_create_dsq' is only valid in sleepable sched_ext_ops callbacks, not sched_ext_ops.dispatch"
    )));
}

#[test]
fn test_verify_mir_for_probe_context_sched_ext_create_dsq_allowed_in_sleepable_init() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    let dsq_id = func.alloc_vreg();
    let node = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dsq_id,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: node,
        src: MirValue::Const(-1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_create_dsq".to_string(),
        btf_id: None,
        args: vec![dsq_id, node],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);
    types.insert(dsq_id, MirType::I64);
    types.insert(node, MirType::I64);

    let probe_ctx = ProbeContext::new_struct_ops_callback("sched_ext_ops", "init");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected create_dsq to verify in sleepable sched_ext_ops.init");
}

