#[test]
fn test_dynptr_initialized_slots_join_requires_all_paths() {
    let slot = StackSlotId(7);
    let mut initialized = VerifierState::new(1);
    initialized.initialize_dynptr_slot(slot);
    let uninitialized = VerifierState::new(1);

    let merged = initialized.join(&uninitialized);
    assert!(
        !merged.is_dynptr_slot_initialized(slot),
        "dynptr slot initialization should require all incoming paths"
    );
    assert!(
        merged.is_dynptr_slot_maybe_initialized(slot),
        "dynptr slot reinitialization should reject if any incoming path initializes"
    );

    let merged_initialized = initialized.join(&initialized);
    assert!(
        merged_initialized.is_dynptr_slot_initialized(slot),
        "dynptr slot initialization should be preserved when all paths initialize"
    );
    assert!(
        merged_initialized.is_dynptr_slot_maybe_initialized(slot),
        "dynptr maybe-initialized state should be preserved when all paths initialize"
    );
}

#[test]
fn test_unknown_stack_object_slots_join_requires_all_paths() {
    let slot = StackSlotId(11);
    let mut initialized = VerifierState::new(1);
    initialized.initialize_unknown_stack_object_slot(slot, "bpf_wq", None);
    let uninitialized = VerifierState::new(1);

    let merged = initialized.join(&uninitialized);
    assert!(
        !merged.has_unknown_stack_object_slot(slot, "bpf_wq", None),
        "unknown stack-object slot initialization should require all incoming paths"
    );

    let merged_initialized = initialized.join(&initialized);
    assert!(
        merged_initialized.has_unknown_stack_object_slot(slot, "bpf_wq", None),
        "unknown stack-object slot initialization should be preserved when all paths initialize"
    );
}

#[test]
fn test_unknown_stack_object_slots_join_tracks_maybe_live_for_exit_checks() {
    let slot = StackSlotId(13);
    let mut initialized = VerifierState::new(1);
    initialized.initialize_unknown_stack_object_slot(slot, "bpf_wq", None);
    let uninitialized = VerifierState::new(1);

    let merged = initialized.join(&uninitialized);
    assert!(
        !merged.has_unknown_stack_object_slot(slot, "bpf_wq", None),
        "unknown stack-object use/release should still require all incoming paths"
    );
    assert!(
        merged.first_live_unknown_stack_object().is_some(),
        "mixed-path unknown stack-object state should still be considered live for exit checks"
    );
}

#[test]
fn test_unknown_stack_object_slot_live_presence() {
    let slot = StackSlotId(17);
    let mut state = VerifierState::new(1);
    assert!(
        !state.has_live_unknown_stack_object_slot(slot),
        "slot should start with no live unknown stack object state"
    );

    state.initialize_unknown_stack_object_slot(slot, "bpf_wq", None);
    assert!(
        state.has_live_unknown_stack_object_slot(slot),
        "initialized slot should be considered live"
    );

    assert!(
        state.release_unknown_stack_object_slot(slot, "bpf_wq", None),
        "release should succeed for initialized slot"
    );
    assert!(
        !state.has_live_unknown_stack_object_slot(slot),
        "released slot should no longer be considered live"
    );
}

#[test]
fn test_unknown_stack_object_slots_distinguish_type_ids() {
    let slot = StackSlotId(19);
    let mut state = VerifierState::new(1);
    state.initialize_unknown_stack_object_slot(slot, "bpf_wq", Some(11));

    assert!(
        state.has_unknown_stack_object_slot(slot, "bpf_wq", Some(11)),
        "matching type id should resolve initialized state"
    );
    assert!(
        !state.has_unknown_stack_object_slot(slot, "bpf_wq", Some(12)),
        "different type id should not alias initialized state"
    );
    assert!(
        !state.has_unknown_stack_object_slot(slot, "bpf_wq", None),
        "missing type id should not alias typed initialized state"
    );
    assert!(
        !state.release_unknown_stack_object_slot(slot, "bpf_wq", Some(12)),
        "release should reject mismatched type id"
    );
    assert!(
        state.release_unknown_stack_object_slot(slot, "bpf_wq", Some(11)),
        "release should succeed for matching type id"
    );
}

#[test]
fn test_kfunc_unknown_signature_rejected() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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

    let err = verify_mir(&func, &types).expect_err("expected unknown-kfunc verifier error");
    assert!(err.iter().any(|e| e.message.contains("unknown kfunc")));
}

#[test]
fn test_kfunc_pointer_argument_required() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
    assert!(err.iter().any(|e| e.message.contains("expects pointer")));
}

#[test]
fn test_kfunc_pointer_argument_requires_kernel_space() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_local_irq_save_requires_stack_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_local_irq_save_rejects_context_derived_stack_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
        err.iter()
            .any(|e| e.message.contains("expects stack pointer from stack slot")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_local_irq_save_requires_stack_slot_base_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_res_spin_lock_requires_kernel_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_res_spin_lock_requires_res_spin_lock_pointee() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_res_spin_lock".to_string(),
        btf_id: None,
        args: vec![task],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(task, MirType::named_kernel_struct_ptr("task_struct"));
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected res_spin_lock pointee error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects bpf_res_spin_lock pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_res_spin_lock_irqsave_requires_stack_flags_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
            .any(|e| e.message.contains("arg1 expects stack pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_list_push_front_requires_graph_root_space() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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

    let err = verify_mir(&func, &types).expect_err("expected graph-root kfunc arg error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc bpf_list root expects pointer in [Map, Kernel]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_list_front_requires_bpf_spin_lock_held() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let root = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_list_front".to_string(),
        btf_id: None,
        args: vec![root],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        root,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_list_head_struct()),
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

    let err = verify_mir(&func, &types).expect_err("expected missing bpf_spin_lock error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires bpf_spin_lock from the same map value")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_list_front_accepts_same_map_value_bpf_spin_lock() {
    let (func, types) = graph_lock_root_function(true);

    verify_mir(&func, &types).expect("same map-value graph lock/root should verify");
}

#[test]
fn test_kfunc_list_front_accepts_same_key_repeated_map_lookup_bpf_spin_lock() {
    let (func, types) = graph_lock_root_repeated_lookup_function(true);

    verify_mir(&func, &types).expect("same map/key graph lock/root should verify");
}

#[test]
fn test_kfunc_list_front_accepts_copied_dynamic_key_repeated_map_lookup_bpf_spin_lock() {
    let (func, types) = graph_lock_root_repeated_lookup_copied_key_function();

    verify_mir(&func, &types).expect("copied dynamic map key graph lock/root should verify");
}

#[test]
fn test_kfunc_list_front_accepts_noop_dynamic_key_repeated_map_lookup_bpf_spin_lock() {
    let (func, types) = graph_lock_root_repeated_lookup_noop_key_function();

    verify_mir(&func, &types).expect("noop dynamic map key graph lock/root should verify");
}

#[test]
fn test_kfunc_list_front_rejects_offset_dynamic_key_repeated_map_lookup_bpf_spin_lock() {
    let (func, types) = graph_lock_root_repeated_lookup_offset_key_function();

    let err = verify_mir(&func, &types).expect_err("expected offset-key graph lock/root error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires bpf_spin_lock from the same map value")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_list_front_accepts_equivalent_expr_key_repeated_map_lookup_bpf_spin_lock() {
    let (func, types) = graph_lock_root_repeated_lookup_equivalent_expr_key_function();

    verify_mir(&func, &types).expect("equivalent expression map key graph lock/root should verify");
}

#[test]
fn test_kfunc_list_front_rejects_different_expr_key_repeated_map_lookup_bpf_spin_lock() {
    let (func, types) = graph_lock_root_repeated_lookup_different_expr_key_function();

    let err = verify_mir(&func, &types).expect_err("expected different expression-key error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires bpf_spin_lock from the same map value")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_list_front_accepts_phi_key_repeated_map_lookup_bpf_spin_lock() {
    let (func, types) = graph_lock_root_repeated_lookup_phi_key_function();

    verify_mir(&func, &types).expect("phi-copied dynamic map key graph lock/root should verify");
}

#[test]
fn test_kfunc_list_front_accepts_same_ctx_field_repeated_map_lookup_bpf_spin_lock() {
    let (func, types) = graph_lock_root_repeated_lookup_ctx_field_key_function();

    verify_mir(&func, &types).expect("same ctx-field map key graph lock/root should verify");
}

#[test]
fn test_kfunc_list_front_rejects_different_map_value_bpf_spin_lock() {
    let (func, types) = graph_lock_root_function(false);

    let err = verify_mir(&func, &types).expect_err("expected mismatched graph lock/root error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires bpf_spin_lock from the same map value")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_list_front_rejects_different_key_repeated_map_lookup_bpf_spin_lock() {
    let (func, types) = graph_lock_root_repeated_lookup_function(false);

    let err = verify_mir(&func, &types).expect_err("expected different-key graph lock/root error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires bpf_spin_lock from the same map value")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_rbtree_first_accepts_same_key_repeated_map_lookup_bpf_spin_lock() {
    let (func, types) = graph_rbtree_lock_root_repeated_lookup_function(true);

    verify_mir(&func, &types).expect("same map/key rbtree lock/root should verify");
}

#[test]
fn test_kfunc_rbtree_first_rejects_different_key_repeated_map_lookup_bpf_spin_lock() {
    let (func, types) = graph_rbtree_lock_root_repeated_lookup_function(false);

    let err = verify_mir(&func, &types).expect_err("expected different-key rbtree lock/root error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires bpf_spin_lock from the same map value")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_path_d_path_requires_kernel_path_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_path_d_path_buffer_requires_stack_or_map_space() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call_block = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let path_ptr = func.alloc_vreg();
    let buf_ptr = func.alloc_vreg();
    let size = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(32),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(buf_ptr),
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
            kfunc: "bpf_path_d_path".to_string(),
            btf_id: None,
            args: vec![path_ptr, buf_ptr, size],
        });
    func.block_mut(call_block).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_path_d_path_requires_positive_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_path_d_path_requires_bounded_size_for_stack_buffer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
            .any(|e| e.message.contains("arg2 must have bounded upper range")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_path_d_path_requires_stack_slot_base_buffer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_path_d_path_accepts_stack_buffer_rule() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
fn test_kfunc_copy_from_user_str_src_requires_user_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_copy_from_user_str_rejects_zero_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let src = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let size = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let dst_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(0),
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
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(size, MirType::I64);
    types.insert(flags, MirType::I64);
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected copy_from_user_str zero-size error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_copy_from_user_str' arg1 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_copy_from_user_str_requires_stack_slot_base_dst() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_copy_from_user_task_str_rejects_cgroup_task_argument() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
fn test_kfunc_copy_from_user_task_str_rejects_zero_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let src = func.alloc_vreg();
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let size = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let dst_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(0),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: task,
            helper: BpfHelper::GetCurrentTaskBtf as u32,
            args: vec![],
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_copy_from_user_task_str".to_string(),
        btf_id: None,
        args: vec![dst, size, src, task, flags],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        src,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(task, MirType::named_kernel_struct_ptr("task_struct"));
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
        verify_mir(&func, &types).expect_err("expected copy_from_user_task_str zero-size error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_copy_from_user_task_str' arg1 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_copy_from_user_dynptr_src_requires_user_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dptr = func.alloc_vreg();
    let off = func.alloc_vreg();
    let size = func.alloc_vreg();
    let src = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let src_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dptr,
        src: MirValue::StackSlot(dptr_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: src,
        src: MirValue::StackSlot(src_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_copy_from_user_dynptr".to_string(),
        btf_id: None,
        args: vec![dptr, off, size, src],
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
    types.insert(size, MirType::I64);
    types.insert(
        src,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected copy_from_user_dynptr user-source error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc bpf_copy_from_user_dynptr src expects pointer in [User], got Stack")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_copy_from_user_dynptr_rejects_zero_size() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let dptr = func.alloc_vreg();
    let off = func.alloc_vreg();
    let size = func.alloc_vreg();
    let src = func.alloc_vreg();
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
        dst: size,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_copy_from_user_dynptr".to_string(),
        btf_id: None,
        args: vec![dptr, off, size, src],
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
    types.insert(size, MirType::I64);
    types.insert(
        src,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::User,
        },
    );
    types.insert(ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected copy_from_user_dynptr zero-size error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_copy_from_user_dynptr' arg2 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_copy_from_user_dynptr_requires_stack_slot_base_dptr() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let src = func.alloc_vreg();
    let dptr_base = func.alloc_vreg();
    let dptr = func.alloc_vreg();
    let off = func.alloc_vreg();
    let size = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dptr_base,
        src: MirValue::StackSlot(dptr_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: dptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(dptr_base),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_copy_from_user_dynptr".to_string(),
        btf_id: None,
        args: vec![dptr, off, size, src],
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
        dptr_base,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        dptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(off, MirType::I64);
    types.insert(size, MirType::I64);
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected copy_from_user_dynptr stack-slot-base error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects stack slot base pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_copy_from_user_dynptr_rejects_destination_initialized_on_one_path() {
    let (func, types) = copy_from_user_dynptr_join_reinitialize_mir();
    let err = verify_mir(&func, &types)
        .expect_err("expected copy_from_user_dynptr reinitialize error at join");
    assert!(
        err.iter().any(|e| e.message.contains(
            "kfunc 'bpf_copy_from_user_dynptr' arg0 requires uninitialized dynptr stack object slot"
        )),
        "unexpected errors: {:?}",
        err
    );
}

fn assert_copy_from_user_task_dynptr_rejects_destination_initialized_on_one_path(kfunc: &str) {
    let (func, types) = copy_from_user_task_dynptr_join_reinitialize_mir(kfunc);
    let err = verify_mir(&func, &types)
        .expect_err("expected copy_from_user_task dynptr reinitialize error at join");
    assert!(
        err.iter().any(|e| e.message.contains(&format!(
            "kfunc '{kfunc}' arg0 requires uninitialized dynptr stack object slot"
        ))),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_task_dynptr_rejects_destination_initialized_on_one_path() {
    assert_copy_from_user_task_dynptr_rejects_destination_initialized_on_one_path(
        "bpf_copy_from_user_task_dynptr",
    );
}

#[test]
fn test_kfunc_task_str_dynptr_rejects_destination_initialized_on_one_path() {
    assert_copy_from_user_task_dynptr_rejects_destination_initialized_on_one_path(
        "bpf_copy_from_user_task_str_dynptr",
    );
}

#[test]
fn test_kfunc_copy_from_user_task_dynptr_rejects_cgroup_task_argument() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let src = func.alloc_vreg();
    let cgid = func.alloc_vreg();
    let cgroup = func.alloc_vreg();
    let dptr = func.alloc_vreg();
    let off = func.alloc_vreg();
    let size = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
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
        dst: dptr,
        src: MirValue::StackSlot(dptr_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_copy_from_user_task_dynptr".to_string(),
        btf_id: None,
        args: vec![dptr, off, size, src, cgroup],
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
        dptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(off, MirType::I64);
    types.insert(size, MirType::I64);
    types.insert(ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected copy_from_user_task_dynptr ref mismatch");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_copy_from_user_task_dynptr' arg4 expects task reference")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("cgroup reference")),
        "unexpected errors: {:?}",
        err
    );
}

fn assert_copy_from_user_task_dynptr_rejects_zero_size(kfunc: &str) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let src = func.alloc_vreg();
    let task = func.alloc_vreg();
    let dptr = func.alloc_vreg();
    let off = func.alloc_vreg();
    let size = func.alloc_vreg();
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
        dst: size,
        src: MirValue::Const(0),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: task,
            helper: BpfHelper::GetCurrentTaskBtf as u32,
            args: vec![],
        });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: kfunc.to_string(),
        btf_id: None,
        args: vec![dptr, off, size, src, task],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        src,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(task, MirType::named_kernel_struct_ptr("task_struct"));
    types.insert(
        dptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(off, MirType::I64);
    types.insert(size, MirType::I64);
    types.insert(ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected copy_from_user_task dynptr zero-size error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains(&format!("kfunc '{kfunc}' arg2 must be > 0"))),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_copy_from_user_task_dynptr_rejects_zero_size() {
    assert_copy_from_user_task_dynptr_rejects_zero_size("bpf_copy_from_user_task_dynptr");
}

#[test]
fn test_kfunc_copy_from_user_task_str_dynptr_rejects_zero_size() {
    assert_copy_from_user_task_dynptr_rejects_zero_size("bpf_copy_from_user_task_str_dynptr");
}

fn make_packet_dynptr_kfunc_verify_function(
    kfunc: &str,
    flags_value: i64,
    repeat_constructor: bool,
    read_size: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    make_packet_dynptr_kfunc_verify_function_with_optional_flags(
        kfunc,
        Some(flags_value),
        repeat_constructor,
        read_size,
    )
}

fn make_packet_dynptr_kfunc_verify_function_with_dynamic_flags(
    kfunc: &str,
) -> (MirFunction, HashMap<VReg, MirType>) {
    make_packet_dynptr_kfunc_verify_function_with_optional_flags(kfunc, None, false, false)
}

fn make_packet_dynptr_kfunc_verify_function_with_optional_flags(
    kfunc: &str,
    flags_value: Option<i64>,
    repeat_constructor: bool,
    read_size: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dptr = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let second_ret = func.alloc_vreg();
    let size_ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    if let Some(flags_value) = flags_value {
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: flags,
            src: MirValue::Const(flags_value),
        });
    }
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dptr,
        src: MirValue::StackSlot(dptr_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: kfunc.to_string(),
        btf_id: None,
        args: vec![ctx, flags, dptr],
    });
    if repeat_constructor {
        func.block_mut(entry).instructions.push(MirInst::CallKfunc {
            dst: second_ret,
            kfunc: kfunc.to_string(),
            btf_id: None,
            args: vec![ctx, flags, dptr],
        });
    }
    if read_size {
        func.block_mut(entry).instructions.push(MirInst::CallKfunc {
            dst: size_ret,
            kfunc: "bpf_dynptr_size".to_string(),
            btf_id: None,
            args: vec![dptr],
        });
    }
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(flags, MirType::I64);
    types.insert(
        dptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(ret, MirType::I64);
    types.insert(second_ret, MirType::I64);
    types.insert(size_ret, MirType::I64);

    (func, types)
}

#[test]
fn test_packet_dynptr_kfuncs_initialize_stack_slot() {
    for kfunc in ["bpf_dynptr_from_xdp", "bpf_dynptr_from_skb"] {
        let (func, types) = make_packet_dynptr_kfunc_verify_function(kfunc, 0, false, true);
        verify_mir(&func, &types)
            .unwrap_or_else(|err| panic!("expected {kfunc} to initialize dynptr: {err:?}"));
    }
}

#[test]
fn test_kfunc_dynptr_subfn_init_size_balanced() {
    let mut init = MirFunction::new();
    let init_entry = init.alloc_block();
    init.entry = init_entry;
    init.param_count = 2;
    init.vreg_count = 2;
    init.param_non_null.insert(1);
    let init_dptr_slot = init.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    init.param_stack_slots.insert(0, init_dptr_slot);
    let off = init.alloc_vreg();
    let size_arg = init.alloc_vreg();
    let init_ret = init.alloc_vreg();
    init.block_mut(init_entry).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    init.block_mut(init_entry).instructions.push(MirInst::Copy {
        dst: size_arg,
        src: MirValue::Const(8),
    });
    init.block_mut(init_entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst: init_ret,
            kfunc: "bpf_copy_from_user_dynptr".to_string(),
            btf_id: None,
            args: vec![VReg(0), off, size_arg, VReg(1)],
        });
    init.block_mut(init_entry).terminator = MirInst::Return { val: None };

    let mut size = MirFunction::new();
    let size_entry = size.alloc_block();
    size.entry = size_entry;
    size.param_count = 1;
    size.vreg_count = 1;
    let size_dptr_slot = size.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    size.param_stack_slots.insert(0, size_dptr_slot);
    let size_ret = size.alloc_vreg();
    size.block_mut(size_entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst: size_ret,
            kfunc: "bpf_dynptr_size".to_string(),
            btf_id: None,
            args: vec![VReg(0)],
        });
    size.block_mut(size_entry).terminator = MirInst::Return { val: None };

    let summaries = infer_subfunction_summaries(&[init.clone(), size.clone()]);
    let init_summary = summaries
        .get(&SubfunctionId(0))
        .cloned()
        .expect("expected init summary");
    let size_summary = summaries
        .get(&SubfunctionId(1))
        .cloned()
        .expect("expected size summary");
    assert_eq!(init_summary.dynptr_delta_arg(0), 1);
    assert!(size_summary.requires_initialized_dynptr_arg(0));

    let dynptr_ty = MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::Stack,
    };
    let user_ptr_ty = MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::User,
    };
    let mut init_types = HashMap::new();
    init_types.insert(VReg(0), dynptr_ty.clone());
    init_types.insert(VReg(1), user_ptr_ty.clone());
    init_types.insert(off, MirType::I64);
    init_types.insert(size_arg, MirType::I64);
    init_types.insert(init_ret, MirType::I64);
    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &init,
        &init_types,
        &summaries,
        Some(init_summary),
        None,
        None,
    )
    .expect("expected dynptr init wrapper to verify");
    let mut size_types = HashMap::new();
    size_types.insert(VReg(0), dynptr_ty.clone());
    size_types.insert(size_ret, MirType::I64);
    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &size,
        &size_types,
        &summaries,
        Some(size_summary),
        None,
        None,
    )
    .expect("expected dynptr size wrapper to verify");

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;
    func.vreg_count = 1;
    func.param_non_null.insert(0);
    let src = VReg(0);
    let dptr = func.alloc_vreg();
    let init_call_ret = func.alloc_vreg();
    let size_call_ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dptr,
        src: MirValue::StackSlot(dptr_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst: init_call_ret,
        subfn: SubfunctionId(0),
        args: vec![dptr, src],
    });
    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst: size_call_ret,
        subfn: SubfunctionId(1),
        args: vec![dptr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(src, user_ptr_ty);
    types.insert(dptr, dynptr_ty);
    types.insert(init_call_ret, MirType::I64);
    types.insert(size_call_ret, MirType::I64);
    verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect("expected dynptr init/size wrappers to compose");
}

#[test]
fn test_kfunc_dynptr_subfn_clone_initializes_destination_stack_slot() {
    let mut clone = MirFunction::new();
    let clone_entry = clone.alloc_block();
    clone.entry = clone_entry;
    clone.param_count = 2;
    clone.vreg_count = 2;
    let clone_src_slot = clone.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let clone_dst_slot = clone.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    clone.param_stack_slots.insert(0, clone_src_slot);
    clone.param_stack_slots.insert(1, clone_dst_slot);
    let clone_ret = clone.alloc_vreg();
    clone
        .block_mut(clone_entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst: clone_ret,
            kfunc: "bpf_dynptr_clone".to_string(),
            btf_id: None,
            args: vec![VReg(0), VReg(1)],
        });
    clone.block_mut(clone_entry).terminator = MirInst::Return { val: None };

    let summaries = infer_subfunction_summaries(&[clone.clone()]);
    let clone_summary = summaries
        .get(&SubfunctionId(0))
        .cloned()
        .expect("expected clone summary");
    assert!(clone_summary.requires_initialized_dynptr_arg(0));
    assert_eq!(clone_summary.dynptr_delta_arg(0), 0);
    assert_eq!(clone_summary.dynptr_delta_arg(1), 1);

    let dynptr_ty = MirType::Ptr {
        pointee: Box::new(MirType::opaque_named_struct("bpf_dynptr")),
        address_space: AddressSpace::Stack,
    };
    let mut clone_types = HashMap::new();
    clone_types.insert(VReg(0), dynptr_ty.clone());
    clone_types.insert(VReg(1), dynptr_ty.clone());
    clone_types.insert(clone_ret, MirType::I64);
    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &clone,
        &clone_types,
        &summaries,
        Some(clone_summary),
        None,
        None,
    )
    .expect("expected dynptr clone wrapper to verify");

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let src = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let subfn_ret = func.alloc_vreg();
    let size_ret = func.alloc_vreg();
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.entry_initialized_dynptr_slots.insert(src_slot);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: src,
        src: MirValue::StackSlot(src_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst: subfn_ret,
        subfn: SubfunctionId(0),
        args: vec![src, dst],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: size_ret,
        kfunc: "bpf_dynptr_size".to_string(),
        btf_id: None,
        args: vec![dst],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(src, dynptr_ty.clone());
    types.insert(dst, dynptr_ty);
    types.insert(subfn_ret, MirType::I64);
    types.insert(size_ret, MirType::I64);
    verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect("expected dynptr clone wrapper to initialize caller destination");
}

#[test]
fn test_kfunc_dynptr_subfn_conditional_init_blocks_reinitialize() {
    let mut init = MirFunction::new();
    let entry = init.alloc_block();
    let init_path = init.alloc_block();
    let done = init.alloc_block();
    init.entry = entry;
    init.param_count = 3;
    init.vreg_count = 3;
    init.param_non_null.insert(1);
    let init_dptr_slot = init.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    init.param_stack_slots.insert(0, init_dptr_slot);
    let off = init.alloc_vreg();
    let size_arg = init.alloc_vreg();
    let init_ret = init.alloc_vreg();
    init.block_mut(entry).terminator = MirInst::Branch {
        cond: VReg(2),
        if_true: init_path,
        if_false: done,
    };
    init.block_mut(init_path).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    init.block_mut(init_path).instructions.push(MirInst::Copy {
        dst: size_arg,
        src: MirValue::Const(8),
    });
    init.block_mut(init_path)
        .instructions
        .push(MirInst::CallKfunc {
            dst: init_ret,
            kfunc: "bpf_copy_from_user_dynptr".to_string(),
            btf_id: None,
            args: vec![VReg(0), off, size_arg, VReg(1)],
        });
    init.block_mut(init_path).terminator = MirInst::Return { val: None };
    init.block_mut(done).terminator = MirInst::Return { val: None };

    let summaries = infer_subfunction_summaries(&[init]);
    let init_summary = summaries
        .get(&SubfunctionId(0))
        .cloned()
        .expect("expected init summary");
    assert_eq!(init_summary.dynptr_delta_arg(0), 0);
    assert!(init_summary.maybe_initializes_dynptr_arg(0));

    let mut func = MirFunction::new();
    let caller_entry = func.alloc_block();
    func.entry = caller_entry;
    func.param_count = 2;
    func.vreg_count = 2;
    func.param_non_null.insert(0);
    let src = VReg(0);
    let cond = VReg(1);
    let dptr = func.alloc_vreg();
    let call_ret = func.alloc_vreg();
    let retry_off = func.alloc_vreg();
    let retry_size = func.alloc_vreg();
    let retry_ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(caller_entry)
        .instructions
        .push(MirInst::Copy {
            dst: dptr,
            src: MirValue::StackSlot(dptr_slot),
        });
    func.block_mut(caller_entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: call_ret,
            subfn: SubfunctionId(0),
            args: vec![dptr, src, cond],
        });
    func.block_mut(caller_entry)
        .instructions
        .push(MirInst::Copy {
            dst: retry_off,
            src: MirValue::Const(0),
        });
    func.block_mut(caller_entry)
        .instructions
        .push(MirInst::Copy {
            dst: retry_size,
            src: MirValue::Const(8),
        });
    func.block_mut(caller_entry)
        .instructions
        .push(MirInst::CallKfunc {
            dst: retry_ret,
            kfunc: "bpf_copy_from_user_dynptr".to_string(),
            btf_id: None,
            args: vec![dptr, retry_off, retry_size, src],
        });
    func.block_mut(caller_entry).terminator = MirInst::Return { val: None };

    let dynptr_ty = MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::Stack,
    };
    let user_ptr_ty = MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::User,
    };
    let mut types = HashMap::new();
    types.insert(src, user_ptr_ty);
    types.insert(cond, MirType::Bool);
    types.insert(dptr, dynptr_ty);
    types.insert(call_ret, MirType::I64);
    types.insert(retry_off, MirType::I64);
    types.insert(retry_size, MirType::I64);
    types.insert(retry_ret, MirType::I64);

    let err = verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect_err("expected maybe-initialized dynptr reinit error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires uninitialized dynptr stack object slot")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_unknown_stack_object_subfn_conditional_init_blocks_reinitialize() {
    let fixture = unknown_stack_object_conditional_init_blocks_reinitialize_mir();
    let summaries = infer_subfunction_summaries(&fixture.subfunctions);
    let init_summary = summaries
        .get(&SubfunctionId(0))
        .cloned()
        .expect("expected init summary");
    assert!(init_summary.unknown_stack_object_delta_arg(0).is_none());
    let maybe = init_summary
        .unknown_stack_object_maybe_initialized_arg(0)
        .expect("expected maybe-initialized unknown stack object");
    assert_eq!(maybe.type_name, "bpf_test_obj");
    assert_eq!(maybe.type_id, Some(0xbeef));

    let err =
        verify_mir_with_subfunction_summaries(&fixture.caller, &fixture.caller_types, &summaries)
            .expect_err("expected maybe-initialized unknown stack object reinit error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires uninitialized bpf_test_obj stack object slot")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_unknown_stack_object_subfn_lifecycle_composes() {
    let fixture = unknown_stack_object_lifecycle_composes_mir();
    let summaries = infer_subfunction_summaries(&fixture.subfunctions);
    let init_summary = summaries
        .get(&SubfunctionId(0))
        .cloned()
        .expect("expected init summary");
    let destroy_summary = summaries
        .get(&SubfunctionId(1))
        .cloned()
        .expect("expected destroy summary");

    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &fixture.subfunctions[0],
        &fixture.subfunction_types[0],
        &summaries,
        Some(init_summary),
        None,
        None,
    )
    .expect("expected init subfunction to verify");

    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &fixture.subfunctions[1],
        &fixture.subfunction_types[1],
        &summaries,
        Some(destroy_summary),
        None,
        None,
    )
    .expect("expected destroy subfunction to verify");

    verify_mir_with_subfunction_summaries(&fixture.caller, &fixture.caller_types, &summaries)
        .expect("expected unknown stack object init/destroy wrappers to compose");
}

#[test]
fn test_unknown_stack_object_subfn_copy_initializes_destination_stack_slot() {
    let fixture = unknown_stack_object_copy_initializes_destination_mir();
    let summaries = infer_subfunction_summaries(&fixture.subfunctions);
    let copy_summary = summaries
        .get(&SubfunctionId(1))
        .cloned()
        .expect("expected copy summary");
    assert!(copy_summary.unknown_stack_object_required_arg(0).is_some());
    let dst_delta = copy_summary
        .unknown_stack_object_delta_arg(1)
        .expect("expected copy destination delta");
    assert_eq!(dst_delta.delta, 1);

    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &fixture.subfunctions[1],
        &fixture.subfunction_types[1],
        &summaries,
        Some(copy_summary),
        None,
        None,
    )
    .expect("expected unknown stack object copy wrapper to verify");

    verify_mir_with_subfunction_summaries(&fixture.caller, &fixture.caller_types, &summaries)
        .expect("expected unknown stack object copy wrapper to initialize caller destination");
}

#[test]
fn test_unknown_stack_object_subfn_init_blocks_reinitialize() {
    let fixture = unknown_stack_object_init_blocks_reinitialize_mir();
    let summaries = infer_subfunction_summaries(&fixture.subfunctions);
    let err =
        verify_mir_with_subfunction_summaries(&fixture.caller, &fixture.caller_types, &summaries)
            .expect_err("expected unknown stack object reinit error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires uninitialized bpf_test_obj stack object slot")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_packet_dynptr_kfuncs_require_zero_flags() {
    for kfunc in ["bpf_dynptr_from_xdp", "bpf_dynptr_from_skb"] {
        let (func, types) = make_packet_dynptr_kfunc_verify_function(kfunc, 1, false, false);
        let err = verify_mir(&func, &types).expect_err("expected packet dynptr kfunc flags error");
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
fn test_packet_dynptr_kfuncs_reject_dynamic_flags() {
    for kfunc in ["bpf_dynptr_from_xdp", "bpf_dynptr_from_skb"] {
        let (func, types) = make_packet_dynptr_kfunc_verify_function_with_dynamic_flags(kfunc);
        let err = verify_mir(&func, &types)
            .expect_err("expected packet dynptr kfunc dynamic flags error");
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
fn test_dynptr_from_xdp_rejects_non_xdp_program() {
    let (func, types) =
        make_packet_dynptr_kfunc_verify_function("bpf_dynptr_from_xdp", 0, false, false);
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_dynptr_from_xdp to reject non-xdp program");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_dynptr_from_xdp' is only valid in xdp programs")),
        "unexpected errors: {:?}",
        err
    );
}

fn make_packet_dynptr_kfunc_verify_function_with_arg0(
    kfunc: &str,
    arg0_field: CtxField,
    arg0_type: MirType,
) -> (MirFunction, HashMap<VReg, MirType>) {
    make_packet_dynptr_kfunc_verify_function_with_arg0_copy(kfunc, arg0_field, arg0_type, false)
}

fn make_packet_dynptr_kfunc_verify_function_with_copied_arg0(
    kfunc: &str,
    arg0_field: CtxField,
    arg0_type: MirType,
) -> (MirFunction, HashMap<VReg, MirType>) {
    make_packet_dynptr_kfunc_verify_function_with_arg0_copy(kfunc, arg0_field, arg0_type, true)
}

fn make_packet_dynptr_kfunc_verify_function_with_arg0_copy(
    kfunc: &str,
    arg0_field: CtxField,
    arg0_type: MirType,
    copy_arg0: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let call_ctx = if copy_arg0 { func.alloc_vreg() } else { ctx };
    let flags = func.alloc_vreg();
    let dptr = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

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
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dptr,
        src: MirValue::StackSlot(dptr_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: kfunc.to_string(),
        btf_id: None,
        args: vec![call_ctx, flags, dptr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ctx, arg0_type.clone());
    if copy_arg0 {
        types.insert(call_ctx, arg0_type);
    }
    types.insert(flags, MirType::I64);
    types.insert(
        dptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(ret, MirType::I64);

    (func, types)
}

#[test]
fn test_dynptr_from_xdp_rejects_packet_pointer_arg0() {
    let (func, types) = make_packet_dynptr_kfunc_verify_function_with_arg0(
        "bpf_dynptr_from_xdp",
        CtxField::Data,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        },
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected packet pointer to fail dynptr_from_xdp arg0");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_dynptr_from_xdp' arg0 expects xdp_md pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_dynptr_from_xdp_accepts_copied_raw_context_arg0() {
    let (func, types) = make_packet_dynptr_kfunc_verify_function_with_copied_arg0(
        "bpf_dynptr_from_xdp",
        CtxField::Context,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected copied raw xdp context to satisfy dynptr_from_xdp arg0");
}

#[test]
fn test_dynptr_from_xdp_rejects_copied_packet_pointer_arg0() {
    let (func, types) = make_packet_dynptr_kfunc_verify_function_with_copied_arg0(
        "bpf_dynptr_from_xdp",
        CtxField::Data,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        },
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");

    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected copied packet pointer to fail dynptr_from_xdp arg0");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_dynptr_from_xdp' arg0 expects xdp_md pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_dynptr_from_skb_rejects_packet_pointer_arg0() {
    let (func, types) = make_packet_dynptr_kfunc_verify_function_with_arg0(
        "bpf_dynptr_from_skb",
        CtxField::Data,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        },
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected packet pointer to fail dynptr_from_skb arg0");
    assert!(
        err.iter().any(|e| e.message.contains(
            "kfunc 'bpf_dynptr_from_skb' arg0 expects __sk_buff context or sk_buff pointer"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_dynptr_from_skb_accepts_copied_tc_raw_context_arg0() {
    let (func, types) = make_packet_dynptr_kfunc_verify_function_with_copied_arg0(
        "bpf_dynptr_from_skb",
        CtxField::Context,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected copied tc raw context to satisfy dynptr_from_skb arg0");
}

#[test]
fn test_dynptr_from_skb_rejects_copied_packet_pointer_arg0() {
    let (func, types) = make_packet_dynptr_kfunc_verify_function_with_copied_arg0(
        "bpf_dynptr_from_skb",
        CtxField::Data,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        },
    );
    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");

    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected copied packet pointer to fail dynptr_from_skb arg0");
    assert!(
        err.iter().any(|e| e.message.contains(
            "kfunc 'bpf_dynptr_from_skb' arg0 expects __sk_buff context or sk_buff pointer"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_dynptr_from_skb_rejects_indirect_skb_raw_context() {
    let (func, types) =
        make_packet_dynptr_kfunc_verify_function("bpf_dynptr_from_skb", 0, false, false);

    for probe_ctx in [
        ProbeContext::new(EbpfProgramType::Netfilter, "ipv4:pre_routing"),
        ProbeContext::new(EbpfProgramType::Fentry, "tcp_v4_rcv"),
    ] {
        let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
            .expect_err("expected raw context to fail dynptr_from_skb arg0");
        assert!(
            err.iter().any(|e| e.message.contains(
                "kfunc 'bpf_dynptr_from_skb' arg0 expects __sk_buff context or sk_buff pointer"
            )),
            "unexpected errors: {:?}",
            err
        );
    }
}

#[test]
fn test_dynptr_from_skb_rejects_non_skb_program() {
    let (func, types) =
        make_packet_dynptr_kfunc_verify_function("bpf_dynptr_from_skb", 0, false, false);
    let probe_ctx = ProbeContext::new(EbpfProgramType::RawTracepoint, "sys_enter");

    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected bpf_dynptr_from_skb to reject non-skb program");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_dynptr_from_skb' is only valid in")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_packet_dynptr_kfuncs_reject_reinitialize() {
    for kfunc in ["bpf_dynptr_from_xdp", "bpf_dynptr_from_skb"] {
        let (func, types) = make_packet_dynptr_kfunc_verify_function(kfunc, 0, true, false);
        let err =
            verify_mir(&func, &types).expect_err("expected packet dynptr kfunc reinitialize error");
        assert!(
            err.iter().any(|e| e.message.contains(&format!(
                "kfunc '{kfunc}' arg2 requires uninitialized dynptr stack object slot"
            ))),
            "unexpected errors for {kfunc}: {:?}",
            err
        );
    }
}

#[test]
fn test_packet_dynptr_kfuncs_reject_destination_initialized_on_one_path() {
    for kfunc in ["bpf_dynptr_from_xdp", "bpf_dynptr_from_skb"] {
        let (func, types) = packet_dynptr_kfunc_join_reinitialize_mir(kfunc);
        let err = verify_mir(&func, &types)
            .expect_err("expected packet dynptr constructor reinitialize error at join");
        assert!(
            err.iter().any(|e| e.message.contains(&format!(
                "kfunc '{kfunc}' arg2 requires uninitialized dynptr stack object slot"
            ))),
            "unexpected errors for {kfunc}: {:?}",
            err
        );
    }
}

#[test]
fn test_kfunc_dynptr_clone_requires_stack_slot_base_dst() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let src = func.alloc_vreg();
    let dst_base = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: src,
        src: MirValue::StackSlot(src_slot),
    });
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
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_dynptr_clone".to_string(),
        btf_id: None,
        args: vec![src, dst],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected dynptr_clone stack-slot-base error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg1 expects stack slot base pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_dynptr_clone_rejects_same_stack_slot_src_and_dst() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let src = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: src,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_dynptr_clone".to_string(),
        btf_id: None,
        args: vec![src, dst],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
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
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected dynptr_clone same-slot error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("arg1 must reference distinct stack slot from arg0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_dynptr_clone_requires_initialized_source_stack_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let src = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let ret = func.alloc_vreg();
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
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_dynptr_clone".to_string(),
        btf_id: None,
        args: vec![src, dst],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        src,
        MirType::Ptr {
            pointee: Box::new(MirType::opaque_named_struct("bpf_dynptr")),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::opaque_named_struct("bpf_dynptr")),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected uninitialized dynptr clone source");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_dynptr_clone' arg0 requires initialized dynptr stack object")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_dynptr_clone_rejects_destination_initialized_on_one_path() {
    let (func, types) = dynptr_clone_join_reinitialize_mir();
    let err = verify_mir(&func, &types)
        .expect_err("expected partially initialized dynptr clone destination error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "kfunc 'bpf_dynptr_clone' arg1 requires uninitialized dynptr stack object slot"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_dynptr_size_requires_initialized_stack_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dptr = func.alloc_vreg();
    let ret = func.alloc_vreg();
    let dptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dptr,
        src: MirValue::StackSlot(dptr_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_dynptr_size".to_string(),
        btf_id: None,
        args: vec![dptr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dptr,
        MirType::Ptr {
            pointee: Box::new(MirType::opaque_named_struct("bpf_dynptr")),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected uninitialized dynptr error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_kfunc_dynptr_clone_initializes_destination_stack_slot() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let src = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let clone_ret = func.alloc_vreg();
    let size_ret = func.alloc_vreg();
    let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.entry_initialized_dynptr_slots.insert(src_slot);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: src,
        src: MirValue::StackSlot(src_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst,
        src: MirValue::StackSlot(dst_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: clone_ret,
        kfunc: "bpf_dynptr_clone".to_string(),
        btf_id: None,
        args: vec![src, dst],
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: size_ret,
        kfunc: "bpf_dynptr_size".to_string(),
        btf_id: None,
        args: vec![dst],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        src,
        MirType::Ptr {
            pointee: Box::new(MirType::opaque_named_struct("bpf_dynptr")),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::opaque_named_struct("bpf_dynptr")),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(clone_ret, MirType::I64);
    types.insert(size_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected clone destination dynptr to be initialized");
}

