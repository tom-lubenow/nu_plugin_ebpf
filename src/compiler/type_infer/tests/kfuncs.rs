use super::*;

#[test]
fn test_type_error_unknown_kfunc_signature() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let arg = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: arg,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "unknown_kfunc".to_string(),
        btf_id: None,
        args: vec![arg],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected unknown-kfunc type error");
    assert!(errs.iter().any(|e| e.message.contains("unknown kfunc")));
}

#[test]
fn test_type_error_kfunc_pointer_argument_required() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let scalar = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: scalar,
        src: MirValue::Const(42),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_task_release".to_string(),
        btf_id: None,
        args: vec![scalar],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected pointer-argument kfunc type error");
    assert!(errs.iter().any(|e| e.message.contains("expects pointer")));
}

#[test]
fn test_type_error_kfunc_pointer_argument_requires_kernel_space() {
    let mut func = make_test_function();
    let ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_task_acquire".to_string(),
        btf_id: None,
        args: vec![ptr],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected kernel-pointer kfunc type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_list_push_front_requires_kernel_space() {
    let mut func = make_test_function();
    let head = func.alloc_vreg();
    let node = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let off = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let head_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let node_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: head,
        src: MirValue::StackSlot(head_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: node,
        src: MirValue::StackSlot(node_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_list_push_front_impl".to_string(),
        btf_id: None,
        args: vec![head, node, meta, off],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected list-push-front kernel-pointer kfunc type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_path_d_path_requires_kernel_path_arg() {
    let mut func = make_test_function();
    let path = func.alloc_vreg();
    let buf = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let path_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: path,
        src: MirValue::StackSlot(path_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: buf,
        src: MirValue::StackSlot(buf_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(32),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_path_d_path".to_string(),
        btf_id: None,
        args: vec![path, buf, size],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected path_d_path kernel-pointer kfunc type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_rbtree_first_requires_kernel_space() {
    let mut func = make_test_function();
    let root = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: root,
        src: MirValue::StackSlot(slot),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_rbtree_first".to_string(),
        btf_id: None,
        args: vec![root],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected rbtree_first kernel-pointer kfunc type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_infer_kfunc_cpumask_create_pointer_return() {
    let mut func = make_test_function();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_cpumask_create".to_string(),
        btf_id: None,
        args: vec![],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected cpumask kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_kfunc_obj_new_pointer_return() {
    let mut func = make_test_function();
    let type_id = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::Copy {
        dst: type_id,
        src: MirValue::Const(1),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_obj_new_impl".to_string(),
        btf_id: None,
        args: vec![type_id, meta],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected object-new kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_kfunc_percpu_obj_new_pointer_return() {
    let mut func = make_test_function();
    let type_id = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::Copy {
        dst: type_id,
        src: MirValue::Const(1),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_percpu_obj_new_impl".to_string(),
        btf_id: None,
        args: vec![type_id, meta],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected percpu-object-new kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_kfunc_get_task_exe_file_pointer_return() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_get_task_exe_file".to_string(),
        btf_id: None,
        args: vec![task],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected get_task_exe_file kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_kfunc_iter_task_vma_next_pointer_return() {
    let mut func = make_test_function();
    let it = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: it,
        src: MirValue::StackSlot(slot),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_task_vma_next".to_string(),
        btf_id: None,
        args: vec![it],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected iter_task_vma_next kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_kfunc_scx_cpu_rq_pointer_return() {
    let mut func = make_test_function();
    let cpu = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: cpu,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_cpu_rq".to_string(),
        btf_id: None,
        args: vec![cpu],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected scx_bpf_cpu_rq kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_type_error_kfunc_scx_events_requires_pointer_arg0() {
    let mut func = make_test_function();
    let events = func.alloc_vreg();
    let events_sz = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: events,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::Copy {
        dst: events_sz,
        src: MirValue::Const(8),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_events".to_string(),
        btf_id: None,
        args: vec![events, events_sz],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected scx_bpf_events pointer-argument type error");
    assert!(
        errs.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_events' arg0 expects pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_obj_drop_requires_kernel_space() {
    let mut func = make_test_function();
    let ptr = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_obj_drop_impl".to_string(),
        btf_id: None,
        args: vec![ptr, meta],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected object-drop kernel-pointer kfunc type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_infer_kfunc_rcu_read_lock_unlock_signatures() {
    let mut func = make_test_function();
    let lock_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallKfunc {
        dst: lock_ret,
        kfunc: "bpf_rcu_read_lock".to_string(),
        btf_id: None,
        args: vec![],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: unlock_ret,
        kfunc: "bpf_rcu_read_unlock".to_string(),
        btf_id: None,
        args: vec![],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected rcu read lock/unlock kfunc type inference");
    assert!(matches!(types.get(&lock_ret), Some(MirType::I64)));
    assert!(matches!(types.get(&unlock_ret), Some(MirType::I64)));
}
