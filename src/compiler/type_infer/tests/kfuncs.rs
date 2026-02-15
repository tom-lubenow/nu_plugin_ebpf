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
fn test_type_error_kfunc_path_d_path_buffer_requires_stack_or_map_space() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let path = func.alloc_vreg();
    let buf = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(42),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: path,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::Copy {
        dst: buf,
        src: MirValue::VReg(path),
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
        .expect_err("expected path_d_path buffer-space type error");
    assert!(
        errs.iter().any(|e| e
            .message
            .contains("kfunc path_d_path buffer expects pointer in [Stack, Map], got Kernel")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_path_d_path_requires_positive_size() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let path = func.alloc_vreg();
    let buf = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(42),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: path,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::Copy {
        dst: buf,
        src: MirValue::StackSlot(buf_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(0),
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
        .expect_err("expected path_d_path size positivity type error");
    assert!(
        errs.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_path_d_path' arg2 must be > 0")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_infer_kfunc_path_d_path_accepts_stack_buffer_rule() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let path = func.alloc_vreg();
    let buf = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let buf_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(42),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: path,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
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
    ti.infer(&func)
        .expect("expected path_d_path stack-buffer rule to type-check");
}

#[test]
fn test_type_error_kfunc_scx_events_buffer_requires_stack_or_map_space() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(64),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_events".to_string(),
        btf_id: None,
        args: vec![task, size],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected scx_bpf_events buffer-space type error");
    assert!(
        errs.iter().any(|e| e
            .message
            .contains("kfunc scx_bpf_events events expects pointer in [Stack, Map], got Kernel")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_scx_events_requires_positive_size() {
    let mut func = make_test_function();
    let events = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let events_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: events,
        src: MirValue::StackSlot(events_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_events".to_string(),
        btf_id: None,
        args: vec![events, size],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected scx_bpf_events size positivity type error");
    assert!(
        errs.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_events' arg1 must be > 0")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_infer_kfunc_scx_events_accepts_stack_buffer_rule() {
    let mut func = make_test_function();
    let events = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let events_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: events,
        src: MirValue::StackSlot(events_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(64),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_events".to_string(),
        btf_id: None,
        args: vec![events, size],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    ti.infer(&func)
        .expect("expected scx_bpf_events stack-buffer rule to type-check");
}

#[test]
fn test_type_error_kfunc_scx_dump_bstr_fmt_requires_stack_or_map_space() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let fmt = func.alloc_vreg();
    let data = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let data_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(9),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: fmt,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::Copy {
        dst: data,
        src: MirValue::StackSlot(data_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(16),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_dump_bstr".to_string(),
        btf_id: None,
        args: vec![fmt, data, size],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected scx_bpf_dump_bstr fmt-space type error");
    assert!(
        errs.iter().any(|e| e
            .message
            .contains("kfunc scx_bpf_dump_bstr fmt expects pointer in [Stack, Map], got Kernel")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_scx_dump_bstr_requires_positive_data_size() {
    let mut func = make_test_function();
    let fmt = func.alloc_vreg();
    let data = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let fmt_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: fmt,
        src: MirValue::StackSlot(fmt_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: data,
        src: MirValue::StackSlot(data_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_dump_bstr".to_string(),
        btf_id: None,
        args: vec![fmt, data, size],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected scx_bpf_dump_bstr positive-size type error");
    assert!(
        errs.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_dump_bstr' arg2 must be > 0")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_infer_kfunc_scx_dump_bstr_accepts_stack_fmt_and_data() {
    let mut func = make_test_function();
    let fmt = func.alloc_vreg();
    let data = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let fmt_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: fmt,
        src: MirValue::StackSlot(fmt_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: data,
        src: MirValue::StackSlot(data_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(16),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_dump_bstr".to_string(),
        btf_id: None,
        args: vec![fmt, data, size],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    ti.infer(&func)
        .expect("expected scx_bpf_dump_bstr stack fmt/data rule to type-check");
}

#[test]
fn test_type_error_kfunc_scx_exit_bstr_requires_positive_data_size() {
    let mut func = make_test_function();
    let code = func.alloc_vreg();
    let fmt = func.alloc_vreg();
    let data = func.alloc_vreg();
    let size = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let fmt_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let data_slot = func.alloc_stack_slot(64, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: code,
        src: MirValue::Const(-1),
    });
    block.instructions.push(MirInst::Copy {
        dst: fmt,
        src: MirValue::StackSlot(fmt_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: data,
        src: MirValue::StackSlot(data_slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: size,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "scx_bpf_exit_bstr".to_string(),
        btf_id: None,
        args: vec![code, fmt, data, size],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected scx_bpf_exit_bstr positive-size type error");
    assert!(
        errs.iter().any(|e| e
            .message
            .contains("kfunc 'scx_bpf_exit_bstr' arg3 must be > 0")),
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
fn test_infer_kfunc_cpumask_populate_signature() {
    let mut func = make_test_function();
    let cpumask = func.alloc_vreg();
    let src = func.alloc_vreg();
    let src_sz = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallKfunc {
        dst: cpumask,
        kfunc: "bpf_cpumask_create".to_string(),
        btf_id: None,
        args: vec![],
    });
    block.instructions.push(MirInst::Copy {
        dst: src,
        src: MirValue::StackSlot(slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: src_sz,
        src: MirValue::Const(8),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_cpumask_populate".to_string(),
        btf_id: None,
        args: vec![cpumask, src, src_sz],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected cpumask_populate kfunc type inference");
    assert!(matches!(types.get(&dst), Some(MirType::I64)));
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
fn test_infer_kfunc_iter_task_next_pointer_return() {
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
        kfunc: "bpf_iter_task_next".to_string(),
        btf_id: None,
        args: vec![it],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected iter_task_next kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_kfunc_iter_scx_dsq_next_pointer_return() {
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
        kfunc: "bpf_iter_scx_dsq_next".to_string(),
        btf_id: None,
        args: vec![it],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected iter_scx_dsq_next kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_kfunc_iter_num_next_pointer_return() {
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
        kfunc: "bpf_iter_num_next".to_string(),
        btf_id: None,
        args: vec![it],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected iter_num_next kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_kfunc_iter_bits_next_pointer_return() {
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
        kfunc: "bpf_iter_bits_next".to_string(),
        btf_id: None,
        args: vec![it],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected iter_bits_next kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_kfunc_iter_css_next_pointer_return() {
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
        kfunc: "bpf_iter_css_next".to_string(),
        btf_id: None,
        args: vec![it],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected iter_css_next kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_kfunc_iter_css_task_next_pointer_return() {
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
        kfunc: "bpf_iter_css_task_next".to_string(),
        btf_id: None,
        args: vec![it],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected iter_css_task_next kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_kfunc_iter_dmabuf_next_pointer_return() {
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
        kfunc: "bpf_iter_dmabuf_next".to_string(),
        btf_id: None,
        args: vec![it],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected iter_dmabuf_next kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_infer_kfunc_iter_kmem_cache_next_pointer_return() {
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
        kfunc: "bpf_iter_kmem_cache_next".to_string(),
        btf_id: None,
        args: vec![it],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected iter_kmem_cache_next kfunc type inference");
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

#[test]
fn test_infer_kfunc_preempt_disable_enable_signatures() {
    let mut func = make_test_function();
    let disable_ret = func.alloc_vreg();
    let enable_ret = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallKfunc {
        dst: disable_ret,
        kfunc: "bpf_preempt_disable".to_string(),
        btf_id: None,
        args: vec![],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: enable_ret,
        kfunc: "bpf_preempt_enable".to_string(),
        btf_id: None,
        args: vec![],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected preempt disable/enable kfunc type inference");
    assert!(matches!(types.get(&disable_ret), Some(MirType::I64)));
    assert!(matches!(types.get(&enable_ret), Some(MirType::I64)));
}

#[test]
fn test_infer_kfunc_local_irq_save_restore_signatures() {
    let mut func = make_test_function();
    let flags = func.alloc_vreg();
    let save_ret = func.alloc_vreg();
    let restore_ret = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::StackSlot(slot),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: save_ret,
        kfunc: "bpf_local_irq_save".to_string(),
        btf_id: None,
        args: vec![flags],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: restore_ret,
        kfunc: "bpf_local_irq_restore".to_string(),
        btf_id: None,
        args: vec![flags],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected local irq save/restore kfunc type inference");
    assert!(matches!(types.get(&save_ret), Some(MirType::I64)));
    assert!(matches!(types.get(&restore_ret), Some(MirType::I64)));
}

#[test]
fn test_type_error_kfunc_local_irq_save_requires_stack_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let save_ret = func.alloc_vreg();
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
        dst: save_ret,
        kfunc: "bpf_local_irq_save".to_string(),
        btf_id: None,
        args: vec![task],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected local_irq_save stack-pointer type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_iter_task_vma_new_requires_stack_iterator_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let addr = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    block.instructions.push(MirInst::Copy {
        dst: addr,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_task_vma_new".to_string(),
        btf_id: None,
        args: vec![task, task, addr],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected iter_task_vma_new stack-iterator type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_iter_task_new_requires_stack_iterator_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    block.instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_task_new".to_string(),
        btf_id: None,
        args: vec![task, task, flags],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected iter_task_new stack-iterator type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_iter_scx_dsq_new_requires_stack_iterator_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let dsq_id = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    block.instructions.push(MirInst::Copy {
        dst: dsq_id,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_scx_dsq_new".to_string(),
        btf_id: None,
        args: vec![task, dsq_id, flags],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected iter_scx_dsq_new stack-iterator type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_iter_num_new_requires_stack_iterator_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let start = func.alloc_vreg();
    let end = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    block.instructions.push(MirInst::Copy {
        dst: start,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::Copy {
        dst: end,
        src: MirValue::Const(8),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_num_new".to_string(),
        btf_id: None,
        args: vec![task, start, end],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected iter_num_new stack-iterator type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_iter_bits_new_requires_stack_iterator_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let words = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    block.instructions.push(MirInst::Copy {
        dst: words,
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
        kfunc: "bpf_iter_bits_new".to_string(),
        btf_id: None,
        args: vec![task, task, words],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected iter_bits_new stack-iterator type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_iter_css_new_requires_stack_iterator_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    block.instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_css_new".to_string(),
        btf_id: None,
        args: vec![task, task, flags],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected iter_css_new stack-iterator type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_iter_css_task_new_requires_stack_iterator_pointer() {
    let mut func = make_test_function();
    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    block.instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_css_task_new".to_string(),
        btf_id: None,
        args: vec![task, task, flags],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected iter_css_task_new stack-iterator type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_iter_css_new_requires_kernel_css_pointer_arg1() {
    let mut func = make_test_function();
    let iter = func.alloc_vreg();
    let css = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: css,
        src: MirValue::VReg(iter),
    });
    block.instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_css_new".to_string(),
        btf_id: None,
        args: vec![iter, css, flags],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected iter_css_new arg1 kernel-pointer type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg1 expects kernel pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_iter_css_task_new_requires_kernel_css_pointer_arg1() {
    let mut func = make_test_function();
    let iter = func.alloc_vreg();
    let css = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    block.instructions.push(MirInst::Copy {
        dst: css,
        src: MirValue::VReg(iter),
    });
    block.instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_iter_css_task_new".to_string(),
        btf_id: None,
        args: vec![iter, css, flags],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected iter_css_task_new arg1 kernel-pointer type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg1 expects kernel pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_iter_dmabuf_new_requires_stack_iterator_pointer() {
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
        kfunc: "bpf_iter_dmabuf_new".to_string(),
        btf_id: None,
        args: vec![task],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected iter_dmabuf_new stack-iterator type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_iter_kmem_cache_new_requires_stack_iterator_pointer() {
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
        kfunc: "bpf_iter_kmem_cache_new".to_string(),
        btf_id: None,
        args: vec![task],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected iter_kmem_cache_new stack-iterator type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects stack pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_infer_kfunc_res_spin_lock_signatures() {
    let mut func = make_test_function();
    let lock = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();
    let lock_irqsave_ret = func.alloc_vreg();
    let unlock_irqrestore_ret = func.alloc_vreg();
    let stack_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallKfunc {
        dst: lock,
        kfunc: "bpf_cpumask_create".to_string(),
        btf_id: None,
        args: vec![],
    });
    block.instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::StackSlot(stack_slot),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: lock_ret,
        kfunc: "bpf_res_spin_lock".to_string(),
        btf_id: None,
        args: vec![lock],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: unlock_ret,
        kfunc: "bpf_res_spin_unlock".to_string(),
        btf_id: None,
        args: vec![lock],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: lock_irqsave_ret,
        kfunc: "bpf_res_spin_lock_irqsave".to_string(),
        btf_id: None,
        args: vec![lock, flags],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: unlock_irqrestore_ret,
        kfunc: "bpf_res_spin_unlock_irqrestore".to_string(),
        btf_id: None,
        args: vec![lock, flags],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected res_spin lock/unlock kfunc type inference");
    assert!(matches!(types.get(&lock_ret), Some(MirType::I64)));
    assert!(matches!(types.get(&unlock_ret), Some(MirType::I64)));
    assert!(matches!(types.get(&lock_irqsave_ret), Some(MirType::I64)));
    assert!(matches!(
        types.get(&unlock_irqrestore_ret),
        Some(MirType::I64)
    ));
}

#[test]
fn test_type_error_kfunc_res_spin_lock_irqsave_requires_stack_flags() {
    let mut func = make_test_function();
    let lock = func.alloc_vreg();
    let lock_irqsave_ret = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::CallKfunc {
        dst: lock,
        kfunc: "bpf_cpumask_create".to_string(),
        btf_id: None,
        args: vec![],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: lock_irqsave_ret,
        kfunc: "bpf_res_spin_lock_irqsave".to_string(),
        btf_id: None,
        args: vec![lock, lock],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected res_spin_lock_irqsave stack-pointer flags type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg1 expects stack pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_type_error_kfunc_map_sum_elem_count_requires_kernel_space() {
    let mut func = make_test_function();
    let map_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: map_ptr,
        src: MirValue::StackSlot(slot),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_map_sum_elem_count".to_string(),
        btf_id: None,
        args: vec![map_ptr],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected map_sum_elem_count kernel-pointer kfunc type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        errs
    );
}

#[test]
fn test_infer_kfunc_list_front_pointer_return() {
    let mut func = make_test_function();
    let type_id = func.alloc_vreg();
    let meta = func.alloc_vreg();
    let list_head = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: type_id,
        src: MirValue::Const(1),
    });
    block.instructions.push(MirInst::Copy {
        dst: meta,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst: list_head,
        kfunc: "bpf_obj_new_impl".to_string(),
        btf_id: None,
        args: vec![type_id, meta],
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_list_front".to_string(),
        btf_id: None,
        args: vec![list_head],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let types = ti
        .infer(&func)
        .expect("expected list_front kfunc type inference");
    match types.get(&dst) {
        Some(MirType::Ptr { address_space, .. }) => {
            assert_eq!(*address_space, AddressSpace::Kernel);
        }
        other => panic!("expected kernel pointer return, got {:?}", other),
    }
}

#[test]
fn test_type_error_kfunc_rbtree_left_requires_kernel_space() {
    let mut func = make_test_function();
    let node = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: node,
        src: MirValue::StackSlot(slot),
    });
    block.instructions.push(MirInst::CallKfunc {
        dst,
        kfunc: "bpf_rbtree_left".to_string(),
        btf_id: None,
        args: vec![node],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errs = ti
        .infer(&func)
        .expect_err("expected rbtree_left kernel-pointer kfunc type error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("arg0 expects kernel pointer")),
        "unexpected errors: {:?}",
        errs
    );
}
