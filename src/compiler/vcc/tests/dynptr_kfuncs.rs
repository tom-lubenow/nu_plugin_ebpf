use super::*;
use crate::compiler::test_mir_builders::dynptr_clone_join_reinitialize_mir;

fn stack_dynptr_ty() -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::opaque_named_struct("bpf_dynptr")),
        address_space: AddressSpace::Stack,
    }
}

fn kernel_ptr_ty() -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::Kernel,
    }
}

fn push_const_arg(func: &mut MirFunction, block: BlockId, value: i64) -> VReg {
    let reg = func.alloc_vreg();
    func.block_mut(block).instructions.push(MirInst::Copy {
        dst: reg,
        src: MirValue::Const(value),
    });
    reg
}

fn push_stack_dynptr(func: &mut MirFunction, block: BlockId, initialized: bool) -> VReg {
    let ptr = func.alloc_vreg();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    if initialized {
        func.entry_initialized_dynptr_slots.insert(slot);
    }
    func.block_mut(block).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    ptr
}

fn insert_scalar_types(types: &mut HashMap<VReg, MirType>, regs: &[VReg]) {
    for reg in regs {
        types.insert(*reg, MirType::I64);
    }
}

#[test]
fn test_verify_mir_kfunc_dynptr_common_ops_accept_initialized_stack_slot() {
    let cases: &[(&str, &[i64], MirType)] = &[
        ("bpf_dynptr_adjust", &[0, 4], MirType::I64),
        ("bpf_dynptr_is_null", &[], MirType::I64),
        ("bpf_dynptr_is_rdonly", &[], MirType::I64),
        ("bpf_dynptr_memset", &[0, 0, 4], MirType::I64),
        ("bpf_dynptr_slice", &[0, 0, 4], kernel_ptr_ty()),
        ("bpf_dynptr_slice_rdwr", &[0, 0, 4], kernel_ptr_ty()),
    ];

    for (kfunc, extra_args, ret_ty) in cases {
        let (mut func, entry) = new_mir_function();
        let dptr = push_stack_dynptr(&mut func, entry, true);
        let extra_regs = extra_args
            .iter()
            .map(|value| push_const_arg(&mut func, entry, *value))
            .collect::<Vec<_>>();
        let ret = func.alloc_vreg();
        let mut args = vec![dptr];
        args.extend(extra_regs.iter().copied());
        func.block_mut(entry).instructions.push(MirInst::CallKfunc {
            dst: ret,
            kfunc: (*kfunc).to_string(),
            btf_id: None,
            args,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dptr, stack_dynptr_ty());
        insert_scalar_types(&mut types, &extra_regs);
        types.insert(ret, ret_ty.clone());

        verify_mir(&func, &types)
            .unwrap_or_else(|err| panic!("expected {kfunc} initialized dynptr to pass: {err:?}"));
    }
}

#[test]
fn test_verify_mir_kfunc_dynptr_common_ops_reject_uninitialized_stack_slot() {
    let cases: &[(&str, &[i64])] = &[
        ("bpf_dynptr_adjust", &[0, 4]),
        ("bpf_dynptr_is_null", &[]),
        ("bpf_dynptr_is_rdonly", &[]),
        ("bpf_dynptr_memset", &[0, 0, 4]),
        ("bpf_dynptr_slice", &[0, 0, 4]),
        ("bpf_dynptr_slice_rdwr", &[0, 0, 4]),
    ];

    for (kfunc, extra_args) in cases {
        let (mut func, entry) = new_mir_function();
        let dptr = push_stack_dynptr(&mut func, entry, false);
        let extra_regs = extra_args
            .iter()
            .map(|value| push_const_arg(&mut func, entry, *value))
            .collect::<Vec<_>>();
        let ret = func.alloc_vreg();
        let mut args = vec![dptr];
        args.extend(extra_regs.iter().copied());
        func.block_mut(entry).instructions.push(MirInst::CallKfunc {
            dst: ret,
            kfunc: (*kfunc).to_string(),
            btf_id: None,
            args,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dptr, stack_dynptr_ty());
        insert_scalar_types(&mut types, &extra_regs);
        types.insert(ret, MirType::I64);

        let err = match verify_mir(&func, &types) {
            Ok(()) => panic!("expected {kfunc} uninitialized dynptr rejection"),
            Err(err) => err,
        };
        assert!(
            err.iter().any(|e| e.message.contains(&format!(
                "kfunc '{kfunc}' arg0 requires initialized dynptr stack object"
            ))),
            "unexpected errors for {kfunc}: {:?}",
            err
        );
    }
}

fn make_dynptr_copy_function(
    dst_initialized: bool,
    src_initialized: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let (mut func, entry) = new_mir_function();
    let dst = push_stack_dynptr(&mut func, entry, dst_initialized);
    let dst_off = push_const_arg(&mut func, entry, 0);
    let src = push_stack_dynptr(&mut func, entry, src_initialized);
    let src_off = push_const_arg(&mut func, entry, 0);
    let len = push_const_arg(&mut func, entry, 4);
    let ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_dynptr_copy".to_string(),
        btf_id: None,
        args: vec![dst, dst_off, src, src_off, len],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, stack_dynptr_ty());
    types.insert(src, stack_dynptr_ty());
    insert_scalar_types(&mut types, &[dst_off, src_off, len, ret]);

    (func, types)
}

#[test]
fn test_verify_mir_kfunc_dynptr_copy_accepts_initialized_operands() {
    let (func, types) = make_dynptr_copy_function(true, true);
    verify_mir(&func, &types).expect("expected initialized dynptr copy operands to pass");
}

#[test]
fn test_verify_mir_kfunc_dynptr_copy_rejects_uninitialized_destination() {
    let (func, types) = make_dynptr_copy_function(false, true);
    let err = verify_mir(&func, &types).expect_err("expected uninitialized dynptr copy dst error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_dynptr_copy' arg0 requires initialized dynptr stack object")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_dynptr_copy_rejects_uninitialized_source() {
    let (func, types) = make_dynptr_copy_function(true, false);
    let err = verify_mir(&func, &types).expect_err("expected uninitialized dynptr copy src error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_dynptr_copy' arg2 requires initialized dynptr stack object")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_dynptr_clone_rejects_initialized_destination() {
    let (mut func, entry) = new_mir_function();
    let src = push_stack_dynptr(&mut func, entry, true);
    let dst = push_stack_dynptr(&mut func, entry, true);
    let ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_dynptr_clone".to_string(),
        btf_id: None,
        args: vec![src, dst],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(src, stack_dynptr_ty());
    types.insert(dst, stack_dynptr_ty());
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected initialized clone dst error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "kfunc 'bpf_dynptr_clone' arg1 requires uninitialized dynptr stack object slot"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_dynptr_clone_rejects_destination_initialized_on_one_path() {
    let (func, types) = dynptr_clone_join_reinitialize_mir();
    let err = verify_mir(&func, &types)
        .expect_err("expected partially initialized clone dst error at join");
    assert!(
        err.iter().any(|e| e.message.contains(
            "kfunc 'bpf_dynptr_clone' arg1 requires uninitialized dynptr stack object slot"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[derive(Clone, Copy)]
enum RingbufDynptrReleaseTarget {
    Source,
    Clone,
}

fn make_ringbuf_dynptr_clone_release_function(
    release_target: RingbufDynptrReleaseTarget,
    read_other_after_release: bool,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let (mut func, entry) = new_mir_function();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let clone_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dynptr_ptr = func.alloc_vreg();
    let clone_ptr = func.alloc_vreg();
    let reserve_ret = func.alloc_vreg();
    let clone_ret = func.alloc_vreg();
    let submit_ret = func.alloc_vreg();
    let size_ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: reserve_ret,
            helper: BpfHelper::RingbufReserveDynptr as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
                MirValue::StackSlot(dynptr_slot),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dynptr_ptr,
        src: MirValue::StackSlot(dynptr_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: clone_ptr,
        src: MirValue::StackSlot(clone_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: clone_ret,
        kfunc: "bpf_dynptr_clone".to_string(),
        btf_id: None,
        args: vec![dynptr_ptr, clone_ptr],
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: submit_ret,
            helper: BpfHelper::RingbufSubmitDynptr as u32,
            args: vec![
                MirValue::StackSlot(match release_target {
                    RingbufDynptrReleaseTarget::Source => dynptr_slot,
                    RingbufDynptrReleaseTarget::Clone => clone_slot,
                }),
                MirValue::Const(0),
            ],
        });
    if read_other_after_release {
        func.block_mut(entry).instructions.push(MirInst::CallKfunc {
            dst: size_ret,
            kfunc: "bpf_dynptr_size".to_string(),
            btf_id: None,
            args: vec![match release_target {
                RingbufDynptrReleaseTarget::Source => clone_ptr,
                RingbufDynptrReleaseTarget::Clone => dynptr_ptr,
            }],
        });
    }
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dynptr_ptr, stack_dynptr_ty());
    types.insert(clone_ptr, stack_dynptr_ty());
    insert_scalar_types(&mut types, &[reserve_ret, clone_ret, submit_ret, size_ret]);

    (func, types)
}

#[test]
fn test_verify_mir_kfunc_dynptr_clone_submit_through_clone_is_balanced() {
    let (func, types) =
        make_ringbuf_dynptr_clone_release_function(RingbufDynptrReleaseTarget::Clone, false);
    verify_mir(&func, &types).expect("expected ringbuf dynptr release through clone to pass");
}

#[test]
fn test_verify_mir_kfunc_dynptr_clone_submit_through_clone_invalidates_source() {
    let (func, types) =
        make_ringbuf_dynptr_clone_release_function(RingbufDynptrReleaseTarget::Clone, true);
    let err = verify_mir(&func, &types).expect_err("expected source dynptr invalidation error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_dynptr_clone_submit_source_invalidates_clone() {
    let (func, types) =
        make_ringbuf_dynptr_clone_release_function(RingbufDynptrReleaseTarget::Source, true);
    let err = verify_mir(&func, &types).expect_err("expected clone dynptr invalidation error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object")),
        "unexpected errors: {:?}",
        err
    );
}
