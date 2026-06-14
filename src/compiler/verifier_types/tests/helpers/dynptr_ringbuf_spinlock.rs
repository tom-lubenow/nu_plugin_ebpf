fn bpf_spin_lock_types(lock: VReg, extra: &[(VReg, MirType)]) -> HashMap<VReg, MirType> {
    let mut types = HashMap::new();
    types.insert(
        lock,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_spin_lock_struct()),
            address_space: AddressSpace::Map,
        },
    );
    for (vreg, ty) in extra {
        types.insert(*vreg, ty.clone());
    }
    types
}

fn bpf_spin_lock_guarded_function(
    body: impl FnOnce(&mut MirFunction, BlockId, VReg),
) -> (MirFunction, VReg) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let locked = func.alloc_block();
    let unlocked = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let lock = func.alloc_vreg();
    let cond = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(lock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: locked,
        if_false: unlocked,
    };
    func.block_mut(unlocked).terminator = MirInst::Return { val: None };
    body(&mut func, locked, lock);
    (func, lock)
}

fn dynptr_map_value_ty() -> MirType {
    MirType::Array {
        elem: Box::new(MirType::U8),
        len: 16,
    }
}

fn dynptr_helper_types(
    data: VReg,
    len: Option<VReg>,
    extra: &[(VReg, MirType)],
) -> HashMap<VReg, MirType> {
    let mut types = HashMap::new();
    types.insert(
        data,
        MirType::Ptr {
            pointee: Box::new(dynptr_map_value_ty()),
            address_space: AddressSpace::Map,
        },
    );
    if let Some(len) = len {
        types.insert(len, MirType::I64);
    }
    for (vreg, ty) in extra {
        types.insert(*vreg, ty.clone());
    }
    types
}

fn dynptr_guarded_function(
    param_count: usize,
    body: impl FnOnce(&mut MirFunction, BlockId, VReg, Option<VReg>),
) -> (MirFunction, VReg, Option<VReg>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let guarded = func.alloc_block();
    let null_data = func.alloc_block();
    func.entry = entry;
    func.param_count = param_count;

    let data = func.alloc_vreg();
    let len = (param_count > 1).then(|| func.alloc_vreg());
    let cond = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(data),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: guarded,
        if_false: null_data,
    };
    func.block_mut(null_data).terminator = MirInst::Return { val: None };
    body(&mut func, guarded, data, len);
    (func, data, len)
}

#[test]
fn test_verify_mir_dynptr_helper_lifecycle_balanced() {
    let mut from_ret = VReg(0);
    let mut read_ret = VReg(0);
    let mut write_ret = VReg(0);
    let mut data_ret = VReg(0);
    let (func, data, len) = dynptr_guarded_function(1, |func, block, data, _| {
        let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let read_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let write_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        from_ret = func.alloc_vreg();
        read_ret = func.alloc_vreg();
        write_ret = func.alloc_vreg();
        data_ret = func.alloc_vreg();
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: from_ret,
                helper: BpfHelper::DynptrFromMem as u32,
                args: vec![
                    MirValue::VReg(data),
                    MirValue::Const(8),
                    MirValue::Const(0),
                    MirValue::StackSlot(dynptr_slot),
                ],
            });
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: read_ret,
                helper: BpfHelper::DynptrRead as u32,
                args: vec![
                    MirValue::StackSlot(read_slot),
                    MirValue::Const(4),
                    MirValue::StackSlot(dynptr_slot),
                    MirValue::Const(0),
                    MirValue::Const(0),
                ],
            });
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: write_ret,
                helper: BpfHelper::DynptrWrite as u32,
                args: vec![
                    MirValue::StackSlot(dynptr_slot),
                    MirValue::Const(0),
                    MirValue::StackSlot(write_slot),
                    MirValue::Const(4),
                    MirValue::Const(0),
                ],
            });
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: data_ret,
                helper: BpfHelper::DynptrData as u32,
                args: vec![
                    MirValue::StackSlot(dynptr_slot),
                    MirValue::Const(0),
                    MirValue::Const(4),
                ],
            });
        func.block_mut(block).terminator = MirInst::Return { val: None };
    });
    let types = dynptr_helper_types(
        data,
        len,
        &[
            (from_ret, MirType::I64),
            (read_ret, MirType::I64),
            (write_ret, MirType::I64),
            (
                data_ret,
                MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Map,
                },
            ),
        ],
    );

    verify_mir(&func, &types).expect("expected dynptr helper lifecycle to verify");
}

#[test]
fn test_verify_mir_dynptr_helpers_accept_zero_size_null_data() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let from_ret = func.alloc_vreg();
    let read_ret = func.alloc_vreg();
    let write_ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: from_ret,
            helper: BpfHelper::DynptrFromMem as u32,
            args: vec![
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::StackSlot(dynptr_slot),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: read_ret,
            helper: BpfHelper::DynptrRead as u32,
            args: vec![
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::StackSlot(dynptr_slot),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: write_ret,
            helper: BpfHelper::DynptrWrite as u32,
            args: vec![
                MirValue::StackSlot(dynptr_slot),
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = HashMap::from([
        (from_ret, MirType::I64),
        (read_ret, MirType::I64),
        (write_ret, MirType::I64),
    ]);

    verify_mir(&func, &types).expect("expected dynptr helpers with null zero-size data to verify");
}

#[test]
fn test_verify_mir_dynptr_helpers_reject_negative_sizes() {
    for (helper, size_arg) in [
        (BpfHelper::DynptrFromMem, 1usize),
        (BpfHelper::DynptrRead, 1usize),
        (BpfHelper::DynptrWrite, 3usize),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        if helper != BpfHelper::DynptrFromMem {
            func.entry_initialized_dynptr_slots.insert(dynptr_slot);
        }
        let dst = func.alloc_vreg();
        let args = match helper {
            BpfHelper::DynptrFromMem => vec![
                MirValue::StackSlot(data_slot),
                MirValue::Const(-1),
                MirValue::Const(0),
                MirValue::StackSlot(dynptr_slot),
            ],
            BpfHelper::DynptrRead => vec![
                MirValue::StackSlot(data_slot),
                MirValue::Const(-1),
                MirValue::StackSlot(dynptr_slot),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
            BpfHelper::DynptrWrite => vec![
                MirValue::StackSlot(dynptr_slot),
                MirValue::Const(0),
                MirValue::StackSlot(data_slot),
                MirValue::Const(-1),
                MirValue::Const(0),
            ],
            _ => unreachable!(),
        };

        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: helper as u32,
                args,
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let types = HashMap::from([(dst, MirType::I64)]);
        let errs =
            verify_mir(&func, &types).expect_err("expected dynptr negative size to be rejected");
        let expected = format!("helper {} arg{} must be >= 0", helper as u32, size_arg);
        assert!(
            errs.iter().any(|err| err.message.contains(&expected)),
            "unexpected errors for {helper:?}: {:?}",
            errs
        );
    }
}

#[test]
fn test_verify_mir_dynptr_from_mem_rejects_dynamic_flags_from_helper_return() {
    let mut flags = VReg(0);
    let mut from_ret = VReg(0);
    let (func, data, len) = dynptr_guarded_function(1, |func, block, data, _| {
        let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        flags = func.alloc_vreg();
        from_ret = func.alloc_vreg();
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: flags,
                helper: BpfHelper::GetPrandomU32 as u32,
                args: vec![],
            });
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: from_ret,
                helper: BpfHelper::DynptrFromMem as u32,
                args: vec![
                    MirValue::VReg(data),
                    MirValue::Const(8),
                    MirValue::VReg(flags),
                    MirValue::StackSlot(dynptr_slot),
                ],
            });
        func.block_mut(block).terminator = MirInst::Return { val: None };
    });
    let types = dynptr_helper_types(
        data,
        len,
        &[(flags, MirType::U32), (from_ret, MirType::I64)],
    );
    let err = verify_mir(&func, &types)
        .expect_err("expected dynptr_from_mem dynamic flags to be rejected");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_dynptr_from_mem' requires arg2 flags to be 0")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_dynptr_helper_rejects_use_before_init() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let dst_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let read_ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: read_ret,
            helper: BpfHelper::DynptrRead as u32,
            args: vec![
                MirValue::StackSlot(dst_slot),
                MirValue::Const(4),
                MirValue::StackSlot(dynptr_slot),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };
    let mut types = HashMap::new();
    types.insert(read_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected uninitialized dynptr error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires initialized dynptr stack object")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_dynptr_helper_rejects_reinit() {
    let mut first_ret = VReg(0);
    let mut second_ret = VReg(0);
    let (func, data, len) = dynptr_guarded_function(1, |func, block, data, _| {
        let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        first_ret = func.alloc_vreg();
        second_ret = func.alloc_vreg();
        let args = vec![
            MirValue::VReg(data),
            MirValue::Const(8),
            MirValue::Const(0),
            MirValue::StackSlot(dynptr_slot),
        ];
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: first_ret,
                helper: BpfHelper::DynptrFromMem as u32,
                args: args.clone(),
            });
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: second_ret,
                helper: BpfHelper::DynptrFromMem as u32,
                args,
            });
        func.block_mut(block).terminator = MirInst::Return { val: None };
    });
    let types = dynptr_helper_types(
        data,
        len,
        &[(first_ret, MirType::I64), (second_ret, MirType::I64)],
    );

    let err = verify_mir(&func, &types).expect_err("expected dynptr reinit error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires uninitialized dynptr stack object slot")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_dynptr_from_mem_rejects_destination_initialized_on_one_path() {
    let (func, types) = dynptr_from_mem_join_reinitialize_mir();
    let err =
        verify_mir(&func, &types).expect_err("expected dynptr_from_mem reinitialize error at join");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_dynptr_from_mem' arg3 requires uninitialized dynptr stack object slot"
        )),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_dynptr_data_requires_constant_len() {
    let mut from_ret = VReg(0);
    let mut data_ret = VReg(0);
    let (func, data, len) = dynptr_guarded_function(2, |func, block, data, len| {
        let len = len.expect("expected second param");
        let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        from_ret = func.alloc_vreg();
        data_ret = func.alloc_vreg();
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: from_ret,
                helper: BpfHelper::DynptrFromMem as u32,
                args: vec![
                    MirValue::VReg(data),
                    MirValue::Const(8),
                    MirValue::Const(0),
                    MirValue::StackSlot(dynptr_slot),
                ],
            });
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: data_ret,
                helper: BpfHelper::DynptrData as u32,
                args: vec![
                    MirValue::StackSlot(dynptr_slot),
                    MirValue::Const(0),
                    MirValue::VReg(len),
                ],
            });
        func.block_mut(block).terminator = MirInst::Return { val: None };
    });
    let types = dynptr_helper_types(
        data,
        len,
        &[
            (from_ret, MirType::I64),
            (
                data_ret,
                MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Map,
                },
            ),
        ],
    );

    let err = verify_mir(&func, &types).expect_err("expected dynptr_data const len error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg2 must be known constant")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_ringbuf_dynptr_reserve_release_balanced() {
    for release_helper in [
        BpfHelper::RingbufSubmitDynptr,
        BpfHelper::RingbufDiscardDynptr,
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let reserve_ret = func.alloc_vreg();
        let data_ret = func.alloc_vreg();
        let release_ret = func.alloc_vreg();

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
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: data_ret,
                helper: BpfHelper::DynptrData as u32,
                args: vec![
                    MirValue::StackSlot(dynptr_slot),
                    MirValue::Const(0),
                    MirValue::Const(4),
                ],
            });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: release_ret,
                helper: release_helper as u32,
                args: vec![MirValue::StackSlot(dynptr_slot), MirValue::Const(0)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(reserve_ret, MirType::I64);
        types.insert(
            data_ret,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Map,
            },
        );
        types.insert(release_ret, MirType::I64);

        verify_mir(&func, &types)
            .unwrap_or_else(|err| panic!("expected {release_helper:?} lifecycle: {err:?}"));
    }
}

#[test]
fn test_verify_mir_ringbuf_dynptr_subfn_reserve_submit_balanced() {
    let mut reserve = MirFunction::new();
    let reserve_entry = reserve.alloc_block();
    reserve.entry = reserve_entry;
    reserve.param_count = 1;
    reserve.vreg_count = 1;
    let reserve_param_slot = reserve.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let reserve_map_slot = reserve.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    reserve.param_stack_slots.insert(0, reserve_param_slot);
    let reserve_ret = reserve.alloc_vreg();
    reserve
        .block_mut(reserve_entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: reserve_ret,
            helper: BpfHelper::RingbufReserveDynptr as u32,
            args: vec![
                MirValue::StackSlot(reserve_map_slot),
                MirValue::Const(8),
                MirValue::Const(0),
                MirValue::VReg(VReg(0)),
            ],
        });
    reserve.block_mut(reserve_entry).terminator = MirInst::Return { val: None };

    let mut submit = MirFunction::new();
    let submit_entry = submit.alloc_block();
    submit.entry = submit_entry;
    submit.param_count = 1;
    submit.vreg_count = 1;
    let submit_param_slot = submit.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    submit.param_stack_slots.insert(0, submit_param_slot);
    let submit_ret = submit.alloc_vreg();
    submit
        .block_mut(submit_entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: submit_ret,
            helper: BpfHelper::RingbufSubmitDynptr as u32,
            args: vec![MirValue::VReg(VReg(0)), MirValue::Const(0)],
        });
    submit.block_mut(submit_entry).terminator = MirInst::Return { val: None };

    let summaries = infer_subfunction_summaries(&[reserve.clone(), submit.clone()]);
    let reserve_summary = summaries
        .get(&SubfunctionId(0))
        .cloned()
        .expect("expected reserve summary");
    let submit_summary = summaries
        .get(&SubfunctionId(1))
        .cloned()
        .expect("expected submit summary");
    assert_eq!(reserve_summary.ringbuf_dynptr_delta_arg(0), 1);
    assert!(submit_summary.releases_ringbuf_dynptr_arg(0));

    let dynptr_ty = MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::Stack,
    };
    let mut reserve_types = HashMap::new();
    reserve_types.insert(VReg(0), dynptr_ty.clone());
    reserve_types.insert(reserve_ret, MirType::I64);
    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &reserve,
        &reserve_types,
        &summaries,
        Some(reserve_summary),
        None,
        None,
    )
    .expect("expected reserve wrapper to verify");
    let mut submit_types = HashMap::new();
    submit_types.insert(VReg(0), dynptr_ty.clone());
    submit_types.insert(submit_ret, MirType::I64);
    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &submit,
        &submit_types,
        &summaries,
        Some(submit_summary),
        None,
        None,
    )
    .expect("expected submit wrapper to verify");

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let dynptr = func.alloc_vreg();
    let call_reserve_ret = func.alloc_vreg();
    let call_submit_ret = func.alloc_vreg();
    let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: dynptr,
        src: MirValue::StackSlot(dynptr_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst: call_reserve_ret,
        subfn: SubfunctionId(0),
        args: vec![dynptr],
    });
    func.block_mut(entry).instructions.push(MirInst::CallSubfn {
        dst: call_submit_ret,
        subfn: SubfunctionId(1),
        args: vec![dynptr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dynptr, dynptr_ty);
    types.insert(call_reserve_ret, MirType::I64);
    types.insert(call_submit_ret, MirType::I64);
    verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect("expected subfunction reserve/submit wrappers to balance");
}

#[test]
fn test_verify_mir_ringbuf_dynptr_leak_is_rejected() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let reserve_ret = func.alloc_vreg();

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
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(reserve_ret, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected unreleased ringbuf dynptr error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased ringbuf dynptr reservation")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_ringbuf_dynptr_conditional_release_leak_is_rejected() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let release = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let reserve_ret = func.alloc_vreg();
    let submit_ret = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

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
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: release,
        if_false: done,
    };

    func.block_mut(release)
        .instructions
        .push(MirInst::CallHelper {
            dst: submit_ret,
            helper: BpfHelper::RingbufSubmitDynptr as u32,
            args: vec![MirValue::StackSlot(dynptr_slot), MirValue::Const(0)],
        });
    func.block_mut(release).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(cond, MirType::Bool);
    types.insert(reserve_ret, MirType::I64);
    types.insert(submit_ret, MirType::I64);
    let err = verify_mir(&func, &types)
        .expect_err("expected conditional unreleased ringbuf dynptr error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased ringbuf dynptr reservation")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_ringbuf_dynptr_submit_rejected_after_mixed_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let reserve = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let reserve_ret = func.alloc_vreg();
    let submit_ret = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: reserve,
        if_false: join,
    };

    func.block_mut(reserve)
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
    func.block_mut(reserve).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::CallHelper {
        dst: submit_ret,
        helper: BpfHelper::RingbufSubmitDynptr as u32,
        args: vec![MirValue::StackSlot(dynptr_slot), MirValue::Const(0)],
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(cond, MirType::Bool);
    types.insert(reserve_ret, MirType::I64);
    types.insert(submit_ret, MirType::I64);
    let err =
        verify_mir(&func, &types).expect_err("expected mixed-path ringbuf dynptr submit error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires initialized dynptr stack object")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_ringbuf_dynptr_reserve_rejected_after_mixed_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let reserve = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let reserve_ret = func.alloc_vreg();
    let reinit_ret = func.alloc_vreg();
    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: reserve,
        if_false: join,
    };

    func.block_mut(reserve)
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
    func.block_mut(reserve).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::CallHelper {
        dst: reinit_ret,
        helper: BpfHelper::RingbufReserveDynptr as u32,
        args: vec![
            MirValue::StackSlot(map_slot),
            MirValue::Const(8),
            MirValue::Const(0),
            MirValue::StackSlot(dynptr_slot),
        ],
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(cond, MirType::Bool);
    types.insert(reserve_ret, MirType::I64);
    types.insert(reinit_ret, MirType::I64);
    let err =
        verify_mir(&func, &types).expect_err("expected mixed-path ringbuf dynptr reinit error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("requires uninitialized dynptr stack object slot")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_ringbuf_dynptr_release_rejects_non_ringbuf_dynptr() {
    for release_helper in [
        BpfHelper::RingbufSubmitDynptr,
        BpfHelper::RingbufDiscardDynptr,
    ] {
        let mut from_ret = VReg(0);
        let mut release_ret = VReg(0);
        let (func, data, len) = dynptr_guarded_function(1, |func, block, data, _| {
            let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
            from_ret = func.alloc_vreg();
            release_ret = func.alloc_vreg();
            func.block_mut(block)
                .instructions
                .push(MirInst::CallHelper {
                    dst: from_ret,
                    helper: BpfHelper::DynptrFromMem as u32,
                    args: vec![
                        MirValue::VReg(data),
                        MirValue::Const(8),
                        MirValue::Const(0),
                        MirValue::StackSlot(dynptr_slot),
                    ],
                });
            func.block_mut(block)
                .instructions
                .push(MirInst::CallHelper {
                    dst: release_ret,
                    helper: release_helper as u32,
                    args: vec![MirValue::StackSlot(dynptr_slot), MirValue::Const(0)],
                });
            func.block_mut(block).terminator = MirInst::Return { val: None };
        });
        let types = dynptr_helper_types(
            data,
            len,
            &[(from_ret, MirType::I64), (release_ret, MirType::I64)],
        );

        let err = verify_mir(&func, &types).expect_err("expected non-ringbuf dynptr release error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("requires live ringbuf dynptr reservation")),
            "unexpected errors for {release_helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_ringbuf_dynptr_release_rejects_double_release() {
    for release_helper in [
        BpfHelper::RingbufSubmitDynptr,
        BpfHelper::RingbufDiscardDynptr,
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let reserve_ret = func.alloc_vreg();
        let release_ret0 = func.alloc_vreg();
        let release_ret1 = func.alloc_vreg();

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
        for dst in [release_ret0, release_ret1] {
            func.block_mut(entry)
                .instructions
                .push(MirInst::CallHelper {
                    dst,
                    helper: release_helper as u32,
                    args: vec![MirValue::StackSlot(dynptr_slot), MirValue::Const(0)],
                });
        }
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(reserve_ret, MirType::I64);
        types.insert(release_ret0, MirType::I64);
        types.insert(release_ret1, MirType::I64);
        let err = verify_mir(&func, &types).expect_err("expected double ringbuf dynptr release");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("ringbuf dynptr reservation already released")),
            "unexpected errors for {release_helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_verify_mir_ringbuf_dynptr_clone_is_invalidated_by_submit() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
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
            args: vec![MirValue::StackSlot(dynptr_slot), MirValue::Const(0)],
        });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: size_ret,
        kfunc: "bpf_dynptr_size".to_string(),
        btf_id: None,
        args: vec![clone_ptr],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dynptr_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::opaque_named_struct("bpf_dynptr")),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        clone_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::opaque_named_struct("bpf_dynptr")),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(reserve_ret, MirType::I64);
    types.insert(clone_ret, MirType::I64);
    types.insert(submit_ret, MirType::I64);
    types.insert(size_ret, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected post-submit clone use error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_dynptr_size' arg0 requires initialized dynptr stack object")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_bpf_spin_lock_unlock_balanced() {
    let mut lock_ret = VReg(0);
    let mut unlock_ret = VReg(0);
    let (func, lock) = bpf_spin_lock_guarded_function(|func, block, lock| {
        lock_ret = func.alloc_vreg();
        unlock_ret = func.alloc_vreg();
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: lock_ret,
                helper: BpfHelper::SpinLock as u32,
                args: vec![MirValue::VReg(lock)],
            });
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: unlock_ret,
                helper: BpfHelper::SpinUnlock as u32,
                args: vec![MirValue::VReg(lock)],
            });
        func.block_mut(block).terminator = MirInst::Return { val: None };
    });
    let types = bpf_spin_lock_types(
        lock,
        &[(lock_ret, MirType::I64), (unlock_ret, MirType::I64)],
    );

    verify_mir(&func, &types).expect("expected balanced bpf spin lock/unlock to verify");
}

#[test]
fn test_verify_mir_bpf_spin_unlock_requires_matching_lock() {
    let mut unlock_ret = VReg(0);
    let (func, lock) = bpf_spin_lock_guarded_function(|func, block, lock| {
        unlock_ret = func.alloc_vreg();
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: unlock_ret,
                helper: BpfHelper::SpinUnlock as u32,
                args: vec![MirValue::VReg(lock)],
            });
        func.block_mut(block).terminator = MirInst::Return { val: None };
    });
    let types = bpf_spin_lock_types(lock, &[(unlock_ret, MirType::I64)]);

    let err = verify_mir(&func, &types).expect_err("expected unmatched bpf_spin_unlock error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_spin_lock")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_bpf_spin_unlock_rejects_different_lock() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let first_checked = func.alloc_block();
    let second_checked = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let first_lock = func.alloc_vreg();
    let second_lock = func.alloc_vreg();
    let first_non_null = func.alloc_vreg();
    let second_non_null = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: first_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(first_lock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: first_non_null,
        if_true: first_checked,
        if_false: done,
    };

    func.block_mut(first_checked)
        .instructions
        .push(MirInst::BinOp {
            dst: second_non_null,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(second_lock),
            rhs: MirValue::Const(0),
        });
    func.block_mut(first_checked).terminator = MirInst::Branch {
        cond: second_non_null,
        if_true: second_checked,
        if_false: done,
    };

    func.block_mut(second_checked)
        .instructions
        .push(MirInst::CallHelper {
            dst: lock_ret,
            helper: BpfHelper::SpinLock as u32,
            args: vec![MirValue::VReg(first_lock)],
        });
    func.block_mut(second_checked)
        .instructions
        .push(MirInst::CallHelper {
            dst: unlock_ret,
            helper: BpfHelper::SpinUnlock as u32,
            args: vec![MirValue::VReg(second_lock)],
        });
    func.block_mut(second_checked).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = bpf_spin_lock_types(
        first_lock,
        &[(lock_ret, MirType::I64), (unlock_ret, MirType::I64)],
    );
    types.insert(
        second_lock,
        MirType::Ptr {
            pointee: Box::new(MirType::bpf_spin_lock_struct()),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(first_non_null, MirType::Bool);
    types.insert(second_non_null, MirType::Bool);

    let err = verify_mir(&func, &types).expect_err("expected different bpf_spin_unlock error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_spin_lock")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_bpf_spin_lock_must_be_released_at_exit() {
    let mut lock_ret = VReg(0);
    let (func, lock) = bpf_spin_lock_guarded_function(|func, block, lock| {
        lock_ret = func.alloc_vreg();
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: lock_ret,
                helper: BpfHelper::SpinLock as u32,
                args: vec![MirValue::VReg(lock)],
            });
        func.block_mut(block).terminator = MirInst::Return { val: None };
    });
    let types = bpf_spin_lock_types(lock, &[(lock_ret, MirType::I64)]);

    let err = verify_mir(&func, &types).expect_err("expected unreleased bpf spin lock error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased bpf spin lock")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_bpf_spin_unlock_rejected_after_mixed_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let acquire = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let selector = func.alloc_vreg();
    let lock = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let unlock_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: acquire,
        if_false: join,
    };

    func.block_mut(acquire)
        .instructions
        .push(MirInst::CallHelper {
            dst: lock_ret,
            helper: BpfHelper::SpinLock as u32,
            args: vec![MirValue::VReg(lock)],
        });
    func.block_mut(acquire).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::CallHelper {
        dst: unlock_ret,
        helper: BpfHelper::SpinUnlock as u32,
        args: vec![MirValue::VReg(lock)],
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let types = bpf_spin_lock_types(
        lock,
        &[
            (selector, MirType::I64),
            (cond, MirType::Bool),
            (lock_ret, MirType::I64),
            (unlock_ret, MirType::I64),
        ],
    );

    let err = verify_mir(&func, &types).expect_err("expected mixed-path bpf_spin_unlock error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_spin_lock")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_bpf_spin_lock_rejected_after_mixed_join() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let acquire = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let selector = func.alloc_vreg();
    let lock = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let lock_ret = func.alloc_vreg();
    let relock_ret = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: acquire,
        if_false: join,
    };

    func.block_mut(acquire)
        .instructions
        .push(MirInst::CallHelper {
            dst: lock_ret,
            helper: BpfHelper::SpinLock as u32,
            args: vec![MirValue::VReg(lock)],
        });
    func.block_mut(acquire).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::CallHelper {
        dst: relock_ret,
        helper: BpfHelper::SpinLock as u32,
        args: vec![MirValue::VReg(lock)],
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let types = bpf_spin_lock_types(
        lock,
        &[
            (selector, MirType::I64),
            (cond, MirType::Bool),
            (lock_ret, MirType::I64),
            (relock_ret, MirType::I64),
        ],
    );

    let err = verify_mir(&func, &types).expect_err("expected mixed-path bpf_spin_lock error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("cannot acquire a second bpf_spin_lock")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_bpf_spin_lock_rejects_second_lock() {
    let mut lock_ret = VReg(0);
    let mut second_lock_ret = VReg(0);
    let mut unlock_ret = VReg(0);
    let (func, lock) = bpf_spin_lock_guarded_function(|func, block, lock| {
        lock_ret = func.alloc_vreg();
        second_lock_ret = func.alloc_vreg();
        unlock_ret = func.alloc_vreg();
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: lock_ret,
                helper: BpfHelper::SpinLock as u32,
                args: vec![MirValue::VReg(lock)],
            });
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: second_lock_ret,
                helper: BpfHelper::SpinLock as u32,
                args: vec![MirValue::VReg(lock)],
            });
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: unlock_ret,
                helper: BpfHelper::SpinUnlock as u32,
                args: vec![MirValue::VReg(lock)],
            });
        func.block_mut(block).terminator = MirInst::Return { val: None };
    });
    let types = bpf_spin_lock_types(
        lock,
        &[
            (lock_ret, MirType::I64),
            (second_lock_ret, MirType::I64),
            (unlock_ret, MirType::I64),
        ],
    );

    let err = verify_mir(&func, &types).expect_err("expected second bpf_spin_lock error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("cannot acquire a second bpf_spin_lock")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_bpf_spin_lock_rejects_helper_call_while_held() {
    let mut lock_ret = VReg(0);
    let mut helper_ret = VReg(0);
    let mut unlock_ret = VReg(0);
    let (func, lock) = bpf_spin_lock_guarded_function(|func, block, lock| {
        lock_ret = func.alloc_vreg();
        helper_ret = func.alloc_vreg();
        unlock_ret = func.alloc_vreg();
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: lock_ret,
                helper: BpfHelper::SpinLock as u32,
                args: vec![MirValue::VReg(lock)],
            });
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: helper_ret,
                helper: BpfHelper::KtimeGetNs as u32,
                args: vec![],
            });
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: unlock_ret,
                helper: BpfHelper::SpinUnlock as u32,
                args: vec![MirValue::VReg(lock)],
            });
        func.block_mut(block).terminator = MirInst::Return { val: None };
    });
    let types = bpf_spin_lock_types(
        lock,
        &[
            (lock_ret, MirType::I64),
            (helper_ret, MirType::I64),
            (unlock_ret, MirType::I64),
        ],
    );

    let err = verify_mir(&func, &types).expect_err("expected helper-in-lock error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("cannot be called while bpf_spin_lock is held")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_bpf_spin_lock_rejects_kfunc_and_subfunction_calls_while_held() {
    let mut lock_ret = VReg(0);
    let mut kfunc_ret = VReg(0);
    let mut subfn_ret = VReg(0);
    let mut unlock_ret = VReg(0);
    let (func, lock) = bpf_spin_lock_guarded_function(|func, block, lock| {
        lock_ret = func.alloc_vreg();
        kfunc_ret = func.alloc_vreg();
        subfn_ret = func.alloc_vreg();
        unlock_ret = func.alloc_vreg();
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: lock_ret,
                helper: BpfHelper::SpinLock as u32,
                args: vec![MirValue::VReg(lock)],
            });
        func.block_mut(block).instructions.push(MirInst::CallKfunc {
            dst: kfunc_ret,
            kfunc: "bpf_preempt_disable".to_string(),
            btf_id: None,
            args: vec![],
        });
        func.block_mut(block).instructions.push(MirInst::CallKfunc {
            dst: kfunc_ret,
            kfunc: "bpf_preempt_enable".to_string(),
            btf_id: None,
            args: vec![],
        });
        func.block_mut(block).instructions.push(MirInst::CallSubfn {
            dst: subfn_ret,
            subfn: crate::compiler::mir::SubfunctionId(0),
            args: vec![],
        });
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: unlock_ret,
                helper: BpfHelper::SpinUnlock as u32,
                args: vec![MirValue::VReg(lock)],
            });
        func.block_mut(block).terminator = MirInst::Return { val: None };
    });
    let types = bpf_spin_lock_types(
        lock,
        &[
            (lock_ret, MirType::I64),
            (kfunc_ret, MirType::I64),
            (subfn_ret, MirType::I64),
            (unlock_ret, MirType::I64),
        ],
    );

    let err = verify_mir(&func, &types).expect_err("expected kfunc/subfunction-in-lock errors");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_preempt_disable' cannot be called")),
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("subfunction 'subfn0' cannot be called")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_bpf_spin_lock_allows_iter_num_kfuncs_while_held() {
    let mut iter = VReg(0);
    let mut start = VReg(0);
    let mut end = VReg(0);
    let mut lock_ret = VReg(0);
    let mut new_ret = VReg(0);
    let mut next_ret = VReg(0);
    let mut destroy_ret = VReg(0);
    let mut unlock_ret = VReg(0);
    let (func, lock) = bpf_spin_lock_guarded_function(|func, block, lock| {
        iter = func.alloc_vreg();
        start = func.alloc_vreg();
        end = func.alloc_vreg();
        lock_ret = func.alloc_vreg();
        new_ret = func.alloc_vreg();
        next_ret = func.alloc_vreg();
        destroy_ret = func.alloc_vreg();
        unlock_ret = func.alloc_vreg();
        let iter_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        func.block_mut(block).instructions.push(MirInst::Copy {
            dst: iter,
            src: MirValue::StackSlot(iter_slot),
        });
        func.block_mut(block).instructions.push(MirInst::Copy {
            dst: start,
            src: MirValue::Const(0),
        });
        func.block_mut(block).instructions.push(MirInst::Copy {
            dst: end,
            src: MirValue::Const(2),
        });
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: lock_ret,
                helper: BpfHelper::SpinLock as u32,
                args: vec![MirValue::VReg(lock)],
            });
        func.block_mut(block).instructions.push(MirInst::CallKfunc {
            dst: new_ret,
            kfunc: "bpf_iter_num_new".to_string(),
            btf_id: None,
            args: vec![iter, start, end],
        });
        func.block_mut(block).instructions.push(MirInst::CallKfunc {
            dst: next_ret,
            kfunc: "bpf_iter_num_next".to_string(),
            btf_id: None,
            args: vec![iter],
        });
        func.block_mut(block).instructions.push(MirInst::CallKfunc {
            dst: destroy_ret,
            kfunc: "bpf_iter_num_destroy".to_string(),
            btf_id: None,
            args: vec![iter],
        });
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: unlock_ret,
                helper: BpfHelper::SpinUnlock as u32,
                args: vec![MirValue::VReg(lock)],
            });
        func.block_mut(block).terminator = MirInst::Return { val: None };
    });
    let mut types = bpf_spin_lock_types(
        lock,
        &[
            (start, MirType::I64),
            (end, MirType::I64),
            (lock_ret, MirType::I64),
            (new_ret, MirType::I64),
            (destroy_ret, MirType::I64),
            (unlock_ret, MirType::I64),
        ],
    );
    types.insert(
        iter,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        next_ret,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );

    verify_mir(&func, &types)
        .expect("expected bpf_iter_num kfuncs to be allowed while bpf_spin_lock is held");
}

#[test]
fn test_verify_mir_for_program_bpf_spin_lock_policy() {
    let mut lock_ret = VReg(0);
    let (func, lock) = bpf_spin_lock_guarded_function(|func, block, lock| {
        lock_ret = func.alloc_vreg();
        func.block_mut(block)
            .instructions
            .push(MirInst::CallHelper {
                dst: lock_ret,
                helper: BpfHelper::SpinLock as u32,
                args: vec![MirValue::VReg(lock)],
            });
        func.block_mut(block).terminator = MirInst::Return { val: None };
    });
    let types = bpf_spin_lock_types(lock, &[(lock_ret, MirType::I64)]);

    let err = verify_mir_for_program(&func, &types, EbpfProgramType::SocketFilter.info())
        .expect_err("expected socket_filter bpf_spin_lock policy rejection");
    assert!(
        err.iter().any(|e| {
            e.message.contains("helper 'bpf_spin_lock' is only valid") && e.message.contains("xdp")
        }),
        "unexpected error messages: {:?}",
        err
    );
}

