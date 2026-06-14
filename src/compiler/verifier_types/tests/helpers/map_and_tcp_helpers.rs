#[test]
fn test_verify_mir_subfn_return_arg_summary_preserves_null_checked_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let use_value = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;
    func.vreg_count = 3;

    let cond = VReg(1);
    let ret = VReg(2);

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(VReg(0)),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: use_value,
        if_false: done,
    };

    func.block_mut(use_value)
        .instructions
        .push(MirInst::CallSubfn {
            dst: ret,
            subfn: crate::compiler::mir::SubfunctionId(0),
            args: vec![VReg(0)],
        });
    func.block_mut(use_value)
        .instructions
        .push(MirInst::EmitEvent {
            data: ret,
            size: 16,
        });
    func.block_mut(use_value).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let path_ty = MirType::Ptr {
        pointee: Box::new(MirType::Struct {
            name: Some("path".to_string()),
            kernel_btf_type_id: None,
            fields: vec![
                StructField {
                    name: "mnt".to_string(),
                    ty: MirType::U64,
                    offset: 0,
                    synthetic: false,
                    bitfield: None,
                },
                StructField {
                    name: "dentry".to_string(),
                    ty: MirType::U64,
                    offset: 8,
                    synthetic: false,
                    bitfield: None,
                },
            ],
        }),
        address_space: AddressSpace::Map,
    };
    let mut types = HashMap::new();
    types.insert(VReg(0), path_ty.clone());
    types.insert(ret, path_ty);

    let summaries = HashMap::from([(
        crate::compiler::mir::SubfunctionId(0),
        SubfunctionSummary::from(SubfunctionReturnSummary::ReturnsArg(0)),
    )]);
    verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect("expected null-checked arg-returning subfunction to preserve pointer safety");
}

#[test]
fn test_helper_map_lookup_requires_null_check() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let load_dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::StackSlot(key_slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::VReg(map), MirValue::VReg(key)],
        });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst: load_dst,
        ptr: dst,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        dst,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(load_dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper null-check error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("may dereference null"))
    );
}

#[test]
fn test_helper_map_lookup_null_check_via_copied_cond_ok() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let load_block = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let cond0 = func.alloc_vreg();
    let cond1 = func.alloc_vreg();
    let load_dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::StackSlot(key_slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ptr,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::VReg(map), MirValue::VReg(key)],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond0,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: cond1,
        src: MirValue::VReg(cond0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cond1,
        if_true: load_block,
        if_false: done,
    };

    func.block_mut(load_block).instructions.push(MirInst::Load {
        dst: load_dst,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(load_block).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(load_dst, MirType::I64);

    verify_mir(&func, &types).expect("expected copied null-check guard to pass");
}

#[test]
fn test_helper_map_lookup_rejects_out_of_bounds_key_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key_base = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key_base,
        src: MirValue::StackSlot(key_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: key,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(key_base),
        rhs: MirValue::Const(8),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::VReg(map), MirValue::VReg(key)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper key bounds error");
    assert!(
        err.iter().any(|e| {
            e.message.contains("helper map_lookup key out of bounds")
                || e.message.contains("pointer arithmetic out of bounds")
        }),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_lookup_percpu_rejects_out_of_bounds_key_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key_base = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key_base,
        src: MirValue::StackSlot(key_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: key,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(key_base),
        rhs: MirValue::Const(8),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::MapLookupPercpuElem as u32,
            args: vec![MirValue::VReg(map), MirValue::VReg(key), MirValue::Const(0)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper key bounds error");
    assert!(
        err.iter().any(|e| {
            e.message.contains("helper map_lookup key out of bounds")
                || e.message.contains("pointer arithmetic out of bounds")
        }),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_lookup_percpu_rejects_cpu_above_u32_max() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let map = func.alloc_vreg();
    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: map,
        src: MirValue::StackSlot(map_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::StackSlot(key_slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::MapLookupPercpuElem as u32,
            args: vec![
                MirValue::VReg(map),
                MirValue::VReg(key),
                MirValue::Const(0x1_0000_0000),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected map_lookup_percpu CPU range error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_map_lookup_percpu_elem' requires arg2 cpu to be between 0 and u32::MAX"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_per_cpu_ptr_helpers_accept_kernel_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let percpu_ptr = func.alloc_vreg();
    let per_cpu_dst = func.alloc_vreg();
    let this_cpu_dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: percpu_ptr,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: per_cpu_dst,
            helper: BpfHelper::PerCpuPtr as u32,
            args: vec![MirValue::VReg(percpu_ptr), MirValue::Const(0)],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: this_cpu_dst,
            helper: BpfHelper::ThisCpuPtr as u32,
            args: vec![MirValue::VReg(percpu_ptr)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let kernel_ptr = MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::Kernel,
    };
    let types = HashMap::from([
        (percpu_ptr, kernel_ptr.clone()),
        (per_cpu_dst, kernel_ptr.clone()),
        (this_cpu_dst, kernel_ptr),
    ]);

    verify_mir(&func, &types).expect("expected per-cpu pointer helpers to verify");
}

#[test]
fn test_helper_per_cpu_ptr_rejects_cpu_above_u32_max() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let percpu_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: percpu_ptr,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::PerCpuPtr as u32,
            args: vec![MirValue::VReg(percpu_ptr), MirValue::Const(0x1_0000_0000)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let kernel_ptr = MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::Kernel,
    };
    let types = HashMap::from([(percpu_ptr, kernel_ptr.clone()), (dst, kernel_ptr)]);

    let err = verify_mir(&func, &types).expect_err("expected per_cpu_ptr CPU range error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_per_cpu_ptr' requires arg1 cpu to be between 0 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_per_cpu_ptr_helpers_reject_unchecked_nullable_kernel_pointer() {
    for helper in [BpfHelper::PerCpuPtr, BpfHelper::ThisCpuPtr] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;
        func.param_count = 1;

        let percpu_ptr = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let args = match helper {
            BpfHelper::PerCpuPtr => vec![MirValue::VReg(percpu_ptr), MirValue::Const(0)],
            BpfHelper::ThisCpuPtr => vec![MirValue::VReg(percpu_ptr)],
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

        let kernel_ptr = MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        };
        let types = HashMap::from([(percpu_ptr, kernel_ptr.clone()), (dst, kernel_ptr)]);

        let err = verify_mir(&func, &types)
            .expect_err("expected per-cpu pointer helper null-check error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("may dereference null pointer")),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_helper_per_cpu_ptr_helpers_reject_stack_pointer() {
    for helper in [BpfHelper::PerCpuPtr, BpfHelper::ThisCpuPtr] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ptr_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();
        let args = match helper {
            BpfHelper::PerCpuPtr => vec![MirValue::StackSlot(ptr_slot), MirValue::Const(0)],
            BpfHelper::ThisCpuPtr => vec![MirValue::StackSlot(ptr_slot)],
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

        let types = HashMap::from([(
            dst,
            MirType::Ptr {
                pointee: Box::new(MirType::Unknown),
                address_space: AddressSpace::Kernel,
            },
        )]);
        let err = verify_mir(&func, &types).expect_err("expected per-cpu pointer helper error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("helper per_cpu_ptr ptr expects pointer in [Kernel]")),
            "unexpected errors for {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_helper_map_lookup_rejects_user_map_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(map),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst,
        helper: 1, // bpf_map_lookup_elem(map, key)
        args: vec![MirValue::VReg(map), MirValue::StackSlot(key_slot)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected helper map pointer-space error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper map_lookup map expects pointer in [Stack]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_update_rejects_map_lookup_value_as_map_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let lookup = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let update_ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: lookup,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(lookup),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: update_ret,
        helper: 2, // bpf_map_update_elem(map, key, value, flags)
        args: vec![
            MirValue::VReg(lookup),
            MirValue::StackSlot(key_slot),
            MirValue::StackSlot(value_slot),
            MirValue::Const(0),
        ],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        lookup,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(update_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected map-value pointer map-arg rejection");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper map_update map expects pointer in [Stack]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_update_rejects_invalid_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let update_ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: update_ret,
            helper: BpfHelper::MapUpdateElem as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(key_slot),
                MirValue::StackSlot(value_slot),
                MirValue::Const(3),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(update_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected map update invalid flags error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_map_update_elem' requires arg3 flags")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_queue_rejects_map_lookup_value_as_map_arg() {
    let helpers = [
        (
            BpfHelper::MapPushElem,
            "helper map_push map expects pointer in [Stack]",
        ),
        (
            BpfHelper::MapPopElem,
            "helper map_pop map expects pointer in [Stack]",
        ),
        (
            BpfHelper::MapPeekElem,
            "helper map_peek map expects pointer in [Stack]",
        ),
    ];

    for (helper, needle) in helpers {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let call = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let lookup = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let helper_ret = func.alloc_vreg();

        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: lookup,
                helper: BpfHelper::MapLookupElem as u32,
                args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
            });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(lookup),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: call,
            if_false: done,
        };

        func.block_mut(call).instructions.push(MirInst::CallHelper {
            dst: helper_ret,
            helper: helper as u32,
            args: match helper {
                BpfHelper::MapPushElem => vec![
                    MirValue::VReg(lookup),
                    MirValue::StackSlot(value_slot),
                    MirValue::Const(0),
                ],
                BpfHelper::MapPopElem | BpfHelper::MapPeekElem => {
                    vec![MirValue::VReg(lookup), MirValue::StackSlot(value_slot)]
                }
                _ => unreachable!(),
            },
        });
        func.block_mut(call).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            lookup,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Map,
            },
        );
        types.insert(helper_ret, MirType::I64);

        let err =
            verify_mir(&func, &types).expect_err("expected map queue helper map-arg rejection");
        assert!(
            err.iter().any(|e| e.message.contains(needle)),
            "unexpected errors for helper {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_helper_map_push_rejects_invalid_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let helper_ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::MapPushElem as u32,
            args: vec![
                MirValue::StackSlot(map_slot),
                MirValue::StackSlot(value_slot),
                MirValue::Const(1),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(helper_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected map push invalid flags error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_map_push_elem' requires arg2 flags")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_map_queue_rejects_non_pointer_value_arg() {
    let helpers = [
        (BpfHelper::MapPushElem, 87u32),
        (BpfHelper::MapPopElem, 88u32),
        (BpfHelper::MapPeekElem, 89u32),
    ];

    for (helper, helper_id) in helpers {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let helper_ret = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: helper_ret,
                helper: helper as u32,
                args: match helper {
                    BpfHelper::MapPushElem => vec![
                        MirValue::StackSlot(map_slot),
                        MirValue::Const(0),
                        MirValue::Const(0),
                    ],
                    BpfHelper::MapPopElem | BpfHelper::MapPeekElem => {
                        vec![MirValue::StackSlot(map_slot), MirValue::Const(0)]
                    }
                    _ => unreachable!(),
                },
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(helper_ret, MirType::I64);

        let err =
            verify_mir(&func, &types).expect_err("expected map queue helper value-arg rejection");
        assert!(
            err.iter().any(|e| e
                .message
                .contains(&format!("helper {} arg1 expects pointer", helper_id))),
            "unexpected errors for helper {helper:?}: {:?}",
            err
        );
    }
}

#[test]
fn test_helper_ringbuf_query_rejects_map_lookup_value_as_map_arg() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let lookup = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let query_ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: lookup,
            helper: BpfHelper::MapLookupElem as u32,
            args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(lookup),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: query_ret,
        helper: BpfHelper::RingbufQuery as u32,
        args: vec![MirValue::VReg(lookup), MirValue::Const(0)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        lookup,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(query_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected ringbuf_query map-arg rejection");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper ringbuf_query map expects pointer in [Stack]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_ringbuf_query_accepts_overwrite_pos_selector() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: BpfHelper::RingbufQuery as u32,
            args: vec![MirValue::StackSlot(map_slot), MirValue::Const(4)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected ringbuf_query overwrite-pos selector to verify");
}

fn make_tcp_syncookie_verify_call(
    helper: BpfHelper,
    iph_len: i64,
    th_len: i64,
) -> (MirFunction, HashMap<VReg, MirType>) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let kptr = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: kptr,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: syncookie_ret,
            helper: helper as u32,
            args: vec![
                MirValue::VReg(kptr),
                MirValue::VReg(kptr),
                MirValue::Const(iph_len),
                MirValue::VReg(kptr),
                MirValue::Const(th_len),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        kptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(syncookie_ret, MirType::I64);

    (func, types)
}

#[test]
fn test_helper_tcp_syncookie_rejects_short_header_lengths() {
    for (helper, iph_len, th_len, expected) in [
        (
            BpfHelper::TcpCheckSyncookie,
            19,
            20,
            "TCP syncookie helpers require arg2 iph_len to be between 20 and u32::MAX",
        ),
        (
            BpfHelper::TcpCheckSyncookie,
            20,
            19,
            "TCP syncookie helpers require arg4 th_len to be between 20 and u32::MAX",
        ),
        (
            BpfHelper::TcpGenSyncookie,
            19,
            20,
            "TCP syncookie helpers require arg2 iph_len to be between 20 and u32::MAX",
        ),
        (
            BpfHelper::TcpGenSyncookie,
            20,
            19,
            "TCP syncookie helpers require arg4 th_len to be between 20 and u32::MAX",
        ),
    ] {
        let (func, types) = make_tcp_syncookie_verify_call(helper, iph_len, th_len);
        let err = verify_mir(&func, &types)
            .expect_err("expected TCP syncookie short header length error");
        assert!(
            err.iter().any(|e| e.message.contains(expected)),
            "unexpected errors for {helper:?} iph_len {iph_len} th_len {th_len}: {:?}",
            err
        );
    }
}

#[test]
fn test_helper_tcp_check_syncookie_rejects_non_positive_lengths() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let kptr = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: kptr,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: syncookie_ret,
            helper: BpfHelper::TcpCheckSyncookie as u32,
            args: vec![
                MirValue::VReg(kptr),
                MirValue::VReg(kptr),
                MirValue::Const(0),
                MirValue::VReg(kptr),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        kptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(syncookie_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected tcp_check_syncookie size errors");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 100 arg2 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 100 arg4 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_tcp_check_syncookie_rejects_lengths_above_u32_max() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let kptr = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: kptr,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: syncookie_ret,
            helper: BpfHelper::TcpCheckSyncookie as u32,
            args: vec![
                MirValue::VReg(kptr),
                MirValue::VReg(kptr),
                MirValue::Const(0x1_0000_0000),
                MirValue::VReg(kptr),
                MirValue::Const(0x1_0000_0000),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        kptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(syncookie_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected tcp_check_syncookie size errors");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("TCP syncookie helpers require arg2 iph_len to be between 20 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("TCP syncookie helpers require arg4 th_len to be between 20 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_tcp_gen_syncookie_rejects_non_positive_lengths() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let kptr = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: kptr,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: syncookie_ret,
            helper: BpfHelper::TcpGenSyncookie as u32,
            args: vec![
                MirValue::VReg(kptr),
                MirValue::VReg(kptr),
                MirValue::Const(0),
                MirValue::VReg(kptr),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        kptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(syncookie_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected tcp_gen_syncookie size errors");
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 110 arg2 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("helper 110 arg4 must be > 0")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_tcp_gen_syncookie_rejects_lengths_above_u32_max() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let kptr = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: kptr,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: syncookie_ret,
            helper: BpfHelper::TcpGenSyncookie as u32,
            args: vec![
                MirValue::VReg(kptr),
                MirValue::VReg(kptr),
                MirValue::Const(0x1_0000_0000),
                MirValue::VReg(kptr),
                MirValue::Const(0x1_0000_0000),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        kptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(syncookie_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected tcp_gen_syncookie size errors");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("TCP syncookie helpers require arg2 iph_len to be between 20 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("TCP syncookie helpers require arg4 th_len to be between 20 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_tcp_gen_syncookie_rejects_non_kernel_sk_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let sk_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let pid = func.alloc_vreg();
    let kptr = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(7),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: kptr,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: syncookie_ret,
            helper: BpfHelper::TcpGenSyncookie as u32,
            args: vec![
                MirValue::StackSlot(sk_slot),
                MirValue::VReg(kptr),
                MirValue::Const(20),
                MirValue::VReg(kptr),
                MirValue::Const(20),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(
        kptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(syncookie_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected tcp_gen_syncookie pointer-kind error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper tcp_gen_syncookie sk expects pointer in [Kernel], got stack slot")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_tcp_check_syncookie_rejects_kprobe() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::TcpCheckSyncookie as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::VReg(ctx),
                MirValue::Const(20),
                MirValue::VReg(ctx),
                MirValue::Const(20),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected tcp_check_syncookie kprobe program-surface error");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "helper 'bpf_tcp_check_syncookie' is only valid in xdp, tc_action, tc, tcx, and netkit programs",
        )
    }));
}

#[test]
fn test_verify_mir_for_probe_context_tcp_check_syncookie_accepts_xdp() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sock,
            helper: BpfHelper::SkLookupTcp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(tuple_slot),
                MirValue::Const(12),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: sock_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: syncookie_ret,
        helper: BpfHelper::TcpCheckSyncookie as u32,
        args: vec![
            MirValue::VReg(sock),
            MirValue::VReg(sock),
            MirValue::Const(20),
            MirValue::VReg(sock),
            MirValue::Const(20),
        ],
    });
    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: cleanup_ret,
        helper: BpfHelper::SkRelease as u32,
        args: vec![MirValue::VReg(sock)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(sock_non_null, MirType::Bool);
    types.insert(syncookie_ret, MirType::I64);
    types.insert(cleanup_ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected tcp_check_syncookie xdp context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_tcp_gen_syncookie_accepts_tc() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let call = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let ctx = func.alloc_vreg();
    let sock = func.alloc_vreg();
    let sock_non_null = func.alloc_vreg();
    let syncookie_ret = func.alloc_vreg();
    let cleanup_ret = func.alloc_vreg();
    let tuple_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ctx,
            field: CtxField::Context,
            slot: None,
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: sock,
            helper: BpfHelper::SkLookupTcp as u32,
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(tuple_slot),
                MirValue::Const(12),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: sock_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(sock),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: sock_non_null,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: syncookie_ret,
        helper: BpfHelper::TcpGenSyncookie as u32,
        args: vec![
            MirValue::VReg(sock),
            MirValue::VReg(sock),
            MirValue::Const(20),
            MirValue::VReg(sock),
            MirValue::Const(20),
        ],
    });
    func.block_mut(call).instructions.push(MirInst::CallHelper {
        dst: cleanup_ret,
        helper: BpfHelper::SkRelease as u32,
        args: vec![MirValue::VReg(sock)],
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(
        sock,
        MirType::Ptr {
            pointee: Box::new(MirType::Unknown),
            address_space: AddressSpace::Kernel,
        },
    );
    types.insert(sock_non_null, MirType::Bool);
    types.insert(syncookie_ret, MirType::I64);
    types.insert(cleanup_ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Tc, "lo:ingress");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected tcp_gen_syncookie tc context to verify");
}

#[test]
fn test_helper_tcp_raw_syncookie_checks_stack_header_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ip_slot = func.alloc_stack_slot(20, 8, StackSlotKind::StringBuffer);
    let th_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::TcpRawGenSyncookieIpv4 as u32,
            args: vec![
                MirValue::StackSlot(ip_slot),
                MirValue::StackSlot(th_slot),
                MirValue::Const(20),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected raw syncookie bounds error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper tcp_raw_gen_syncookie_ipv4 th out of bounds")
            || e.message
                .contains("helper tcp_raw_gen_syncookie_ipv4 th requires 20 bytes")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_helper_tcp_raw_syncookie_gen_accepts_zero_size_null_tcp_header() {
    for (helper, ip_size) in [
        (BpfHelper::TcpRawGenSyncookieIpv4, 20),
        (BpfHelper::TcpRawGenSyncookieIpv6, 40),
    ] {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ip_slot = func.alloc_stack_slot(ip_size, 8, StackSlotKind::StringBuffer);
        let ret = func.alloc_vreg();

        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: ret,
                helper: helper as u32,
                args: vec![
                    MirValue::StackSlot(ip_slot),
                    MirValue::Const(0),
                    MirValue::Const(0),
                ],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(ret, MirType::I64);

        verify_mir(&func, &types)
            .unwrap_or_else(|err| panic!("expected {helper:?} to verify: {err:?}"));
    }
}

#[test]
fn test_helper_tcp_raw_syncookie_rejects_len_above_u32_max() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ip_slot = func.alloc_stack_slot(20, 8, StackSlotKind::StringBuffer);
    let th_slot = func.alloc_stack_slot(20, 8, StackSlotKind::StringBuffer);
    let ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::TcpRawGenSyncookieIpv4 as u32,
            args: vec![
                MirValue::StackSlot(ip_slot),
                MirValue::StackSlot(th_slot),
                MirValue::Const(0x1_0000_0000),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected raw syncookie len range error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("raw syncookie helpers require arg2 th_len to be between 0 and u32::MAX")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_probe_context_tcp_raw_syncookie_accepts_xdp() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ip_slot = func.alloc_stack_slot(40, 8, StackSlotKind::StringBuffer);
    let th_slot = func.alloc_stack_slot(20, 8, StackSlotKind::StringBuffer);
    let ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::TcpRawCheckSyncookieIpv6 as u32,
            args: vec![MirValue::StackSlot(ip_slot), MirValue::StackSlot(th_slot)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Xdp, "lo");
    verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect("expected raw syncookie xdp context to verify");
}

#[test]
fn test_verify_mir_for_probe_context_tcp_raw_syncookie_rejects_kprobe() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let ip_slot = func.alloc_stack_slot(20, 8, StackSlotKind::StringBuffer);
    let th_slot = func.alloc_stack_slot(20, 8, StackSlotKind::StringBuffer);
    let ret = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: ret,
            helper: BpfHelper::TcpRawCheckSyncookieIpv4 as u32,
            args: vec![MirValue::StackSlot(ip_slot), MirValue::StackSlot(th_slot)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(ret, MirType::I64);

    let probe_ctx = ProbeContext::new(EbpfProgramType::Kprobe, "ksys_read");
    let err = verify_mir_for_probe_context(&func, &types, &probe_ctx)
        .expect_err("expected raw syncookie kprobe program-surface error");
    assert!(err.iter().any(|e| {
        e.message.contains(
            "helper 'bpf_tcp_raw_check_syncookie_ipv4' is only valid in xdp, tc_action, tc, tcx, and netkit programs",
        )
    }));
}

