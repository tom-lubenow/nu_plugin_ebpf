const BPF_LOAD_HDR_OPT_TCP_SYN: i64 = 1;
const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: i64 = 4;
const BPF_SOCK_OPS_HDR_OPT_LEN_CB: i64 = 14;
const BPF_SOCK_OPS_WRITE_HDR_OPT_CB: i64 = 15;

fn bpf_timer_map_ptr_ty() -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::opaque_named_struct("bpf_timer")),
        address_space: AddressSpace::Map,
    }
}

fn timer_map_ref() -> MapRef {
    MapRef {
        name: "timer_map".to_string(),
        kind: MapKind::Array,
    }
}

fn timer_map_ref_ty() -> MirType {
    MirType::MapRef {
        key_ty: Box::new(MirType::U32),
        val_ty: Box::new(MirType::opaque_named_struct("bpf_timer")),
    }
}

fn timer_callback_ty() -> MirType {
    MirType::Subprogram {
        args: vec![
            MirType::named_kernel_struct_ptr("bpf_map"),
            MirType::Ptr {
                pointee: Box::new(MirType::U32),
                address_space: AddressSpace::Map,
            },
            MirType::Ptr {
                pointee: Box::new(MirType::Struct {
                    name: Some("timer_value".to_string()),
                    kernel_btf_type_id: None,
                    fields: vec![
                        StructField {
                            name: "timer".to_string(),
                            ty: MirType::opaque_named_struct("bpf_timer"),
                            offset: 0,
                            synthetic: false,
                            bitfield: None,
                        },
                        StructField {
                            name: "cookie".to_string(),
                            ty: MirType::U64,
                            offset: 8,
                            synthetic: false,
                            bitfield: None,
                        },
                    ],
                }),
                address_space: AddressSpace::Map,
            },
        ],
        ret: Box::new(MirType::I64),
    }
}

fn emit_unchecked_timer_map_lookup(func: &mut MirFunction, entry: BlockId, timer: VReg) -> VReg {
    let key = func.alloc_vreg();
    let block = func.block_mut(entry);
    block.instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::MapLookup {
        dst: timer,
        map: timer_map_ref(),
        key,
    });
    key
}

fn emit_checked_timer_map_lookup(
    func: &mut MirFunction,
    entry: BlockId,
    timer: VReg,
) -> (BlockId, VReg) {
    let timer_loaded = func.alloc_block();
    let done = func.alloc_block();
    let key = func.alloc_vreg();
    let timer_non_null = func.alloc_vreg();
    let block = func.block_mut(entry);
    block.instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::MapLookup {
        dst: timer,
        map: MapRef {
            name: "timer_map".to_string(),
            kind: MapKind::Array,
        },
        key,
    });
    block.instructions.push(MirInst::BinOp {
        dst: timer_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(timer),
        rhs: MirValue::Const(0),
    });
    block.terminator = MirInst::Branch {
        cond: timer_non_null,
        if_true: timer_loaded,
        if_false: done,
    };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    (timer_loaded, timer_non_null)
}

fn timer_init_subfunction() -> MirFunction {
    let mut subfn = MirFunction::new();
    let entry = subfn.alloc_block();
    subfn.entry = entry;
    subfn.param_count = 3;
    subfn.vreg_count = 3;
    let helper_ret = subfn.alloc_vreg();
    subfn
        .block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerInit as u32,
            args: vec![
                MirValue::VReg(VReg(0)),
                MirValue::VReg(VReg(1)),
                MirValue::VReg(VReg(2)),
            ],
        });
    subfn.block_mut(entry).terminator = MirInst::Return { val: None };
    subfn
}

fn timer_init_fixed_map_subfunction() -> MirFunction {
    let mut subfn = MirFunction::new();
    let entry = subfn.alloc_block();
    subfn.entry = entry;
    subfn.param_count = 1;
    subfn.vreg_count = 1;
    let map = subfn.alloc_vreg();
    let flags = subfn.alloc_vreg();
    let helper_ret = subfn.alloc_vreg();
    subfn
        .block_mut(entry)
        .instructions
        .push(MirInst::LoadMapFd {
            dst: map,
            map: timer_map_ref(),
        });
    subfn.block_mut(entry).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    subfn
        .block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerInit as u32,
            args: vec![
                MirValue::VReg(VReg(0)),
                MirValue::VReg(map),
                MirValue::VReg(flags),
            ],
        });
    subfn.block_mut(entry).terminator = MirInst::Return { val: None };
    subfn
}

#[test]
fn test_helper_pointer_arg_required() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let dst = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst,
            helper: 16, // bpf_get_current_comm(buf, size)
            args: vec![MirValue::Const(0), MirValue::Const(16)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(dst, MirType::I64);
    let err = verify_mir(&func, &types).expect_err("expected helper pointer-arg error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("arg0 expects pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_timer_set_callback_accepts_modeled_callback_subprogram() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let timer = func.alloc_vreg();
    let callback_fn = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let value_ty = MirType::Struct {
        name: Some("timer_value".to_string()),
        kernel_btf_type_id: None,
        fields: vec![
            StructField {
                name: "timer".to_string(),
                ty: MirType::opaque_named_struct("bpf_timer"),
                offset: 0,
                synthetic: false,
                bitfield: None,
            },
            StructField {
                name: "cookie".to_string(),
                ty: MirType::U64,
                offset: 8,
                synthetic: false,
                bitfield: None,
            },
        ],
    };
    let (timer_loaded, timer_non_null) = emit_checked_timer_map_lookup(&mut func, entry, timer);
    func.block_mut(timer_loaded)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback_fn,
            subfn: SubfunctionId(0),
        });
    func.block_mut(timer_loaded)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerSetCallback as u32,
            args: vec![MirValue::VReg(timer), MirValue::VReg(callback_fn)],
        });
    func.block_mut(timer_loaded).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(timer, bpf_timer_map_ptr_ty());
    types.insert(timer_non_null, MirType::Bool);
    types.insert(
        callback_fn,
        MirType::Subprogram {
            args: vec![
                MirType::named_kernel_struct_ptr("bpf_map"),
                MirType::Ptr {
                    pointee: Box::new(MirType::U32),
                    address_space: AddressSpace::Map,
                },
                MirType::Ptr {
                    pointee: Box::new(value_ty),
                    address_space: AddressSpace::Map,
                },
            ],
            ret: Box::new(MirType::I64),
        },
    );
    types.insert(helper_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected modeled bpf_timer_set_callback callback to verify");
}

#[test]
fn test_verify_mir_timer_set_callback_rejects_wrong_callback_signature() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let timer = func.alloc_vreg();
    let callback_fn = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let (timer_loaded, timer_non_null) = emit_checked_timer_map_lookup(&mut func, entry, timer);
    func.block_mut(timer_loaded)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback_fn,
            subfn: SubfunctionId(0),
        });
    func.block_mut(timer_loaded)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerSetCallback as u32,
            args: vec![MirValue::VReg(timer), MirValue::VReg(callback_fn)],
        });
    func.block_mut(timer_loaded).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(timer, bpf_timer_map_ptr_ty());
    types.insert(timer_non_null, MirType::Bool);
    types.insert(
        callback_fn,
        MirType::Subprogram {
            args: vec![MirType::I64],
            ret: Box::new(MirType::I64),
        },
    );
    types.insert(helper_ret, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected bpf_timer_set_callback callback signature error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_timer_set_callback' callback must have signature fn(bpf_map*, *map, *map) -> scalar"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_callback_return_rejects_out_of_range_value() {
    let mut callback = MirFunction::with_name("bpf_loop_callback_test");
    callback.required_return_range = Some(crate::compiler::mir::ScalarValueRange::new(0, 1));
    let entry = callback.alloc_block();
    callback.entry = entry;
    callback.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(2)),
    };

    let summaries = infer_subfunction_summaries(&[callback.clone()]);
    let current_summary = summaries
        .get(&SubfunctionId(0))
        .cloned()
        .expect("expected callback summary");
    assert_eq!(
        current_summary.required_return_range(),
        Some(crate::compiler::mir::ScalarValueRange::new(0, 1))
    );

    let err = verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &callback,
        &HashMap::new(),
        &summaries,
        Some(current_summary),
        None,
        None,
    )
    .expect_err("expected callback return range error");
    assert!(
        err.iter().any(|e| e.message.contains("callback return")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_callback_return_accepts_allowed_value() {
    let mut callback = MirFunction::with_name("bpf_loop_callback_test");
    callback.required_return_range = Some(crate::compiler::mir::ScalarValueRange::new(0, 1));
    let entry = callback.alloc_block();
    callback.entry = entry;
    callback.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(1)),
    };

    let summaries = infer_subfunction_summaries(&[callback.clone()]);
    let current_summary = summaries
        .get(&SubfunctionId(0))
        .cloned()
        .expect("expected callback summary");
    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        &callback,
        &HashMap::new(),
        &summaries,
        Some(current_summary),
        None,
        None,
    )
    .expect("expected allowed callback return to verify");
}

#[test]
fn test_verify_mir_timer_start_rejects_stack_timer_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let timer = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let helper_ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerStart as u32,
            args: vec![
                MirValue::StackSlot(timer),
                MirValue::Const(1000),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(helper_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bpf_timer_start stack timer error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_timer_start' arg0 expects map-backed bpf_timer pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_timer_start_requires_null_checked_map_lookup() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let timer = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let key = emit_unchecked_timer_map_lookup(&mut func, entry, timer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerStart as u32,
            args: vec![
                MirValue::VReg(timer),
                MirValue::Const(1000),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(key, MirType::I64);
    types.insert(timer, bpf_timer_map_ptr_ty());
    types.insert(helper_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected unchecked map-backed timer pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("may dereference null pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_timer_init_requires_null_checked_map_lookup() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let timer = func.alloc_vreg();
    let map = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let key = emit_unchecked_timer_map_lookup(&mut func, entry, timer);
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: timer_map_ref(),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerInit as u32,
            args: vec![
                MirValue::VReg(timer),
                MirValue::VReg(map),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(key, MirType::I64);
    types.insert(timer, bpf_timer_map_ptr_ty());
    types.insert(map, timer_map_ref_ty());
    types.insert(helper_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected unchecked map-backed timer pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("may dereference null pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_timer_init_rejects_mismatched_map_fd() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let timer = func.alloc_vreg();
    let map = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let (timer_loaded, timer_non_null) = emit_checked_timer_map_lookup(&mut func, entry, timer);
    func.block_mut(timer_loaded)
        .instructions
        .push(MirInst::LoadMapFd {
            dst: map,
            map: MapRef {
                name: "other_timer_map".to_string(),
                kind: MapKind::Array,
            },
        });
    func.block_mut(timer_loaded)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerInit as u32,
            args: vec![
                MirValue::VReg(timer),
                MirValue::VReg(map),
                MirValue::Const(0),
            ],
        });
    func.block_mut(timer_loaded).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(timer, bpf_timer_map_ptr_ty());
    types.insert(timer_non_null, MirType::Bool);
    types.insert(map, timer_map_ref_ty());
    types.insert(helper_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected mismatched timer map fd error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_timer_init' arg1 map 'other_timer_map' does not match arg0 map value 'timer_map'"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_timer_init_rejects_phi_mismatched_map_fd() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let timer = func.alloc_vreg();
    let map_left = func.alloc_vreg();
    let map_right = func.alloc_vreg();
    let map_phi = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let join = func.alloc_block();
    let (timer_loaded, timer_non_null) = emit_checked_timer_map_lookup(&mut func, entry, timer);
    func.block_mut(timer_loaded).terminator = MirInst::Branch {
        cond: selector,
        if_true: left,
        if_false: right,
    };
    for (block, map_reg) in [(left, map_left), (right, map_right)] {
        func.block_mut(block).instructions.push(MirInst::LoadMapFd {
            dst: map_reg,
            map: MapRef {
                name: "other_timer_map".to_string(),
                kind: MapKind::Array,
            },
        });
        func.block_mut(block).terminator = MirInst::Jump { target: join };
    }
    func.block_mut(join).instructions.push(MirInst::Phi {
        dst: map_phi,
        args: vec![(left, map_left), (right, map_right)],
    });
    func.block_mut(join).instructions.push(MirInst::CallHelper {
        dst: helper_ret,
        helper: BpfHelper::TimerInit as u32,
        args: vec![
            MirValue::VReg(timer),
            MirValue::VReg(map_phi),
            MirValue::Const(0),
        ],
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(timer, bpf_timer_map_ptr_ty());
    types.insert(timer_non_null, MirType::Bool);
    types.insert(map_left, timer_map_ref_ty());
    types.insert(map_right, timer_map_ref_ty());
    types.insert(map_phi, timer_map_ref_ty());
    types.insert(helper_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected phi mismatched timer map fd error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_timer_init' arg1 map 'other_timer_map' does not match arg0 map value 'timer_map'"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_timer_init_subfn_accepts_matching_map_fd() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let timer = func.alloc_vreg();
    let map = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let subfn_ret = func.alloc_vreg();
    let (timer_loaded, timer_non_null) = emit_checked_timer_map_lookup(&mut func, entry, timer);
    func.block_mut(timer_loaded)
        .instructions
        .push(MirInst::LoadMapFd {
            dst: map,
            map: timer_map_ref(),
        });
    func.block_mut(timer_loaded)
        .instructions
        .push(MirInst::Copy {
            dst: flags,
            src: MirValue::Const(0),
        });
    func.block_mut(timer_loaded)
        .instructions
        .push(MirInst::CallSubfn {
            dst: subfn_ret,
            subfn: SubfunctionId(0),
            args: vec![timer, map, flags],
        });
    func.block_mut(timer_loaded).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(timer, bpf_timer_map_ptr_ty());
    types.insert(timer_non_null, MirType::Bool);
    types.insert(map, timer_map_ref_ty());
    types.insert(flags, MirType::I64);
    types.insert(subfn_ret, MirType::I64);

    let summaries = infer_subfunction_summaries(&[timer_init_subfunction()]);
    assert_eq!(
        summaries[&SubfunctionId(0)]
            .map_value_map_fd_requirements()
            .len(),
        1
    );
    verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect("expected timer init subfunction with matching map fd to verify");
}

#[test]
fn test_verify_mir_timer_init_subfn_rejects_mismatched_map_fd() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let timer = func.alloc_vreg();
    let map = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let subfn_ret = func.alloc_vreg();
    let (timer_loaded, timer_non_null) = emit_checked_timer_map_lookup(&mut func, entry, timer);
    func.block_mut(timer_loaded)
        .instructions
        .push(MirInst::LoadMapFd {
            dst: map,
            map: MapRef {
                name: "other_timer_map".to_string(),
                kind: MapKind::Array,
            },
        });
    func.block_mut(timer_loaded)
        .instructions
        .push(MirInst::Copy {
            dst: flags,
            src: MirValue::Const(0),
        });
    func.block_mut(timer_loaded)
        .instructions
        .push(MirInst::CallSubfn {
            dst: subfn_ret,
            subfn: SubfunctionId(0),
            args: vec![timer, map, flags],
        });
    func.block_mut(timer_loaded).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(timer, bpf_timer_map_ptr_ty());
    types.insert(timer_non_null, MirType::Bool);
    types.insert(map, timer_map_ref_ty());
    types.insert(flags, MirType::I64);
    types.insert(subfn_ret, MirType::I64);

    let summaries = infer_subfunction_summaries(&[timer_init_subfunction()]);
    let err = verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect_err("expected timer init subfunction map fd mismatch");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_timer_init' arg1 map 'other_timer_map' does not match arg0 map value 'timer_map'"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_timer_init_fixed_map_subfn_rejects_mismatched_map_value() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let timer_loaded = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let timer = func.alloc_vreg();
    let timer_non_null = func.alloc_vreg();
    let subfn_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: timer,
        map: MapRef {
            name: "other_timer_map".to_string(),
            kind: MapKind::Array,
        },
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: timer_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(timer),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: timer_non_null,
        if_true: timer_loaded,
        if_false: done,
    };
    func.block_mut(timer_loaded)
        .instructions
        .push(MirInst::CallSubfn {
            dst: subfn_ret,
            subfn: SubfunctionId(0),
            args: vec![timer],
        });
    func.block_mut(timer_loaded).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(key, MirType::I64);
    types.insert(timer, bpf_timer_map_ptr_ty());
    types.insert(timer_non_null, MirType::Bool);
    types.insert(subfn_ret, MirType::I64);

    let summaries = infer_subfunction_summaries(&[timer_init_fixed_map_subfunction()]);
    let err = verify_mir_with_subfunction_summaries(&func, &types, &summaries)
        .expect_err("expected fixed-map timer init subfunction map value mismatch");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_timer_init' map 'timer_map' does not match arg0 map value 'other_timer_map'"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_timer_init_rejects_phi_mismatched_map_value_source() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let key = func.alloc_vreg();
    let timer_left = func.alloc_vreg();
    let timer_right = func.alloc_vreg();
    let timer_phi = func.alloc_vreg();
    let timer_non_null = func.alloc_vreg();
    let map_fd = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let checked = func.alloc_block();
    let done = func.alloc_block();
    let join = func.alloc_block();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: selector,
        if_true: left,
        if_false: right,
    };
    for (block, timer) in [(left, timer_left), (right, timer_right)] {
        func.block_mut(block).instructions.push(MirInst::MapLookup {
            dst: timer,
            map: timer_map_ref(),
            key,
        });
        func.block_mut(block).terminator = MirInst::Jump { target: join };
    }
    func.block_mut(join).instructions.push(MirInst::Phi {
        dst: timer_phi,
        args: vec![(left, timer_left), (right, timer_right)],
    });
    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: timer_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(timer_phi),
        rhs: MirValue::Const(0),
    });
    func.block_mut(join).terminator = MirInst::Branch {
        cond: timer_non_null,
        if_true: checked,
        if_false: done,
    };
    func.block_mut(done).terminator = MirInst::Return { val: None };
    func.block_mut(checked)
        .instructions
        .push(MirInst::LoadMapFd {
            dst: map_fd,
            map: MapRef {
                name: "other_timer_map".to_string(),
                kind: MapKind::Array,
            },
        });
    func.block_mut(checked)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerInit as u32,
            args: vec![
                MirValue::VReg(timer_phi),
                MirValue::VReg(map_fd),
                MirValue::Const(0),
            ],
        });
    func.block_mut(checked).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(key, MirType::I64);
    types.insert(timer_left, bpf_timer_map_ptr_ty());
    types.insert(timer_right, bpf_timer_map_ptr_ty());
    types.insert(timer_phi, bpf_timer_map_ptr_ty());
    types.insert(timer_non_null, MirType::Bool);
    types.insert(map_fd, timer_map_ref_ty());
    types.insert(helper_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected phi map-value source mismatch");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_timer_init' arg1 map 'other_timer_map' does not match arg0 map value 'timer_map'"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_timer_init_rejects_phi_mismatched_map_value_source_with_aliased_keys() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    func.param_count = 2;

    let key = func.alloc_vreg();
    let selector = func.alloc_vreg();
    let key_left = func.alloc_vreg();
    let key_right = func.alloc_vreg();
    let timer_left = func.alloc_vreg();
    let timer_right = func.alloc_vreg();
    let timer_phi = func.alloc_vreg();
    let timer_non_null = func.alloc_vreg();
    let map_fd = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let checked = func.alloc_block();
    let done = func.alloc_block();
    let join = func.alloc_block();

    func.block_mut(entry).terminator = MirInst::Branch {
        cond: selector,
        if_true: left,
        if_false: right,
    };
    for (block, copied_key, timer) in [
        (left, key_left, timer_left),
        (right, key_right, timer_right),
    ] {
        func.block_mut(block).instructions.push(MirInst::Copy {
            dst: copied_key,
            src: MirValue::VReg(key),
        });
        func.block_mut(block).instructions.push(MirInst::MapLookup {
            dst: timer,
            map: timer_map_ref(),
            key: copied_key,
        });
        func.block_mut(block).terminator = MirInst::Jump { target: join };
    }
    func.block_mut(join).instructions.push(MirInst::Phi {
        dst: timer_phi,
        args: vec![(left, timer_left), (right, timer_right)],
    });
    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: timer_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(timer_phi),
        rhs: MirValue::Const(0),
    });
    func.block_mut(join).terminator = MirInst::Branch {
        cond: timer_non_null,
        if_true: checked,
        if_false: done,
    };
    func.block_mut(done).terminator = MirInst::Return { val: None };
    func.block_mut(checked)
        .instructions
        .push(MirInst::LoadMapFd {
            dst: map_fd,
            map: MapRef {
                name: "other_timer_map".to_string(),
                kind: MapKind::Array,
            },
        });
    func.block_mut(checked)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerInit as u32,
            args: vec![
                MirValue::VReg(timer_phi),
                MirValue::VReg(map_fd),
                MirValue::Const(0),
            ],
        });
    func.block_mut(checked).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(key, MirType::I64);
    types.insert(selector, MirType::I64);
    types.insert(key_left, MirType::I64);
    types.insert(key_right, MirType::I64);
    types.insert(timer_left, bpf_timer_map_ptr_ty());
    types.insert(timer_right, bpf_timer_map_ptr_ty());
    types.insert(timer_phi, bpf_timer_map_ptr_ty());
    types.insert(timer_non_null, MirType::Bool);
    types.insert(map_fd, timer_map_ref_ty());
    types.insert(helper_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected aliased-key phi source mismatch");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_timer_init' arg1 map 'other_timer_map' does not match arg0 map value 'timer_map'"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_timer_set_callback_requires_null_checked_map_lookup() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let timer = func.alloc_vreg();
    let callback_fn = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let key = emit_unchecked_timer_map_lookup(&mut func, entry, timer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback_fn,
            subfn: SubfunctionId(0),
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerSetCallback as u32,
            args: vec![MirValue::VReg(timer), MirValue::VReg(callback_fn)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(key, MirType::I64);
    types.insert(timer, bpf_timer_map_ptr_ty());
    types.insert(callback_fn, timer_callback_ty());
    types.insert(helper_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected unchecked map-backed timer pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("may dereference null pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_timer_cancel_requires_null_checked_map_lookup() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let timer = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let key = emit_unchecked_timer_map_lookup(&mut func, entry, timer);
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerCancel as u32,
            args: vec![MirValue::VReg(timer)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(key, MirType::I64);
    types.insert(timer, bpf_timer_map_ptr_ty());
    types.insert(helper_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected unchecked map-backed timer pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("may dereference null pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_timer_start_rejects_acquired_task_reference() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let pid = func.alloc_vreg();
    let task = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: pid,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: task,
        kfunc: "bpf_task_from_pid".to_string(),
        btf_id: None,
        args: vec![pid],
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerStart as u32,
            args: vec![
                MirValue::VReg(task),
                MirValue::Const(1000),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(pid, MirType::I64);
    types.insert(task, MirType::named_kernel_struct_ptr("task_struct"));
    types.insert(helper_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected task ref timer pointer error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_timer_start' arg0 expects map-backed bpf_timer pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_timer_init_rejects_invalid_clock_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let timer = func.alloc_vreg();
    let map = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let (timer_loaded, timer_non_null) = emit_checked_timer_map_lookup(&mut func, entry, timer);
    func.block_mut(timer_loaded)
        .instructions
        .push(MirInst::LoadMapFd {
            dst: map,
            map: timer_map_ref(),
        });
    func.block_mut(timer_loaded)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerInit as u32,
            args: vec![
                MirValue::VReg(timer),
                MirValue::VReg(map),
                MirValue::Const(99),
            ],
        });
    func.block_mut(timer_loaded).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(timer, bpf_timer_map_ptr_ty());
    types.insert(timer_non_null, MirType::Bool);
    types.insert(
        map,
        MirType::MapRef {
            key_ty: Box::new(MirType::U32),
            val_ty: Box::new(MirType::opaque_named_struct("bpf_timer")),
        },
    );
    types.insert(helper_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected bpf_timer_init invalid clock flags error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_timer_init' requires arg2 flags to be CLOCK_REALTIME, CLOCK_MONOTONIC, or CLOCK_BOOTTIME"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_timer_start_rejects_invalid_flags() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let timer = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    let (timer_loaded, timer_non_null) = emit_checked_timer_map_lookup(&mut func, entry, timer);
    func.block_mut(timer_loaded)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerStart as u32,
            args: vec![
                MirValue::VReg(timer),
                MirValue::Const(1000),
                MirValue::Const(4),
            ],
        });
    func.block_mut(timer_loaded).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(timer, bpf_timer_map_ptr_ty());
    types.insert(timer_non_null, MirType::Bool);
    types.insert(helper_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bpf_timer_start invalid flags error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_timer_start' requires arg2 flags")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_spin_lock_rejects_plain_map_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let lock = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::SpinLock as u32,
            args: vec![MirValue::VReg(lock)],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        lock,
        MirType::Ptr {
            pointee: Box::new(MirType::U32),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(helper_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bpf_spin_lock map pointer error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_spin_lock' arg0 expects map-backed bpf_spin_lock pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_for_each_map_elem_accepts_modeled_callback_subprogram() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map = func.alloc_vreg();
    let callback_ctx = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let callback_fn = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_map".to_string(),
            kind: MapKind::Array,
        },
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback_fn,
            subfn: SubfunctionId(0),
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::ForEachMapElem as u32,
            args: vec![
                MirValue::VReg(map),
                MirValue::VReg(callback_fn),
                MirValue::StackSlot(callback_ctx),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map,
        MirType::MapRef {
            key_ty: Box::new(MirType::U32),
            val_ty: Box::new(MirType::U64),
        },
    );
    types.insert(
        callback_fn,
        MirType::Subprogram {
            args: vec![
                MirType::named_kernel_struct_ptr("bpf_map"),
                MirType::Ptr {
                    pointee: Box::new(MirType::U32),
                    address_space: AddressSpace::Map,
                },
                MirType::Ptr {
                    pointee: Box::new(MirType::U64),
                    address_space: AddressSpace::Map,
                },
                MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Stack,
                },
            ],
            ret: Box::new(MirType::I64),
        },
    );
    types.insert(helper_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected modeled bpf_for_each_map_elem callback to verify");
}

#[test]
fn test_verify_mir_for_each_map_elem_rejects_wrong_callback_signature() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map = func.alloc_vreg();
    let callback_ctx = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let callback_fn = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "demo_map".to_string(),
            kind: MapKind::Array,
        },
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback_fn,
            subfn: SubfunctionId(0),
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::ForEachMapElem as u32,
            args: vec![
                MirValue::VReg(map),
                MirValue::VReg(callback_fn),
                MirValue::StackSlot(callback_ctx),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map,
        MirType::MapRef {
            key_ty: Box::new(MirType::U32),
            val_ty: Box::new(MirType::U64),
        },
    );
    types.insert(
        callback_fn,
        MirType::Subprogram {
            args: vec![MirType::I64],
            ret: Box::new(MirType::I64),
        },
    );
    types.insert(helper_ret, MirType::I64);

    let err = verify_mir(&func, &types)
        .expect_err("expected bpf_for_each_map_elem callback signature error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_for_each_map_elem' callback must have signature fn(bpf_map*, *map, *map, *stack) -> scalar"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_find_vma_accepts_modeled_callback_subprogram() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let task = func.alloc_vreg();
    let callback_ctx = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let callback_fn = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: task,
            helper: BpfHelper::GetCurrentTaskBtf as u32,
            args: vec![],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback_fn,
            subfn: SubfunctionId(0),
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::FindVma as u32,
            args: vec![
                MirValue::VReg(task),
                MirValue::Const(0),
                MirValue::VReg(callback_fn),
                MirValue::StackSlot(callback_ctx),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(task, MirType::named_kernel_struct_ptr("task_struct"));
    types.insert(
        callback_fn,
        MirType::Subprogram {
            args: vec![
                MirType::named_kernel_struct_ptr("task_struct"),
                MirType::named_kernel_struct_ptr("vm_area_struct"),
                MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Stack,
                },
            ],
            ret: Box::new(MirType::I64),
        },
    );
    types.insert(helper_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected modeled bpf_find_vma callback to verify");
}

#[test]
fn test_verify_mir_find_vma_rejects_wrong_callback_signature() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let task = func.alloc_vreg();
    let callback_ctx = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let callback_fn = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: task,
            helper: BpfHelper::GetCurrentTaskBtf as u32,
            args: vec![],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback_fn,
            subfn: SubfunctionId(0),
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::FindVma as u32,
            args: vec![
                MirValue::VReg(task),
                MirValue::Const(0),
                MirValue::VReg(callback_fn),
                MirValue::StackSlot(callback_ctx),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(task, MirType::named_kernel_struct_ptr("task_struct"));
    types.insert(
        callback_fn,
        MirType::Subprogram {
            args: vec![MirType::I64],
            ret: Box::new(MirType::I64),
        },
    );
    types.insert(helper_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected bpf_find_vma callback signature error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "helper 'bpf_find_vma' callback must have signature fn(task_struct*, vm_area_struct*, *stack) -> scalar"
        )),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_find_vma_requires_task_pointer_arg0() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let not_task = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let callback_ctx = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let callback_fn = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback_fn,
            subfn: SubfunctionId(0),
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::FindVma as u32,
            args: vec![
                MirValue::StackSlot(not_task),
                MirValue::Const(0),
                MirValue::VReg(callback_fn),
                MirValue::StackSlot(callback_ctx),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        callback_fn,
        MirType::Subprogram {
            args: vec![
                MirType::named_kernel_struct_ptr("task_struct"),
                MirType::named_kernel_struct_ptr("vm_area_struct"),
                MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Stack,
                },
            ],
            ret: Box::new(MirType::I64),
        },
    );
    types.insert(helper_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bpf_find_vma task pointer error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_find_vma' arg0 expects task pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_find_vma_accepts_null_callback_ctx() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let task = func.alloc_vreg();
    let callback_fn = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: task,
            helper: BpfHelper::GetCurrentTaskBtf as u32,
            args: vec![],
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback_fn,
            subfn: SubfunctionId(0),
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::FindVma as u32,
            args: vec![
                MirValue::VReg(task),
                MirValue::Const(0),
                MirValue::VReg(callback_fn),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(task, MirType::named_kernel_struct_ptr("task_struct"));
    types.insert(
        callback_fn,
        MirType::Subprogram {
            args: vec![
                MirType::named_kernel_struct_ptr("task_struct"),
                MirType::named_kernel_struct_ptr("vm_area_struct"),
                MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Stack,
                },
            ],
            ret: Box::new(MirType::I64),
        },
    );
    types.insert(helper_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected null bpf_find_vma callback_ctx to verify");
}

#[test]
fn test_verify_mir_find_vma_rejects_map_callback_ctx() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let callback_loaded = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let task = func.alloc_vreg();
    let key = func.alloc_vreg();
    let callback_ctx = func.alloc_vreg();
    let callback_ctx_non_null = func.alloc_vreg();
    let callback_fn = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: task,
            helper: BpfHelper::GetCurrentTaskBtf as u32,
            args: vec![],
        });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: callback_ctx,
        map: MapRef {
            name: "callback_ctx_map".to_string(),
            kind: MapKind::Array,
        },
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: callback_ctx_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(callback_ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: callback_ctx_non_null,
        if_true: callback_loaded,
        if_false: done,
    };
    func.block_mut(callback_loaded)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback_fn,
            subfn: SubfunctionId(0),
        });
    func.block_mut(callback_loaded)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::FindVma as u32,
            args: vec![
                MirValue::VReg(task),
                MirValue::Const(0),
                MirValue::VReg(callback_fn),
                MirValue::VReg(callback_ctx),
                MirValue::Const(0),
            ],
        });
    func.block_mut(callback_loaded).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(task, MirType::named_kernel_struct_ptr("task_struct"));
    types.insert(key, MirType::I64);
    types.insert(
        callback_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(callback_ctx_non_null, MirType::Bool);
    types.insert(
        callback_fn,
        MirType::Subprogram {
            args: vec![
                MirType::named_kernel_struct_ptr("task_struct"),
                MirType::named_kernel_struct_ptr("vm_area_struct"),
                MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Stack,
                },
            ],
            ret: Box::new(MirType::I64),
        },
    );
    types.insert(helper_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bpf_find_vma callback_ctx error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper bpf_find_vma callback_ctx expects pointer in [Stack]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_user_ringbuf_drain_rejects_map_callback_ctx() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let callback_loaded = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let map = func.alloc_vreg();
    let key = func.alloc_vreg();
    let callback_ctx = func.alloc_vreg();
    let callback_ctx_non_null = func.alloc_vreg();
    let callback_fn = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "events".to_string(),
            kind: MapKind::UserRingBuf,
        },
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: callback_ctx,
        map: MapRef {
            name: "callback_ctx_map".to_string(),
            kind: MapKind::Array,
        },
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: callback_ctx_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(callback_ctx),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: callback_ctx_non_null,
        if_true: callback_loaded,
        if_false: done,
    };
    func.block_mut(callback_loaded)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback_fn,
            subfn: SubfunctionId(0),
        });
    func.block_mut(callback_loaded)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::UserRingbufDrain as u32,
            args: vec![
                MirValue::VReg(map),
                MirValue::VReg(callback_fn),
                MirValue::VReg(callback_ctx),
                MirValue::Const(0),
            ],
        });
    func.block_mut(callback_loaded).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map,
        MirType::MapRef {
            key_ty: Box::new(MirType::U32),
            val_ty: Box::new(MirType::Unknown),
        },
    );
    types.insert(key, MirType::I64);
    types.insert(
        callback_ctx,
        MirType::Ptr {
            pointee: Box::new(MirType::U64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(callback_ctx_non_null, MirType::Bool);
    types.insert(
        callback_fn,
        MirType::Subprogram {
            args: vec![
                MirType::Ptr {
                    pointee: Box::new(MirType::opaque_named_struct("bpf_dynptr")),
                    address_space: AddressSpace::Stack,
                },
                MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Stack,
                },
            ],
            ret: Box::new(MirType::I64),
        },
    );
    types.insert(helper_ret, MirType::I64);

    let err =
        verify_mir(&func, &types).expect_err("expected user_ringbuf_drain callback_ctx error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper user_ringbuf_drain callback_ctx expects pointer in [Stack]")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_user_ringbuf_drain_accepts_null_callback_ctx() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let map = func.alloc_vreg();
    let callback_fn = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::LoadMapFd {
        dst: map,
        map: MapRef {
            name: "events".to_string(),
            kind: MapKind::UserRingBuf,
        },
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback_fn,
            subfn: SubfunctionId(0),
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::UserRingbufDrain as u32,
            args: vec![
                MirValue::VReg(map),
                MirValue::VReg(callback_fn),
                MirValue::Const(0),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        map,
        MirType::MapRef {
            key_ty: Box::new(MirType::U32),
            val_ty: Box::new(MirType::Unknown),
        },
    );
    types.insert(
        callback_fn,
        MirType::Subprogram {
            args: vec![
                MirType::Ptr {
                    pointee: Box::new(MirType::opaque_named_struct("bpf_dynptr")),
                    address_space: AddressSpace::Stack,
                },
                MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Stack,
                },
            ],
            ret: Box::new(MirType::I64),
        },
    );
    types.insert(helper_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected null user_ringbuf_drain callback_ctx to verify");
}

#[test]
fn test_verify_mir_bpf_loop_accepts_modeled_callback_subprogram() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let callback_ctx = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let callback_fn = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback_fn,
            subfn: SubfunctionId(0),
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::BpfLoop as u32,
            args: vec![
                MirValue::Const(1),
                MirValue::VReg(callback_fn),
                MirValue::StackSlot(callback_ctx),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        callback_fn,
        MirType::Subprogram {
            args: vec![
                MirType::I64,
                MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Stack,
                },
            ],
            ret: Box::new(MirType::I64),
        },
    );
    types.insert(helper_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected modeled bpf_loop callback to verify");
}

#[test]
fn test_verify_mir_bpf_loop_rejects_wrong_callback_signature() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let callback_ctx = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let callback_fn = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback_fn,
            subfn: SubfunctionId(0),
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::BpfLoop as u32,
            args: vec![
                MirValue::Const(1),
                MirValue::VReg(callback_fn),
                MirValue::StackSlot(callback_ctx),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        callback_fn,
        MirType::Subprogram {
            args: vec![MirType::I64],
            ret: Box::new(MirType::I64),
        },
    );
    types.insert(helper_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bpf_loop callback signature error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_loop' callback must have signature fn(u64, *stack) -> scalar")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_bpf_loop_rejects_too_many_iterations() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let callback_ctx = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let callback_fn = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadSubprogram {
            dst: callback_fn,
            subfn: SubfunctionId(0),
        });
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::BpfLoop as u32,
            args: vec![
                MirValue::Const(8 * 1024 * 1024 + 1),
                MirValue::VReg(callback_fn),
                MirValue::StackSlot(callback_ctx),
                MirValue::Const(0),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        callback_fn,
        MirType::Subprogram {
            args: vec![
                MirType::I64,
                MirType::Ptr {
                    pointee: Box::new(MirType::U8),
                    address_space: AddressSpace::Stack,
                },
            ],
            ret: Box::new(MirType::I64),
        },
    );
    types.insert(helper_ret, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bpf_loop iteration bound error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("helper 'bpf_loop' requires arg0 nr_loops")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_callback_dynptr_param_seeds_initialized_stack_slot() {
    let mut func = MirFunction::new();
    func.param_count = 2;
    func.vreg_count = func.param_count as u32;
    let dynptr_slot = func.alloc_stack_slot(16, 8, StackSlotKind::Local);
    func.param_stack_slots.insert(0, dynptr_slot);
    func.entry_initialized_dynptr_slots.insert(dynptr_slot);
    let entry = func.alloc_block();
    func.entry = entry;
    let data_ptr = func.alloc_vreg();
    func.block_mut(entry)
        .instructions
        .push(MirInst::CallHelper {
            dst: data_ptr,
            helper: BpfHelper::DynptrData as u32,
            args: vec![
                MirValue::VReg(VReg(0)),
                MirValue::Const(0),
                MirValue::Const(4),
            ],
        });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let types = HashMap::from([
        (
            VReg(0),
            MirType::Ptr {
                pointee: Box::new(MirType::opaque_named_struct("bpf_dynptr")),
                address_space: AddressSpace::Stack,
            },
        ),
        (
            VReg(1),
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        ),
    ]);

    verify_mir(&func, &types).expect("expected callback dynptr param to verify as initialized");
}

