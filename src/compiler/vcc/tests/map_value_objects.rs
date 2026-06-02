use super::*;
use crate::compiler::mir::StructField;

fn named_array_map(name: &str) -> MapRef {
    MapRef {
        name: name.to_string(),
        kind: MapKind::Array,
    }
}

fn timer_map(name: &str) -> MapRef {
    named_array_map(name)
}

fn workqueue_map(name: &str) -> MapRef {
    named_array_map(name)
}

fn bpf_timer_map_ptr_ty() -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::opaque_named_struct("bpf_timer")),
        address_space: AddressSpace::Map,
    }
}

fn timer_map_ref_ty() -> MirType {
    MirType::MapRef {
        key_ty: Box::new(MirType::U32),
        val_ty: Box::new(MirType::opaque_named_struct("bpf_timer")),
    }
}

fn workqueue_value_ty() -> MirType {
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

fn workqueue_map_ptr_ty() -> MirType {
    MirType::Ptr {
        pointee: Box::new(workqueue_value_ty()),
        address_space: AddressSpace::Map,
    }
}

fn workqueue_map_ref_ty() -> MirType {
    MirType::MapRef {
        key_ty: Box::new(MirType::U32),
        val_ty: Box::new(workqueue_value_ty()),
    }
}

struct PhiLookup {
    checked: BlockId,
    value: VReg,
    types: HashMap<VReg, MirType>,
}

fn emit_branch_phi_map_lookup(
    func: &mut MirFunction,
    entry: BlockId,
    left_map: MapRef,
    right_map: MapRef,
    value_ty: MirType,
    copy_keys: bool,
) -> PhiLookup {
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let key = func.alloc_vreg();
    let left_key = func.alloc_vreg();
    let right_key = func.alloc_vreg();
    let left_value = func.alloc_vreg();
    let right_value = func.alloc_vreg();
    let value_phi = func.alloc_vreg();
    let value_non_null = func.alloc_vreg();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let join = func.alloc_block();
    let checked = func.alloc_block();
    let done = func.alloc_block();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: selector,
        if_true: left,
        if_false: right,
    };

    for (block, map, copied_key, value) in [
        (left, left_map, left_key, left_value),
        (right, right_map, right_key, right_value),
    ] {
        let lookup_key = if copy_keys {
            func.block_mut(block).instructions.push(MirInst::Copy {
                dst: copied_key,
                src: MirValue::VReg(key),
            });
            copied_key
        } else {
            key
        };
        func.block_mut(block).instructions.push(MirInst::MapLookup {
            dst: value,
            map,
            key: lookup_key,
        });
        func.block_mut(block).terminator = MirInst::Jump { target: join };
    }

    func.block_mut(join).instructions.push(MirInst::Phi {
        dst: value_phi,
        args: vec![(left, left_value), (right, right_value)],
    });
    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: value_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(value_phi),
        rhs: MirValue::Const(0),
    });
    func.block_mut(join).terminator = MirInst::Branch {
        cond: value_non_null,
        if_true: checked,
        if_false: done,
    };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(key, MirType::I64);
    types.insert(left_key, MirType::I64);
    types.insert(right_key, MirType::I64);
    types.insert(left_value, value_ty.clone());
    types.insert(right_value, value_ty.clone());
    types.insert(value_phi, value_ty);
    types.insert(value_non_null, MirType::Bool);

    PhiLookup {
        checked,
        value: value_phi,
        types,
    }
}

fn assert_error_contains(errors: Vec<VccError>, expected: &str) {
    assert!(
        errors.iter().any(|err| err.message.contains(expected)),
        "expected error containing {expected:?}, got {errors:?}"
    );
}

#[test]
fn test_verify_mir_timer_init_accepts_phi_same_map_value_source_with_aliased_keys() {
    let (mut func, entry) = new_mir_function();
    let PhiLookup {
        checked,
        value: timer,
        mut types,
    } = emit_branch_phi_map_lookup(
        &mut func,
        entry,
        timer_map("timer_map"),
        timer_map("timer_map"),
        bpf_timer_map_ptr_ty(),
        true,
    );
    let map_fd = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();

    func.block_mut(checked)
        .instructions
        .push(MirInst::LoadMapFd {
            dst: map_fd,
            map: timer_map("timer_map"),
        });
    func.block_mut(checked)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerInit as u32,
            args: vec![
                MirValue::VReg(timer),
                MirValue::VReg(map_fd),
                MirValue::Const(0),
            ],
        });
    func.block_mut(checked).terminator = MirInst::Return { val: None };

    types.insert(map_fd, timer_map_ref_ty());
    types.insert(helper_ret, MirType::I64);

    verify_mir(&func, &types).expect("expected same-map timer phi to verify");
}

#[test]
fn test_verify_mir_timer_init_rejects_phi_different_map_value_source() {
    let (mut func, entry) = new_mir_function();
    let PhiLookup {
        checked,
        value: timer,
        mut types,
    } = emit_branch_phi_map_lookup(
        &mut func,
        entry,
        timer_map("timer_map"),
        timer_map("other_timer_map"),
        bpf_timer_map_ptr_ty(),
        false,
    );
    let map_fd = func.alloc_vreg();
    let helper_ret = func.alloc_vreg();

    func.block_mut(checked)
        .instructions
        .push(MirInst::LoadMapFd {
            dst: map_fd,
            map: timer_map("timer_map"),
        });
    func.block_mut(checked)
        .instructions
        .push(MirInst::CallHelper {
            dst: helper_ret,
            helper: BpfHelper::TimerInit as u32,
            args: vec![
                MirValue::VReg(timer),
                MirValue::VReg(map_fd),
                MirValue::Const(0),
            ],
        });
    func.block_mut(checked).terminator = MirInst::Return { val: None };

    types.insert(map_fd, timer_map_ref_ty());
    types.insert(helper_ret, MirType::I64);

    let errors =
        verify_mir(&func, &types).expect_err("expected mixed-map timer phi to be rejected");
    assert_error_contains(
        errors,
        "helper 'bpf_timer_init' arg0 map value may come from multiple maps",
    );
}

#[test]
fn test_verify_mir_wq_init_accepts_phi_same_map_value_source() {
    let (mut func, entry) = new_mir_function();
    let PhiLookup {
        checked,
        value: wq,
        mut types,
    } = emit_branch_phi_map_lookup(
        &mut func,
        entry,
        workqueue_map("work_items"),
        workqueue_map("work_items"),
        workqueue_map_ptr_ty(),
        false,
    );
    let map_fd = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(checked)
        .instructions
        .push(MirInst::LoadMapFd {
            dst: map_fd,
            map: workqueue_map("work_items"),
        });
    func.block_mut(checked).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(checked)
        .instructions
        .push(MirInst::CallKfunc {
            dst,
            kfunc: "bpf_wq_init".to_string(),
            btf_id: None,
            args: vec![wq, map_fd, flags],
        });
    func.block_mut(checked).terminator = MirInst::Return { val: None };

    types.insert(map_fd, workqueue_map_ref_ty());
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected same-map workqueue phi to verify");
}

#[test]
fn test_verify_mir_wq_init_accepts_phi_same_map_value_source_with_copied_keys() {
    let (mut func, entry) = new_mir_function();
    let PhiLookup {
        checked,
        value: wq,
        mut types,
    } = emit_branch_phi_map_lookup(
        &mut func,
        entry,
        workqueue_map("work_items"),
        workqueue_map("work_items"),
        workqueue_map_ptr_ty(),
        true,
    );
    let map_fd = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(checked)
        .instructions
        .push(MirInst::LoadMapFd {
            dst: map_fd,
            map: workqueue_map("work_items"),
        });
    func.block_mut(checked).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(checked)
        .instructions
        .push(MirInst::CallKfunc {
            dst,
            kfunc: "bpf_wq_init".to_string(),
            btf_id: None,
            args: vec![wq, map_fd, flags],
        });
    func.block_mut(checked).terminator = MirInst::Return { val: None };

    types.insert(map_fd, workqueue_map_ref_ty());
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected copied-key same-map workqueue phi to verify");
}

#[test]
fn test_verify_mir_wq_init_rejects_phi_different_map_value_source() {
    let (mut func, entry) = new_mir_function();
    let PhiLookup {
        checked,
        value: wq,
        mut types,
    } = emit_branch_phi_map_lookup(
        &mut func,
        entry,
        workqueue_map("work_items"),
        workqueue_map("other_work_items"),
        workqueue_map_ptr_ty(),
        false,
    );
    let map_fd = func.alloc_vreg();
    let flags = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(checked)
        .instructions
        .push(MirInst::LoadMapFd {
            dst: map_fd,
            map: workqueue_map("work_items"),
        });
    func.block_mut(checked).instructions.push(MirInst::Copy {
        dst: flags,
        src: MirValue::Const(0),
    });
    func.block_mut(checked)
        .instructions
        .push(MirInst::CallKfunc {
            dst,
            kfunc: "bpf_wq_init".to_string(),
            btf_id: None,
            args: vec![wq, map_fd, flags],
        });
    func.block_mut(checked).terminator = MirInst::Return { val: None };

    types.insert(map_fd, workqueue_map_ref_ty());
    types.insert(flags, MirType::I64);
    types.insert(dst, MirType::I64);

    let errors =
        verify_mir(&func, &types).expect_err("expected mixed-map workqueue phi to be rejected");
    assert_error_contains(
        errors,
        "kfunc 'bpf_wq_init' arg0 map value may come from multiple maps",
    );
}
