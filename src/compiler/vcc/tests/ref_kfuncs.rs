use super::*;

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

fn push_cgroup_from_id(func: &mut MirFunction, block: BlockId, id: VReg) -> VReg {
    let cgroup = func.alloc_vreg();
    func.block_mut(block).instructions.push(MirInst::CallKfunc {
        dst: cgroup,
        kfunc: "bpf_cgroup_from_id".to_string(),
        btf_id: None,
        args: vec![id],
    });
    cgroup
}

fn push_cgroup_release(func: &mut MirFunction, block: BlockId, cgroup: VReg) -> VReg {
    let ret = func.alloc_vreg();
    func.block_mut(block).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_cgroup_release".to_string(),
        btf_id: None,
        args: vec![cgroup],
    });
    ret
}

fn insert_scalar_types(types: &mut HashMap<VReg, MirType>, regs: &[VReg]) {
    for reg in regs {
        types.insert(*reg, MirType::I64);
    }
}

#[test]
fn test_verify_mir_kfunc_cgroup_release_accepts_both_branch_release() {
    let (mut func, entry) = new_mir_function();
    let cgroup_live = func.alloc_block();
    let release_left = func.alloc_block();
    let release_right = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let cgroup_non_null = func.alloc_vreg();
    let branch_cond = func.alloc_vreg();
    let id = push_const_arg(&mut func, entry, 1);
    let cgroup = push_cgroup_from_id(&mut func, entry, id);
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cgroup_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(cgroup),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cgroup_non_null,
        if_true: cgroup_live,
        if_false: done,
    };

    func.block_mut(cgroup_live)
        .instructions
        .push(MirInst::BinOp {
            dst: branch_cond,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(selector),
            rhs: MirValue::Const(0),
        });
    func.block_mut(cgroup_live).terminator = MirInst::Branch {
        cond: branch_cond,
        if_true: release_left,
        if_false: release_right,
    };

    let left_release = push_cgroup_release(&mut func, release_left, cgroup);
    func.block_mut(release_left).terminator = MirInst::Jump { target: done };
    let right_release = push_cgroup_release(&mut func, release_right, cgroup);
    func.block_mut(release_right).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(cgroup_non_null, MirType::Bool);
    types.insert(branch_cond, MirType::Bool);
    types.insert(cgroup, kernel_ptr_ty());
    insert_scalar_types(&mut types, &[id, left_release, right_release]);

    verify_mir(&func, &types).expect("expected cgroup ref released on both branches");
}

#[test]
fn test_verify_mir_kfunc_cgroup_release_rejects_one_branch_release_leak() {
    let (mut func, entry) = new_mir_function();
    let cgroup_live = func.alloc_block();
    let release_path = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let cgroup_non_null = func.alloc_vreg();
    let branch_cond = func.alloc_vreg();
    let id = push_const_arg(&mut func, entry, 1);
    let cgroup = push_cgroup_from_id(&mut func, entry, id);
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cgroup_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(cgroup),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cgroup_non_null,
        if_true: cgroup_live,
        if_false: done,
    };

    func.block_mut(cgroup_live)
        .instructions
        .push(MirInst::BinOp {
            dst: branch_cond,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(selector),
            rhs: MirValue::Const(0),
        });
    func.block_mut(cgroup_live).terminator = MirInst::Branch {
        cond: branch_cond,
        if_true: release_path,
        if_false: done,
    };

    let release_ret = push_cgroup_release(&mut func, release_path, cgroup);
    func.block_mut(release_path).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(cgroup_non_null, MirType::Bool);
    types.insert(branch_cond, MirType::Bool);
    types.insert(cgroup, kernel_ptr_ty());
    insert_scalar_types(&mut types, &[id, release_ret]);

    let err = verify_mir(&func, &types).expect_err("expected one-branch cgroup ref leak");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased kfunc reference")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_cgroup_release_rejects_release_after_conditional_release() {
    let (mut func, entry) = new_mir_function();
    let cgroup_live = func.alloc_block();
    let conditional_release = func.alloc_block();
    let join = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let cgroup_non_null = func.alloc_vreg();
    let branch_cond = func.alloc_vreg();
    let id = push_const_arg(&mut func, entry, 1);
    let cgroup = push_cgroup_from_id(&mut func, entry, id);
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cgroup_non_null,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(cgroup),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cgroup_non_null,
        if_true: cgroup_live,
        if_false: done,
    };

    func.block_mut(cgroup_live)
        .instructions
        .push(MirInst::BinOp {
            dst: branch_cond,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(selector),
            rhs: MirValue::Const(0),
        });
    func.block_mut(cgroup_live).terminator = MirInst::Branch {
        cond: branch_cond,
        if_true: conditional_release,
        if_false: join,
    };

    let conditional_release_ret = push_cgroup_release(&mut func, conditional_release, cgroup);
    func.block_mut(conditional_release).terminator = MirInst::Jump { target: join };
    let final_release_ret = push_cgroup_release(&mut func, join, cgroup);
    func.block_mut(join).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(cgroup_non_null, MirType::Bool);
    types.insert(branch_cond, MirType::Bool);
    types.insert(cgroup, kernel_ptr_ty());
    insert_scalar_types(
        &mut types,
        &[id, conditional_release_ret, final_release_ret],
    );

    let err = verify_mir(&func, &types)
        .expect_err("expected release-after-conditional-release cgroup ref error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'bpf_cgroup_release' arg0 reference already released")),
        "unexpected errors: {:?}",
        err
    );
}
