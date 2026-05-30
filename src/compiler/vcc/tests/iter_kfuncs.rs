use super::*;

fn stack_iter_ty() -> MirType {
    MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::Stack,
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

fn push_stack_iter(func: &mut MirFunction, block: BlockId) -> VReg {
    let iter = func.alloc_vreg();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    func.block_mut(block).instructions.push(MirInst::Copy {
        dst: iter,
        src: MirValue::StackSlot(slot),
    });
    iter
}

fn push_iter_num_new(
    func: &mut MirFunction,
    block: BlockId,
    iter: VReg,
    start: VReg,
    end: VReg,
) -> VReg {
    let ret = func.alloc_vreg();
    func.block_mut(block).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_iter_num_new".to_string(),
        btf_id: None,
        args: vec![iter, start, end],
    });
    ret
}

fn push_iter_num_destroy(func: &mut MirFunction, block: BlockId, iter: VReg) -> VReg {
    let ret = func.alloc_vreg();
    func.block_mut(block).instructions.push(MirInst::CallKfunc {
        dst: ret,
        kfunc: "bpf_iter_num_destroy".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    ret
}

fn insert_scalar_types(types: &mut HashMap<VReg, MirType>, regs: &[VReg]) {
    for reg in regs {
        types.insert(*reg, MirType::I64);
    }
}

#[test]
fn test_verify_mir_kfunc_iter_num_accepts_reinit_after_conditional_balanced_lifecycle() {
    let (mut func, entry) = new_mir_function();
    let init_path = func.alloc_block();
    let skip_path = func.alloc_block();
    let join = func.alloc_block();
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let iter = push_stack_iter(&mut func, entry);
    let start = push_const_arg(&mut func, entry, 0);
    let mid = push_const_arg(&mut func, entry, 4);
    let end = push_const_arg(&mut func, entry, 8);
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: init_path,
        if_false: skip_path,
    };

    let conditional_new = push_iter_num_new(&mut func, init_path, iter, start, mid);
    let conditional_destroy = push_iter_num_destroy(&mut func, init_path, iter);
    func.block_mut(init_path).terminator = MirInst::Jump { target: join };
    func.block_mut(skip_path).terminator = MirInst::Jump { target: join };

    let reinit = push_iter_num_new(&mut func, join, iter, mid, end);
    let final_destroy = push_iter_num_destroy(&mut func, join, iter);
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(cond, MirType::Bool);
    types.insert(iter, stack_iter_ty());
    insert_scalar_types(
        &mut types,
        &[
            start,
            mid,
            end,
            conditional_new,
            conditional_destroy,
            reinit,
            final_destroy,
        ],
    );

    verify_mir(&func, &types)
        .expect("expected reinit after conditional balanced iter_num lifecycle to pass");
}

#[test]
fn test_verify_mir_kfunc_iter_num_conditional_destroy_leak_is_rejected() {
    let (mut func, entry) = new_mir_function();
    let destroy_path = func.alloc_block();
    let done = func.alloc_block();
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let iter = push_stack_iter(&mut func, entry);
    let start = push_const_arg(&mut func, entry, 0);
    let end = push_const_arg(&mut func, entry, 8);
    let new_ret = push_iter_num_new(&mut func, entry, iter, start, end);
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: destroy_path,
        if_false: done,
    };

    let destroy_ret = push_iter_num_destroy(&mut func, destroy_path, iter);
    func.block_mut(destroy_path).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(cond, MirType::Bool);
    types.insert(iter, stack_iter_ty());
    insert_scalar_types(&mut types, &[start, end, new_ret, destroy_ret]);

    let err = verify_mir(&func, &types).expect_err("expected conditional iter_num leak error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("unreleased iter_num iterator")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_num_destroy_rejected_after_conditional_destroy() {
    let (mut func, entry) = new_mir_function();
    let destroy_path = func.alloc_block();
    let join = func.alloc_block();
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let iter = push_stack_iter(&mut func, entry);
    let start = push_const_arg(&mut func, entry, 0);
    let end = push_const_arg(&mut func, entry, 8);
    let new_ret = push_iter_num_new(&mut func, entry, iter, start, end);
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: destroy_path,
        if_false: join,
    };

    let conditional_destroy = push_iter_num_destroy(&mut func, destroy_path, iter);
    func.block_mut(destroy_path).terminator = MirInst::Jump { target: join };
    let final_destroy = push_iter_num_destroy(&mut func, join, iter);
    func.block_mut(join).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(cond, MirType::Bool);
    types.insert(iter, stack_iter_ty());
    insert_scalar_types(
        &mut types,
        &[start, end, new_ret, conditional_destroy, final_destroy],
    );

    let err = verify_mir(&func, &types)
        .expect_err("expected destroy-after-conditional-destroy iter_num error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_iter_num_new")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_num_rejects_double_destroy() {
    let (mut func, entry) = new_mir_function();
    let iter = push_stack_iter(&mut func, entry);
    let start = push_const_arg(&mut func, entry, 0);
    let end = push_const_arg(&mut func, entry, 8);
    let new_ret = push_iter_num_new(&mut func, entry, iter, start, end);
    let first_destroy = push_iter_num_destroy(&mut func, entry, iter);
    let second_destroy = push_iter_num_destroy(&mut func, entry, iter);
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(iter, stack_iter_ty());
    insert_scalar_types(
        &mut types,
        &[start, end, new_ret, first_destroy, second_destroy],
    );

    let err = verify_mir(&func, &types).expect_err("expected double iter_num destroy error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_iter_num_new")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_kfunc_iter_num_rejects_wrong_family_destroy() {
    let (mut func, entry) = new_mir_function();
    let iter = push_stack_iter(&mut func, entry);
    let start = push_const_arg(&mut func, entry, 0);
    let end = push_const_arg(&mut func, entry, 8);
    let new_ret = push_iter_num_new(&mut func, entry, iter, start, end);
    let destroy_ret = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::CallKfunc {
        dst: destroy_ret,
        kfunc: "bpf_iter_bits_destroy".to_string(),
        btf_id: None,
        args: vec![iter],
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(iter, stack_iter_ty());
    insert_scalar_types(&mut types, &[start, end, new_ret, destroy_ret]);

    let err = verify_mir(&func, &types).expect_err("expected wrong-family iterator destroy error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("requires a matching bpf_iter_bits_new")),
        "unexpected errors: {:?}",
        err
    );
}
