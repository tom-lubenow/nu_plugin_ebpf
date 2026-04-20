use super::*;

#[test]
fn test_reject_pointer_binop() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let p0 = func.alloc_reg();
    let p1 = func.alloc_reg();
    let out = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: p0,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: p1,
        slot: StackSlotId(1),
        size: 16,
    });
    func.block_mut(entry).instructions.push(VccInst::BinOp {
        dst: out,
        op: VccBinOp::Add,
        lhs: VccValue::Reg(p0),
        rhs: VccValue::Reg(p1),
    });

    verify_err(&func, VccErrorKind::PointerArithmetic);
}

#[test]
fn test_ptr_add_in_bounds() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let base = func.alloc_reg();
    let out = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: base,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry).instructions.push(VccInst::PtrAdd {
        dst: out,
        base,
        offset: VccValue::Imm(8),
    });

    verify_ok(&func);
}

#[test]
fn test_ptr_add_out_of_bounds() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let base = func.alloc_reg();
    let out = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: base,
        slot: StackSlotId(0),
        size: 8,
    });
    func.block_mut(entry).instructions.push(VccInst::PtrAdd {
        dst: out,
        base,
        offset: VccValue::Imm(16),
    });

    verify_err(&func, VccErrorKind::PointerBounds);
}

#[test]
fn test_ptr_add_unknown_offset_on_stack() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let base = func.alloc_reg();
    let tmp = func.alloc_reg();
    let out = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: base,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry).instructions.push(VccInst::Assume {
        dst: tmp,
        ty: VccValueType::Scalar { range: None },
        ctx_field_source: None,
    });
    func.block_mut(entry).instructions.push(VccInst::PtrAdd {
        dst: out,
        base,
        offset: VccValue::Reg(tmp),
    });

    verify_err(&func, VccErrorKind::UnknownOffset);
}

#[test]
fn test_verify_mir_stack_pointer_loop_counter_range_in_bounds() {
    let (mut func, entry) = new_mir_function();
    let header = func.alloc_block();
    let body = func.alloc_block();
    let exit = func.alloc_block();

    let slot = func.alloc_stack_slot(24, 8, StackSlotKind::ListBuffer);
    let list = func.alloc_vreg();
    let counter = func.alloc_vreg();
    let scaled = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 2,
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: counter,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Jump { target: header };

    func.block_mut(header).terminator = MirInst::LoopHeader {
        counter,
        start: 0,
        step: 1,
        limit: 2,
        body,
        exit,
    };

    func.block_mut(body).instructions.push(MirInst::BinOp {
        dst: scaled,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(counter),
        rhs: MirValue::Const(8),
    });
    func.block_mut(body).instructions.push(MirInst::BinOp {
        dst: ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(list),
        rhs: MirValue::VReg(scaled),
    });
    func.block_mut(body).instructions.push(MirInst::Load {
        dst,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(body).terminator = MirInst::LoopBack {
        counter,
        step: 1,
        header,
    };

    func.block_mut(exit).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        list,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(counter, MirType::I64);
    types.insert(scaled, MirType::I64);
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("bounded loop counter should preserve stack bounds");
}

#[test]
fn test_verify_mir_stack_pointer_descending_loop_counter_range_in_bounds() {
    let (mut func, entry) = new_mir_function();
    let header = func.alloc_block();
    let body = func.alloc_block();
    let exit = func.alloc_block();

    let slot = func.alloc_stack_slot(24, 8, StackSlotKind::ListBuffer);
    let list = func.alloc_vreg();
    let counter = func.alloc_vreg();
    let scaled = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 2,
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: counter,
        src: MirValue::Const(1),
    });
    func.block_mut(entry).terminator = MirInst::Jump { target: header };

    func.block_mut(header).terminator = MirInst::LoopHeader {
        counter,
        start: 1,
        step: -1,
        limit: -1,
        body,
        exit,
    };

    func.block_mut(body).instructions.push(MirInst::BinOp {
        dst: scaled,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(counter),
        rhs: MirValue::Const(8),
    });
    func.block_mut(body).instructions.push(MirInst::BinOp {
        dst: ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(list),
        rhs: MirValue::VReg(scaled),
    });
    func.block_mut(body).instructions.push(MirInst::Load {
        dst,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(body).terminator = MirInst::LoopBack {
        counter,
        step: -1,
        header,
    };

    func.block_mut(exit).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        list,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(counter, MirType::I64);
    types.insert(scaled, MirType::I64);
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("descending loop counter should preserve stack bounds");
}

#[test]
fn test_verify_mir_ctx_u32_mod_range_in_bounds() {
    let (mut func, entry) = new_mir_function();

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::ListBuffer);
    let list = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let modded = func.alloc_vreg();
    let scaled = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 2,
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: idx,
            field: CtxField::Pid,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: modded,
        op: BinOpKind::Mod,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::Const(2),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: scaled,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(modded),
        rhs: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(list),
        rhs: MirValue::VReg(scaled),
    });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        list,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(idx, MirType::U32);
    types.insert(modded, MirType::U32);
    types.insert(scaled, MirType::U32);
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("unsigned ctx-field mod range should stay in bounds");
}

#[test]
fn test_unreachable_block_is_ignored() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let unreachable = func.alloc_block();
    let p0 = func.alloc_reg();
    let p1 = func.alloc_reg();
    let out = func.alloc_reg();

    func.block_mut(entry).terminator = VccTerminator::Return { value: None };
    func.block_mut(unreachable)
        .instructions
        .push(VccInst::StackAddr {
            dst: p0,
            slot: StackSlotId(0),
            size: 16,
        });
    func.block_mut(unreachable)
        .instructions
        .push(VccInst::StackAddr {
            dst: p1,
            slot: StackSlotId(1),
            size: 16,
        });
    func.block_mut(unreachable)
        .instructions
        .push(VccInst::BinOp {
            dst: out,
            op: VccBinOp::Add,
            lhs: VccValue::Reg(p0),
            rhs: VccValue::Reg(p1),
        });

    verify_ok(&func);
}

#[test]
fn test_joined_null_wildcard_pointer_keeps_concrete_space() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let with_ptr = func.alloc_block();
    let with_null = func.alloc_block();
    let join = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();

    let selector = func.alloc_reg();
    let ptr = func.alloc_reg();
    let cond = func.alloc_reg();
    let tmp = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::Assume {
        dst: selector,
        ty: VccValueType::Bool,
        ctx_field_source: None,
    });
    func.block_mut(entry).terminator = VccTerminator::Branch {
        cond: VccValue::Reg(selector),
        if_true: with_ptr,
        if_false: with_null,
    };

    func.block_mut(with_ptr)
        .instructions
        .push(VccInst::StackAddr {
            dst: tmp,
            slot: StackSlotId(0),
            size: 16,
        });
    func.block_mut(with_ptr).instructions.push(VccInst::Copy {
        dst: ptr,
        src: VccValue::Reg(tmp),
    });
    func.block_mut(with_ptr).terminator = VccTerminator::Jump { target: join };

    func.block_mut(with_null).instructions.push(VccInst::Copy {
        dst: ptr,
        src: VccValue::Imm(0),
    });
    func.block_mut(with_null).terminator = VccTerminator::Jump { target: join };

    func.block_mut(join).instructions.push(VccInst::BinOp {
        dst: cond,
        op: VccBinOp::Ne,
        lhs: VccValue::Reg(ptr),
        rhs: VccValue::Imm(0),
    });
    func.block_mut(join).terminator = VccTerminator::Branch {
        cond: VccValue::Reg(cond),
        if_true: ok,
        if_false: bad,
    };

    func.block_mut(ok)
        .instructions
        .push(VccInst::AssertPtrAccess {
            ptr,
            size: VccValue::Imm(8),
            op: "pointer access",
        });
    func.block_mut(ok).terminator = VccTerminator::Return { value: None };
    func.block_mut(bad).terminator = VccTerminator::Return { value: None };

    let seed = HashMap::from([(
        ptr,
        VccValueType::Ptr(VccPointerInfo {
            space: VccAddrSpace::Unknown,
            nullability: VccNullability::NonNull,
            bounds: None,
            packet_root: None,
            packet_root_field: None,
            packet_ctx_field: None,
            packet_end: false,
            context_buffer_root: None,
            context_buffer_end: false,
            ringbuf_ref: None,
            kfunc_ref: None,
        }),
    )]);

    VccVerifier::default()
        .verify_function_with_seed(&func, seed)
        .expect("null wildcard pointer join should preserve concrete pointer space");
}

#[test]
fn test_verify_mir_joined_typed_null_copy_preserves_pointer_nullability() {
    let (mut func, entry) = new_mir_function();
    let with_ptr = func.alloc_block();
    let with_null = func.alloc_block();
    let join = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();
    func.param_count = 1;

    let selector = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let loaded = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::Local);

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(selector),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: with_ptr,
        if_false: with_null,
    };

    func.block_mut(with_ptr).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(with_ptr).terminator = MirInst::Jump { target: join };

    func.block_mut(with_null).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::Const(0),
    });
    func.block_mut(with_null).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(join).terminator = MirInst::Branch {
        cond,
        if_true: ok,
        if_false: bad,
    };

    func.block_mut(ok).instructions.push(MirInst::Load {
        dst: loaded,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(ok).terminator = MirInst::Return { val: None };
    func.block_mut(bad).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(selector, MirType::I64);
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(loaded, MirType::I64);

    verify_mir(&func, &types)
        .expect("typed null-pointer branch join should remain nullable pointer");
}

#[test]
fn test_constant_false_branch_prunes_true_path() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let bad = func.alloc_block();
    let done = func.alloc_block();
    let cond = func.alloc_reg();
    let p0 = func.alloc_reg();
    let p1 = func.alloc_reg();
    let out = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::Const {
        dst: cond,
        value: 0,
    });
    func.block_mut(entry).terminator = VccTerminator::Branch {
        cond: VccValue::Reg(cond),
        if_true: bad,
        if_false: done,
    };
    func.block_mut(bad).instructions.push(VccInst::StackAddr {
        dst: p0,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(bad).instructions.push(VccInst::StackAddr {
        dst: p1,
        slot: StackSlotId(1),
        size: 16,
    });
    // This pointer binop would be rejected if the branch were reachable.
    func.block_mut(bad).instructions.push(VccInst::BinOp {
        dst: out,
        op: VccBinOp::Add,
        lhs: VccValue::Reg(p0),
        rhs: VccValue::Reg(p1),
    });

    verify_ok(&func);
}

#[test]
fn test_dynptr_require_initialized_after_mark() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let ptr = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: ptr,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrMarkInitialized {
            ptr,
            kfunc: "unknown_dynptr_init".to_string(),
            arg_idx: 0,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrRequireInitialized {
            ptr,
            kfunc: "unknown_dynptr_use".to_string(),
            arg_idx: 0,
        });

    verify_ok(&func);
}

#[test]
fn test_dynptr_require_initialized_rejects_uninitialized() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let ptr = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: ptr,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrRequireInitialized {
            ptr,
            kfunc: "unknown_dynptr_use".to_string(),
            arg_idx: 0,
        });

    verify_err(&func, VccErrorKind::PointerBounds);
}

#[test]
fn test_dynptr_copy_requires_distinct_slots() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let src = func.alloc_reg();
    let dst = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: src,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrMarkInitialized {
            ptr: src,
            kfunc: "unknown_dynptr_init".to_string(),
            arg_idx: 0,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrCopy {
            src,
            dst,
            kfunc: "unknown_dynptr_copy".to_string(),
            src_arg_idx: 0,
            dst_arg_idx: 1,
            move_semantics: false,
        });

    verify_err(&func, VccErrorKind::PointerBounds);
}

#[test]
fn test_dynptr_copy_propagates_initialized_state() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let src = func.alloc_reg();
    let dst = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: src,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst,
        slot: StackSlotId(1),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrMarkInitialized {
            ptr: src,
            kfunc: "unknown_dynptr_init".to_string(),
            arg_idx: 0,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrCopy {
            src,
            dst,
            kfunc: "unknown_dynptr_copy".to_string(),
            src_arg_idx: 0,
            dst_arg_idx: 1,
            move_semantics: false,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrRequireInitialized {
            ptr: dst,
            kfunc: "unknown_dynptr_use".to_string(),
            arg_idx: 0,
        });

    verify_ok(&func);
}

#[test]
fn test_dynptr_mark_initialized_rejects_reinit_of_live_slot() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let ptr = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: ptr,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrMarkInitialized {
            ptr,
            kfunc: "unknown_dynptr_init".to_string(),
            arg_idx: 0,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrMarkInitialized {
            ptr,
            kfunc: "unknown_dynptr_init".to_string(),
            arg_idx: 0,
        });

    let err = VccVerifier::default()
        .verify_function(&func)
        .expect_err("expected dynptr reinit verifier error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "kfunc 'unknown_dynptr_init' arg0 requires uninitialized dynptr stack object slot",
        )),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_dynptr_move_transfers_initialized_state() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let src = func.alloc_reg();
    let dst = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: src,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst,
        slot: StackSlotId(1),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrMarkInitialized {
            ptr: src,
            kfunc: "unknown_dynptr_init".to_string(),
            arg_idx: 0,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrCopy {
            src,
            dst,
            kfunc: "unknown_dynptr_move".to_string(),
            src_arg_idx: 0,
            dst_arg_idx: 1,
            move_semantics: true,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrRequireInitialized {
            ptr: dst,
            kfunc: "unknown_dynptr_use".to_string(),
            arg_idx: 0,
        });

    verify_ok(&func);
}

#[test]
fn test_dynptr_move_invalidates_source() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let src = func.alloc_reg();
    let dst = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: src,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst,
        slot: StackSlotId(1),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrMarkInitialized {
            ptr: src,
            kfunc: "unknown_dynptr_init".to_string(),
            arg_idx: 0,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrCopy {
            src,
            dst,
            kfunc: "unknown_dynptr_move".to_string(),
            src_arg_idx: 0,
            dst_arg_idx: 1,
            move_semantics: true,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrRequireInitialized {
            ptr: src,
            kfunc: "unknown_dynptr_use".to_string(),
            arg_idx: 0,
        });

    verify_err(&func, VccErrorKind::PointerBounds);
}

#[test]
fn test_dynptr_copy_does_not_initialize_from_uninitialized_source() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let src = func.alloc_reg();
    let dst = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: src,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst,
        slot: StackSlotId(1),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrCopy {
            src,
            dst,
            kfunc: "unknown_dynptr_copy".to_string(),
            src_arg_idx: 0,
            dst_arg_idx: 1,
            move_semantics: false,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrRequireInitialized {
            ptr: dst,
            kfunc: "unknown_dynptr_use".to_string(),
            arg_idx: 0,
        });

    verify_err(&func, VccErrorKind::PointerBounds);
}

#[test]
fn test_dynptr_copy_rejects_initialized_destination() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let src = func.alloc_reg();
    let dst = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: src,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst,
        slot: StackSlotId(1),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrMarkInitialized {
            ptr: src,
            kfunc: "unknown_dynptr_init".to_string(),
            arg_idx: 0,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrMarkInitialized {
            ptr: dst,
            kfunc: "unknown_dynptr_init".to_string(),
            arg_idx: 1,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::DynptrCopy {
            src,
            dst,
            kfunc: "unknown_dynptr_copy".to_string(),
            src_arg_idx: 0,
            dst_arg_idx: 1,
            move_semantics: false,
        });

    let err = VccVerifier::default()
        .verify_function(&func)
        .expect_err("expected dynptr copy-dst reinit verifier error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "kfunc 'unknown_dynptr_copy' arg1 requires uninitialized dynptr stack object slot",
        )),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_dynptr_initialized_slots_join_requires_all_paths() {
    let slot = StackSlotId(7);
    let mut initialized = VccState::with_seed(HashMap::new());
    initialized.initialize_dynptr_slot(slot);
    let uninitialized = VccState::with_seed(HashMap::new());

    let merged = initialized.merge_with(&uninitialized);
    assert!(
        !merged.is_dynptr_slot_initialized(slot),
        "dynptr slot initialization should require all incoming paths"
    );

    let merged_initialized = initialized.merge_with(&initialized);
    assert!(
        merged_initialized.is_dynptr_slot_initialized(slot),
        "dynptr slot initialization should be preserved when all paths initialize"
    );
}

#[test]
fn test_unknown_stack_object_slots_join_requires_all_paths() {
    let slot = StackSlotId(11);
    let mut initialized = VccState::with_seed(HashMap::new());
    initialized.initialize_unknown_stack_object_slot(slot, "bpf_wq", None);
    let uninitialized = VccState::with_seed(HashMap::new());

    let merged = initialized.merge_with(&uninitialized);
    assert!(
        !merged.has_unknown_stack_object_slot(slot, "bpf_wq", None),
        "unknown stack-object slot initialization should require all incoming paths"
    );

    let merged_initialized = initialized.merge_with(&initialized);
    assert!(
        merged_initialized.has_unknown_stack_object_slot(slot, "bpf_wq", None),
        "unknown stack-object slot initialization should be preserved when all paths initialize"
    );
}

#[test]
fn test_unknown_stack_object_slots_join_tracks_maybe_live_for_exit_checks() {
    let slot = StackSlotId(13);
    let mut initialized = VccState::with_seed(HashMap::new());
    initialized.initialize_unknown_stack_object_slot(slot, "bpf_wq", None);
    let uninitialized = VccState::with_seed(HashMap::new());

    let merged = initialized.merge_with(&uninitialized);
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
    let mut state = VccState::with_seed(HashMap::new());
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
    let mut state = VccState::with_seed(HashMap::new());
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
fn test_unknown_stack_object_destroy_requires_initialized() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let ptr = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: ptr,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectDestroy {
            ptr,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_destroy".to_string(),
            arg_idx: 0,
        });

    verify_err(&func, VccErrorKind::PointerBounds);
}

#[test]
fn test_unknown_stack_object_copy_propagates_initialized_state() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let src = func.alloc_reg();
    let dst = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: src,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst,
        slot: StackSlotId(1),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectInit {
            ptr: src,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_new".to_string(),
            arg_idx: 0,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectCopy {
            src,
            dst,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_copy".to_string(),
            src_arg_idx: 0,
            dst_arg_idx: 1,
            move_semantics: false,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectDestroy {
            ptr: dst,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_destroy".to_string(),
            arg_idx: 0,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectDestroy {
            ptr: src,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_destroy".to_string(),
            arg_idx: 0,
        });

    verify_ok(&func);
}

#[test]
fn test_unknown_stack_object_move_transfers_initialized_state() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let src = func.alloc_reg();
    let dst = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: src,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst,
        slot: StackSlotId(1),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectInit {
            ptr: src,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_new".to_string(),
            arg_idx: 0,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectCopy {
            src,
            dst,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_move".to_string(),
            src_arg_idx: 0,
            dst_arg_idx: 1,
            move_semantics: true,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectDestroy {
            ptr: dst,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_destroy".to_string(),
            arg_idx: 1,
        });

    verify_ok(&func);
}

#[test]
fn test_unknown_stack_object_move_invalidates_source() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let src = func.alloc_reg();
    let dst = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: src,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst,
        slot: StackSlotId(1),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectInit {
            ptr: src,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_new".to_string(),
            arg_idx: 0,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectCopy {
            src,
            dst,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_move".to_string(),
            src_arg_idx: 0,
            dst_arg_idx: 1,
            move_semantics: true,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectDestroy {
            ptr: src,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_destroy".to_string(),
            arg_idx: 0,
        });

    let err = VccVerifier::default()
        .verify_function(&func)
        .expect_err("expected moved source to be uninitialized");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'unknown_wq_destroy' arg0 requires initialized bpf_wq stack object")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_unknown_stack_object_copy_does_not_initialize_from_uninitialized_source() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let src = func.alloc_reg();
    let dst = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: src,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst,
        slot: StackSlotId(1),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectCopy {
            src,
            dst,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_copy".to_string(),
            src_arg_idx: 0,
            dst_arg_idx: 1,
            move_semantics: false,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectDestroy {
            ptr: dst,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_destroy".to_string(),
            arg_idx: 1,
        });

    let err = VccVerifier::default()
        .verify_function(&func)
        .expect_err("expected unknown stack-object source-init verifier errors");
    assert!(
        err.iter().any(|e| {
            e.message
                .contains("kfunc 'unknown_wq_copy' arg0 requires initialized bpf_wq stack object")
        }),
        "unexpected error messages: {:?}",
        err
    );
    assert!(
        err.iter().any(|e| {
            e.message.contains(
                "kfunc 'unknown_wq_destroy' arg1 requires initialized bpf_wq stack object",
            )
        }),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_unknown_stack_object_init_requires_release_before_return() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let ptr = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: ptr,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectInit {
            ptr,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_new".to_string(),
            arg_idx: 0,
        });

    let err = VccVerifier::default()
        .verify_function(&func)
        .expect_err("expected unknown stack-object leak at return");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("unreleased unknown stack object at function exit")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_unknown_stack_object_destroy_rejected_after_mixed_join() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let init = func.alloc_block();
    let skip = func.alloc_block();
    let join = func.alloc_block();
    let cond = func.alloc_reg();
    let ptr = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: ptr,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry).instructions.push(VccInst::Assume {
        dst: cond,
        ty: VccValueType::Scalar { range: None },
        ctx_field_source: None,
    });
    func.block_mut(entry).terminator = VccTerminator::Branch {
        cond: VccValue::Reg(cond),
        if_true: init,
        if_false: skip,
    };

    func.block_mut(init)
        .instructions
        .push(VccInst::UnknownStackObjectInit {
            ptr,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_new".to_string(),
            arg_idx: 0,
        });
    func.block_mut(init).terminator = VccTerminator::Jump { target: join };
    func.block_mut(skip).terminator = VccTerminator::Jump { target: join };

    func.block_mut(join)
        .instructions
        .push(VccInst::UnknownStackObjectDestroy {
            ptr,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_destroy".to_string(),
            arg_idx: 0,
        });

    let err = VccVerifier::default()
        .verify_function(&func)
        .expect_err("expected mixed-path unknown stack-object destroy rejection");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'unknown_wq_destroy' arg0 requires initialized bpf_wq stack object",)),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_unknown_stack_object_init_rejects_reinit_of_live_slot() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let ptr = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: ptr,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectInit {
            ptr,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_new".to_string(),
            arg_idx: 0,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectInit {
            ptr,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_new".to_string(),
            arg_idx: 0,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectDestroy {
            ptr,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_destroy".to_string(),
            arg_idx: 0,
        });

    let err = VccVerifier::default()
        .verify_function(&func)
        .expect_err("expected unknown stack-object reinit verifier error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "kfunc 'unknown_wq_new' arg0 requires uninitialized bpf_wq stack object slot",
        )),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_unknown_stack_object_copy_rejects_initialized_destination() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let src = func.alloc_reg();
    let dst = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: src,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst,
        slot: StackSlotId(1),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectInit {
            ptr: src,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_new".to_string(),
            arg_idx: 0,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectInit {
            ptr: dst,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_new".to_string(),
            arg_idx: 1,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectCopy {
            src,
            dst,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_copy".to_string(),
            src_arg_idx: 0,
            dst_arg_idx: 1,
            move_semantics: false,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectDestroy {
            ptr: src,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_destroy".to_string(),
            arg_idx: 0,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectDestroy {
            ptr: dst,
            type_name: "bpf_wq".to_string(),
            type_id: None,
            kfunc: "unknown_wq_destroy".to_string(),
            arg_idx: 1,
        });

    let err = VccVerifier::default()
        .verify_function(&func)
        .expect_err("expected unknown stack-object copy-dst reinit verifier error");
    assert!(
        err.iter().any(|e| e.message.contains(
            "kfunc 'unknown_wq_copy' arg1 requires uninitialized bpf_wq stack object slot",
        )),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_unknown_stack_object_destroy_rejects_type_id_mismatch() {
    let mut func = VccFunction::new();
    let entry = func.entry;
    let ptr = func.alloc_reg();

    func.block_mut(entry).instructions.push(VccInst::StackAddr {
        dst: ptr,
        slot: StackSlotId(0),
        size: 16,
    });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectInit {
            ptr,
            type_name: "bpf_wq".to_string(),
            type_id: Some(11),
            kfunc: "unknown_wq_new".to_string(),
            arg_idx: 0,
        });
    func.block_mut(entry)
        .instructions
        .push(VccInst::UnknownStackObjectDestroy {
            ptr,
            type_name: "bpf_wq".to_string(),
            type_id: Some(12),
            kfunc: "unknown_wq_destroy".to_string(),
            arg_idx: 0,
        });

    let err = VccVerifier::default()
        .verify_function(&func)
        .expect_err("expected unknown stack-object type-id mismatch verifier error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("kfunc 'unknown_wq_destroy' arg0 requires initialized bpf_wq stack object")),
        "unexpected error messages: {:?}",
        err
    );
}

fn new_mir_function() -> (MirFunction, BlockId) {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;
    (func, entry)
}

#[test]
fn test_verify_mir_string_append_literal_bounds() {
    let (mut func, entry) = new_mir_function();
    let buffer = func.alloc_stack_slot(8, 1, StackSlotKind::StringBuffer);
    let len = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: len,
        src: MirValue::Const(0),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::StringAppend {
            dst_buffer: buffer,
            dst_len: len,
            val: MirValue::Const(0),
            val_type: StringAppendType::Literal {
                bytes: vec![b'a', b'b', b'c'],
            },
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    assert!(verify_mir(&func, &HashMap::new()).is_ok());
}

#[test]
fn test_verify_mir_string_append_literal_oob() {
    let (mut func, entry) = new_mir_function();
    let buffer = func.alloc_stack_slot(8, 1, StackSlotKind::StringBuffer);
    let len = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: len,
        src: MirValue::Const(0),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::StringAppend {
            dst_buffer: buffer,
            dst_len: len,
            val: MirValue::Const(0),
            val_type: StringAppendType::Literal {
                bytes: vec![0u8; 9],
            },
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_string_append_slot_oob() {
    let (mut func, entry) = new_mir_function();
    let dst_buffer = func.alloc_stack_slot(16, 1, StackSlotKind::StringBuffer);
    let src_buffer = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
    let len = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: len,
        src: MirValue::Const(0),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::StringAppend {
            dst_buffer,
            dst_len: len,
            val: MirValue::Const(0),
            val_type: StringAppendType::StringSlot {
                slot: src_buffer,
                max_len: 8,
            },
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_int_to_string_buffer_oob() {
    let (mut func, entry) = new_mir_function();
    let buffer = func.alloc_stack_slot(8, 1, StackSlotKind::StringBuffer);
    let len = func.alloc_vreg();
    let val = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: val,
        src: MirValue::Const(42),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::IntToString {
            dst_buffer: buffer,
            dst_len: len,
            val,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_emit_event_requires_ptr() {
    let (mut func, entry) = new_mir_function();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let data = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: data,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::EmitEvent { data, size: 16 });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    assert!(verify_mir(&func, &HashMap::new()).is_ok());

    let (mut func, entry) = new_mir_function();
    let data = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: data,
        src: MirValue::Const(0),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::EmitEvent { data, size: 16 });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected pointer error");
    assert!(
        err.iter()
            .any(|e| matches!(e.kind, VccErrorKind::TypeMismatch { .. })),
        "expected type mismatch error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_strcmp_bounds() {
    let (mut func, entry) = new_mir_function();
    let lhs = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
    let rhs = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::StrCmp {
        dst,
        lhs,
        rhs,
        len: 8,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_map_lookup_requires_null_check_before_load() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let load_dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst,
        map: MapRef {
            name: "test".to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst: load_dst,
        ptr: dst,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let types = map_lookup_types(&func, dst);
    let err = verify_mir(&func, &types).expect_err("expected null-check error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("may dereference null pointer")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_map_lookup_null_check_then_load_ok() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let load_block = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let load_dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst,
        map: MapRef {
            name: "test".to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(dst),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: load_block,
        if_false: done,
    };

    func.block_mut(load_block).instructions.push(MirInst::Load {
        dst: load_dst,
        ptr: dst,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(load_block).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let types = map_lookup_types(&func, dst);
    verify_mir(&func, &types).expect("expected null-checked map lookup load to pass");
}

#[test]
fn test_verify_mir_map_value_bounds() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();
    let left = func.alloc_block();
    let right = func.alloc_block();
    let join = func.alloc_block();
    func.entry = entry;

    let split = func.alloc_vreg();
    func.param_count = 1;
    let key = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let off = func.alloc_vreg();
    let tmp_ptr = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: ptr,
        map: MapRef {
            name: COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: ok,
        if_false: bad,
    };

    func.block_mut(ok).terminator = MirInst::Branch {
        cond: split,
        if_true: left,
        if_false: right,
    };

    func.block_mut(left).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(0),
    });
    func.block_mut(left).terminator = MirInst::Jump { target: join };

    func.block_mut(right).instructions.push(MirInst::Copy {
        dst: off,
        src: MirValue::Const(4),
    });
    func.block_mut(right).terminator = MirInst::Jump { target: join };

    func.block_mut(join).instructions.push(MirInst::BinOp {
        dst: tmp_ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::VReg(off),
    });
    func.block_mut(join).instructions.push(MirInst::Load {
        dst,
        ptr: tmp_ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(join).terminator = MirInst::Return { val: None };
    func.block_mut(bad).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(
        tmp_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(split, MirType::I64);
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected map bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_unknown_map_uses_pointee_bounds_for_lookup_result() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: ptr,
        map: MapRef {
            name: "custom_map".to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: ok,
        if_false: bad,
    };

    func.block_mut(ok).instructions.push(MirInst::Load {
        dst,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(ok).terminator = MirInst::Return { val: None };
    func.block_mut(bad).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 4,
            }),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected map bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_unknown_map_pointee_bounds_allow_in_bounds_access() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let ok = func.alloc_block();
    let bad = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: ptr,
        map: MapRef {
            name: "custom_map".to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: ok,
        if_false: bad,
    };

    func.block_mut(ok).instructions.push(MirInst::Load {
        dst,
        ptr,
        offset: 0,
        ty: MirType::I32,
    });
    func.block_mut(ok).terminator = MirInst::Return { val: None };
    func.block_mut(bad).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::Array {
                elem: Box::new(MirType::U8),
                len: 8,
            }),
            address_space: AddressSpace::Map,
        },
    );
    types.insert(dst, MirType::I32);

    verify_mir(&func, &types).expect("expected in-bounds access");
}

#[test]
fn test_verify_mir_prunes_impossible_null_branch_for_non_null_pointer() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let bad = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let load_dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Eq,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: bad,
        if_false: done,
    };

    // This path is unreachable: stack pointers are non-null.
    func.block_mut(bad).instructions.push(MirInst::Load {
        dst: load_dst,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(bad).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(load_dst, MirType::I64);
    verify_mir(&func, &types).expect("expected impossible null branch to be pruned");
}

#[test]
fn test_verify_mir_load_rejects_user_ptr() {
    let (mut func, entry) = new_mir_function();
    let ptr = func.alloc_vreg();
    func.param_count = 1;
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Load {
        dst,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected user ptr load error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e.message.contains("load")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_stack_pointer_non_null() {
    let (mut func, entry) = new_mir_function();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("stack pointer should be non-null");
}

#[test]
fn test_verify_mir_stack_load_out_of_bounds() {
    let (mut func, entry) = new_mir_function();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst,
        ptr,
        offset: 8,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_stack_pointer_offset_in_bounds() {
    let (mut func, entry) = new_mir_function();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let tmp = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: tmp,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(8),
    });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst,
        ptr: tmp,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        tmp,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    verify_mir(&func, &types).expect("expected in-bounds access");
}

#[test]
fn test_verify_mir_stack_pointer_offset_via_mul_out_of_bounds() {
    let (mut func, entry) = new_mir_function();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let base = func.alloc_vreg();
    let scale = func.alloc_vreg();
    let offset = func.alloc_vreg();
    let tmp = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: base,
        src: MirValue::Const(3),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: scale,
        src: MirValue::Const(4),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: offset,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(base),
        rhs: MirValue::VReg(scale),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: tmp,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::VReg(offset),
    });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst,
        ptr: tmp,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        tmp,
        MirType::Ptr {
            pointee: Box::new(MirType::I64),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I64);

    let err = verify_mir(&func, &types).expect_err("expected bounds error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_read_str_rejects_non_user_ptr_for_user_space() {
    let (mut func, entry) = new_mir_function();
    let ptr = func.alloc_vreg();
    func.param_count = 1;
    let dst = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::ReadStr {
        dst,
        ptr,
        user_space: true,
        max_len: 16,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected read_str user ptr error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("read_str expects pointer in [User]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_read_str_user_ptr_requires_null_check_for_user_space() {
    let (mut func, entry) = new_mir_function();
    let ptr = func.alloc_vreg();
    func.param_count = 1;
    let dst = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::ReadStr {
        dst,
        ptr,
        user_space: true,
        max_len: 16,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected read_str null-check error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter()
            .any(|e| e.message.contains("may dereference null pointer")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_read_str_user_ptr_with_null_check_for_user_space() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();
    let ptr = func.alloc_vreg();
    func.param_count = 1;
    let cond = func.alloc_vreg();
    let dst = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call).instructions.push(MirInst::ReadStr {
        dst,
        ptr,
        user_space: true,
        max_len: 16,
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );

    verify_mir(&func, &types).expect("expected null-checked user-space read_str to pass");
}

#[test]
fn test_verify_mir_read_str_null_check_flows_to_reloaded_ctx_field() {
    let (mut func, entry) = new_mir_function();
    let call = func.alloc_block();
    let done = func.alloc_block();

    let ptr_for_cond = func.alloc_vreg();
    let ptr_for_read = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let dst = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ptr_for_cond,
            field: CtxField::TracepointField("filename".to_string()),
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Ne,
        lhs: MirValue::VReg(ptr_for_cond),
        rhs: MirValue::Const(0),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: call,
        if_false: done,
    };

    func.block_mut(call)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: ptr_for_read,
            field: CtxField::TracepointField("filename".to_string()),
            slot: None,
        });
    func.block_mut(call).instructions.push(MirInst::ReadStr {
        dst,
        ptr: ptr_for_read,
        user_space: true,
        max_len: 16,
    });
    func.block_mut(call).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    for ptr in [ptr_for_cond, ptr_for_read] {
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::User,
            },
        );
    }
    types.insert(cond, MirType::Bool);

    verify_mir(&func, &types).expect("expected null check to flow across reloaded context field");
}

#[test]
fn test_verify_mir_read_str_rejects_user_ptr_for_kernel_space() {
    let (mut func, entry) = new_mir_function();
    let ptr = func.alloc_vreg();
    func.param_count = 1;
    let dst = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::ReadStr {
        dst,
        ptr,
        user_space: false,
        max_len: 16,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected read_str kernel ptr-space error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
    assert!(
        err.iter().any(|e| e
            .message
            .contains("read_str expects pointer in [Stack, Map, Kernel]")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_helper_pointer_arg_required() {
    let (mut func, entry) = new_mir_function();
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
            .any(|e| e.message.contains("helper 16 arg0 expects pointer value")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_prune_impossible_const_compare_branch() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let impossible = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
    let ptr = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let cmp = func.alloc_vreg();
    let tmp_ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: idx,
        src: MirValue::Const(5),
    });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cmp,
        op: BinOpKind::Lt,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::Const(4),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: cmp,
        if_true: impossible,
        if_false: done,
    };

    func.block_mut(impossible)
        .instructions
        .push(MirInst::BinOp {
            dst: tmp_ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::VReg(idx),
        });
    func.block_mut(impossible).instructions.push(MirInst::Load {
        dst,
        ptr: tmp_ptr,
        offset: 0,
        ty: MirType::I8,
    });
    func.block_mut(impossible).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(
        tmp_ptr,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Stack,
        },
    );
    types.insert(dst, MirType::I8);

    verify_mir(&func, &types).expect("expected impossible branch to be pruned");
}

#[test]
fn test_verify_mir_packet_load_with_data_end_guard_passes() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let load = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let data = func.alloc_vreg();
    let access_end = func.alloc_vreg();
    let data_end = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: access_end,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(data),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data_end,
            field: CtxField::DataEnd,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Le,
        lhs: MirValue::VReg(access_end),
        rhs: MirValue::VReg(data_end),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: load,
        if_false: done,
    };

    func.block_mut(load).instructions.push(MirInst::Load {
        dst,
        ptr: data,
        offset: 0,
        ty: MirType::U8,
    });
    func.block_mut(load).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let packet_ptr = MirType::Ptr {
        pointee: Box::new(MirType::U8),
        address_space: AddressSpace::Packet,
    };
    let mut types = HashMap::new();
    types.insert(data, packet_ptr.clone());
    types.insert(access_end, packet_ptr.clone());
    types.insert(data_end, packet_ptr);
    types.insert(cond, MirType::Bool);
    types.insert(dst, MirType::U8);

    verify_mir(&func, &types).expect("guarded packet byte load should verify in VCC");
}

#[test]
fn test_verify_mir_packet_store_with_data_end_guard_passes() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let store = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let data = func.alloc_vreg();
    let access_end = func.alloc_vreg();
    let data_end = func.alloc_vreg();
    let cond = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: access_end,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(data),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data_end,
            field: CtxField::DataEnd,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Le,
        lhs: MirValue::VReg(access_end),
        rhs: MirValue::VReg(data_end),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: store,
        if_false: done,
    };

    func.block_mut(store).instructions.push(MirInst::Store {
        ptr: data,
        offset: 0,
        val: MirValue::Const(0xff),
        ty: MirType::U8,
    });
    func.block_mut(store).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let packet_ptr = MirType::Ptr {
        pointee: Box::new(MirType::U8),
        address_space: AddressSpace::Packet,
    };
    let mut types = HashMap::new();
    types.insert(data, packet_ptr.clone());
    types.insert(access_end, packet_ptr.clone());
    types.insert(data_end, packet_ptr);
    types.insert(cond, MirType::Bool);

    verify_mir(&func, &types).expect("guarded packet byte store should verify in VCC");
}

#[test]
fn test_verify_mir_packet_metadata_load_with_data_guard_passes() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let load = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let data_meta = func.alloc_vreg();
    let access_end = func.alloc_vreg();
    let data = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data_meta,
            field: CtxField::DataMeta,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: access_end,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(data_meta),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Le,
        lhs: MirValue::VReg(access_end),
        rhs: MirValue::VReg(data),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: load,
        if_false: done,
    };

    func.block_mut(load).instructions.push(MirInst::Load {
        dst,
        ptr: data_meta,
        offset: 0,
        ty: MirType::U8,
    });
    func.block_mut(load).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let packet_ptr = MirType::Ptr {
        pointee: Box::new(MirType::U8),
        address_space: AddressSpace::Packet,
    };
    let mut types = HashMap::new();
    types.insert(data_meta, packet_ptr.clone());
    types.insert(access_end, packet_ptr.clone());
    types.insert(data, packet_ptr);
    types.insert(cond, MirType::Bool);
    types.insert(dst, MirType::U8);

    verify_mir(&func, &types).expect("guarded packet metadata byte load should verify in VCC");
}

#[test]
fn test_verify_mir_packet_load_without_data_end_guard_fails() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let data = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::Load {
        dst,
        ptr: data,
        offset: 0,
        ty: MirType::U8,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        data,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        },
    );
    types.insert(dst, MirType::U8);

    let err = verify_mir(&func, &types).expect_err("unguarded packet load should fail in VCC");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_packet_store_without_data_end_guard_fails() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let data = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::Store {
        ptr: data,
        offset: 0,
        val: MirValue::Const(0xff),
        ty: MirType::U8,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut types = HashMap::new();
    types.insert(
        data,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::Packet,
        },
    );

    let err = verify_mir(&func, &types).expect_err("unguarded packet store should fail in VCC");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}

#[test]
fn test_verify_mir_packet_load_rejects_guard_that_is_too_small() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let load = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let data = func.alloc_vreg();
    let access_end = func.alloc_vreg();
    let data_end = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data,
            field: CtxField::Data,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: access_end,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(data),
        rhs: MirValue::Const(1),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::LoadCtxField {
            dst: data_end,
            field: CtxField::DataEnd,
            slot: None,
        });
    func.block_mut(entry).instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Le,
        lhs: MirValue::VReg(access_end),
        rhs: MirValue::VReg(data_end),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true: load,
        if_false: done,
    };

    func.block_mut(load).instructions.push(MirInst::Load {
        dst,
        ptr: data,
        offset: 0,
        ty: MirType::U16,
    });
    func.block_mut(load).terminator = MirInst::Jump { target: done };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let packet_ptr = MirType::Ptr {
        pointee: Box::new(MirType::U8),
        address_space: AddressSpace::Packet,
    };
    let mut types = HashMap::new();
    types.insert(data, packet_ptr.clone());
    types.insert(access_end, packet_ptr.clone());
    types.insert(data_end, packet_ptr);
    types.insert(cond, MirType::Bool);
    types.insert(dst, MirType::U16);

    let err = verify_mir(&func, &types).expect_err("undersized packet guard should fail in VCC");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds),
        "expected pointer bounds error, got {:?}",
        err
    );
}
