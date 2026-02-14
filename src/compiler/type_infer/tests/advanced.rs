use super::*;

#[test]
fn test_infer_subfunction_schemes_rejects_recursive_calls_with_guidance() {
    let mut subfn = MirFunction::with_name("rec");
    subfn.param_count = 1;
    let entry = subfn.alloc_block();
    subfn.entry = entry;
    let arg = VReg(0);
    subfn
        .block_mut(entry)
        .instructions
        .push(MirInst::CallSubfn {
            dst: arg,
            subfn: SubfunctionId(0),
            args: vec![arg],
        });
    subfn.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::VReg(arg)),
    };

    let errs = infer_subfunction_schemes(&[subfn], None)
        .expect_err("expected recursive subfunction scheme inference to fail");
    assert!(errs.iter().any(|e| {
        e.message
            .contains("polymorphic recursion requires explicit type annotations")
    }));
}

#[test]
fn test_infer_subfunction_schemes_rejects_param_limit() {
    let mut subfn = MirFunction::with_name("too_many_params");
    subfn.param_count = 6;
    let entry = subfn.alloc_block();
    subfn.entry = entry;
    subfn.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let errs = infer_subfunction_schemes(&[subfn], None)
        .expect_err("expected subfunction param-limit error");
    assert!(
        errs.iter()
            .any(|e| e.message.contains("at most 5 arguments"))
    );
}

#[test]
fn test_type_error_pointer_add() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let v1 = func.alloc_vreg();
    let v2 = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::LoadCtxField {
        dst: v0,
        field: CtxField::Comm,
        slot: None,
    });
    block.instructions.push(MirInst::Copy {
        dst: v1,
        src: MirValue::VReg(v0),
    });
    block.instructions.push(MirInst::BinOp {
        dst: v2,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(v0),
        rhs: MirValue::VReg(v1),
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(ti.infer(&func).is_err());
}

#[test]
fn test_stack_pointer_add_bounded_offset() {
    let mut func = make_test_function();
    let list = func.alloc_vreg();
    let len = func.alloc_vreg();
    let scaled = func.alloc_vreg();
    let ptr = func.alloc_vreg();

    let slot = func.alloc_stack_slot(40, 8, StackSlotKind::ListBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 4,
    });
    block.instructions.push(MirInst::ListLen { dst: len, list });
    block.instructions.push(MirInst::BinOp {
        dst: scaled,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(len),
        rhs: MirValue::Const(8),
    });
    block.instructions.push(MirInst::BinOp {
        dst: ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(list),
        rhs: MirValue::VReg(scaled),
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(
        ti.infer(&func).is_ok(),
        "bounded stack pointer arithmetic should type-check"
    );
}

#[test]
fn test_stack_pointer_add_unbounded_offset_errors() {
    let mut func = make_test_function();
    let ptr = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let out = func.alloc_vreg();

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: ptr,
        src: MirValue::StackSlot(slot),
    });
    block.instructions.push(MirInst::LoadCtxField {
        dst: idx,
        field: CtxField::Pid,
        slot: None,
    });
    block.instructions.push(MirInst::BinOp {
        dst: out,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(ptr),
        rhs: MirValue::VReg(idx),
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(
        ti.infer(&func).is_err(),
        "unbounded stack pointer arithmetic should be rejected"
    );
}

#[test]
fn test_type_error_read_str_non_ptr() {
    use crate::compiler::mir::StackSlotKind;

    let mut func = make_test_function();
    let v0 = func.alloc_vreg();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(123),
    });
    block.instructions.push(MirInst::ReadStr {
        dst: slot,
        ptr: v0,
        user_space: false,
        max_len: 16,
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(ti.infer(&func).is_err());
}

#[test]
fn test_type_error_emit_record_string_scalar() {
    let mut func = make_test_function();
    let v0 = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: v0,
        src: MirValue::Const(7),
    });
    block.instructions.push(MirInst::EmitRecord {
        fields: vec![RecordFieldDef {
            name: "comm".to_string(),
            value: v0,
            ty: MirType::Array {
                elem: Box::new(MirType::U8),
                len: 16,
            },
        }],
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(ti.infer(&func).is_err());
}
