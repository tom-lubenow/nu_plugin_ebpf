use super::*;
use crate::compiler::type_infer::validate_program_capabilities_for_info;
use crate::compiler::{EbpfProgramType, MapRef, ProgramCapability, ProgramTypeInfo};
use std::collections::HashMap;

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
fn test_stack_pointer_add_with_bounded_loop_counter() {
    let mut func = make_test_function();
    let list = func.alloc_vreg();
    let counter = func.alloc_vreg();
    let scaled = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let loaded = func.alloc_vreg();

    let header = func.alloc_block();
    let body = func.alloc_block();
    let exit = func.alloc_block();
    let slot = func.alloc_stack_slot(24, 8, StackSlotKind::ListBuffer);

    let entry = func.block_mut(BlockId(0));
    entry.instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 2,
    });
    entry.instructions.push(MirInst::Copy {
        dst: counter,
        src: MirValue::Const(0),
    });
    entry.terminator = MirInst::Jump { target: header };

    func.block_mut(header).terminator = MirInst::LoopHeader {
        counter,
        start: 0,
        step: 1,
        limit: 2,
        body,
        exit,
    };

    let body_block = func.block_mut(body);
    body_block.instructions.push(MirInst::BinOp {
        dst: scaled,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(counter),
        rhs: MirValue::Const(8),
    });
    body_block.instructions.push(MirInst::BinOp {
        dst: ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(list),
        rhs: MirValue::VReg(scaled),
    });
    body_block.instructions.push(MirInst::Load {
        dst: loaded,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    body_block.terminator = MirInst::LoopBack {
        counter,
        step: 1,
        header,
    };

    func.block_mut(exit).terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(
        ti.infer(&func).is_ok(),
        "bounded loop counters should preserve stack-pointer offset ranges"
    );
}

#[test]
fn test_stack_pointer_add_with_descending_loop_counter() {
    let mut func = make_test_function();
    let list = func.alloc_vreg();
    let counter = func.alloc_vreg();
    let scaled = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let loaded = func.alloc_vreg();

    let header = func.alloc_block();
    let body = func.alloc_block();
    let exit = func.alloc_block();
    let slot = func.alloc_stack_slot(24, 8, StackSlotKind::ListBuffer);

    let entry = func.block_mut(BlockId(0));
    entry.instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 2,
    });
    entry.instructions.push(MirInst::Copy {
        dst: counter,
        src: MirValue::Const(1),
    });
    entry.terminator = MirInst::Jump { target: header };

    func.block_mut(header).terminator = MirInst::LoopHeader {
        counter,
        start: 1,
        step: -1,
        limit: -1,
        body,
        exit,
    };

    let body_block = func.block_mut(body);
    body_block.instructions.push(MirInst::BinOp {
        dst: scaled,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(counter),
        rhs: MirValue::Const(8),
    });
    body_block.instructions.push(MirInst::BinOp {
        dst: ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(list),
        rhs: MirValue::VReg(scaled),
    });
    body_block.instructions.push(MirInst::Load {
        dst: loaded,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    body_block.terminator = MirInst::LoopBack {
        counter,
        step: -1,
        header,
    };

    func.block_mut(exit).terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(
        ti.infer(&func).is_ok(),
        "descending loop counters should preserve stack-pointer offset ranges"
    );
}

#[test]
fn test_stack_pointer_add_with_loop_counter_mod_index() {
    let mut func = make_test_function();
    let list = func.alloc_vreg();
    let counter = func.alloc_vreg();
    let modded = func.alloc_vreg();
    let scaled = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let loaded = func.alloc_vreg();

    let header = func.alloc_block();
    let body = func.alloc_block();
    let exit = func.alloc_block();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::ListBuffer);

    let entry = func.block_mut(BlockId(0));
    entry.instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 2,
    });
    entry.instructions.push(MirInst::Copy {
        dst: counter,
        src: MirValue::Const(0),
    });
    entry.terminator = MirInst::Jump { target: header };

    func.block_mut(header).terminator = MirInst::LoopHeader {
        counter,
        start: 0,
        step: 1,
        limit: 2,
        body,
        exit,
    };

    let body_block = func.block_mut(body);
    body_block.instructions.push(MirInst::BinOp {
        dst: modded,
        op: BinOpKind::Mod,
        lhs: MirValue::VReg(counter),
        rhs: MirValue::Const(2),
    });
    body_block.instructions.push(MirInst::BinOp {
        dst: scaled,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(modded),
        rhs: MirValue::Const(8),
    });
    body_block.instructions.push(MirInst::BinOp {
        dst: ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(list),
        rhs: MirValue::VReg(scaled),
    });
    body_block.instructions.push(MirInst::Load {
        dst: loaded,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    body_block.terminator = MirInst::LoopBack {
        counter,
        step: 1,
        header,
    };

    func.block_mut(exit).terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(
        ti.infer(&func).is_ok(),
        "mod-derived loop indices should preserve stack-pointer offset ranges"
    );
}

#[test]
fn test_range_add_and_sub_clamp_instead_of_panicking_on_i64_overflow() {
    let ti = TypeInference::new(None);

    assert_eq!(
        ti.range_add(
            ValueRange::known(i64::MAX, i64::MAX),
            ValueRange::known(1, 1)
        ),
        ValueRange::known(i64::MAX, i64::MAX)
    );
    assert_eq!(
        ti.range_sub(
            ValueRange::known(i64::MIN, i64::MIN),
            ValueRange::known(1, 1)
        ),
        ValueRange::known(i64::MIN, i64::MIN)
    );
}

#[test]
fn test_stack_pointer_add_with_loop_counter_bitand_index() {
    let mut func = make_test_function();
    let list = func.alloc_vreg();
    let counter = func.alloc_vreg();
    let masked = func.alloc_vreg();
    let scaled = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let loaded = func.alloc_vreg();

    let header = func.alloc_block();
    let body = func.alloc_block();
    let exit = func.alloc_block();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::ListBuffer);

    let entry = func.block_mut(BlockId(0));
    entry.instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 2,
    });
    entry.instructions.push(MirInst::Copy {
        dst: counter,
        src: MirValue::Const(0),
    });
    entry.terminator = MirInst::Jump { target: header };

    func.block_mut(header).terminator = MirInst::LoopHeader {
        counter,
        start: 0,
        step: 1,
        limit: 2,
        body,
        exit,
    };

    let body_block = func.block_mut(body);
    body_block.instructions.push(MirInst::BinOp {
        dst: masked,
        op: BinOpKind::And,
        lhs: MirValue::VReg(counter),
        rhs: MirValue::Const(1),
    });
    body_block.instructions.push(MirInst::BinOp {
        dst: scaled,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(masked),
        rhs: MirValue::Const(8),
    });
    body_block.instructions.push(MirInst::BinOp {
        dst: ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(list),
        rhs: MirValue::VReg(scaled),
    });
    body_block.instructions.push(MirInst::Load {
        dst: loaded,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    body_block.terminator = MirInst::LoopBack {
        counter,
        step: 1,
        header,
    };

    func.block_mut(exit).terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(
        ti.infer(&func).is_ok(),
        "bitmask-derived loop indices should preserve stack-pointer offset ranges"
    );
}

#[test]
fn test_stack_pointer_add_with_ctx_u32_mod_index() {
    let mut func = make_test_function();
    let list = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let modded = func.alloc_vreg();
    let scaled = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let loaded = func.alloc_vreg();

    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::ListBuffer);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 2,
    });
    block.instructions.push(MirInst::LoadCtxField {
        dst: idx,
        field: CtxField::Pid,
        slot: None,
    });
    block.instructions.push(MirInst::BinOp {
        dst: modded,
        op: BinOpKind::Mod,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::Const(2),
    });
    block.instructions.push(MirInst::BinOp {
        dst: scaled,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(modded),
        rhs: MirValue::Const(8),
    });
    block.instructions.push(MirInst::BinOp {
        dst: ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(list),
        rhs: MirValue::VReg(scaled),
    });
    block.instructions.push(MirInst::Load {
        dst: loaded,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(
        ti.infer(&func).is_ok(),
        "unsigned ctx-field ranges should bound mod-derived indices"
    );
}

#[test]
fn test_stack_pointer_add_with_u32_load_slot_mod_index() {
    let mut func = make_test_function();
    let list = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let modded = func.alloc_vreg();
    let scaled = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let loaded = func.alloc_vreg();

    let list_slot = func.alloc_stack_slot(16, 8, StackSlotKind::ListBuffer);
    let scalar_slot = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::ListNew {
        dst: list,
        buffer: list_slot,
        max_len: 2,
    });
    block.instructions.push(MirInst::StoreSlot {
        slot: scalar_slot,
        offset: 0,
        val: MirValue::Const(7),
        ty: MirType::U32,
    });
    block.instructions.push(MirInst::LoadSlot {
        dst: idx,
        slot: scalar_slot,
        offset: 0,
        ty: MirType::U32,
    });
    block.instructions.push(MirInst::BinOp {
        dst: modded,
        op: BinOpKind::Mod,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::Const(2),
    });
    block.instructions.push(MirInst::BinOp {
        dst: scaled,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(modded),
        rhs: MirValue::Const(8),
    });
    block.instructions.push(MirInst::BinOp {
        dst: ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(list),
        rhs: MirValue::VReg(scaled),
    });
    block.instructions.push(MirInst::Load {
        dst: loaded,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(
        ti.infer(&func).is_ok(),
        "unsigned load-slot ranges should bound mod-derived indices"
    );
}

#[test]
fn test_stack_pointer_add_with_branch_refined_ctx_u32_minus_one_mod_index() {
    let mut func = make_test_function();
    let list = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let dec = func.alloc_vreg();
    let modded = func.alloc_vreg();
    let scaled = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let loaded = func.alloc_vreg();

    let then_block = func.alloc_block();
    let exit = func.alloc_block();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::ListBuffer);

    let entry = func.block_mut(BlockId(0));
    entry.instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 2,
    });
    entry.instructions.push(MirInst::LoadCtxField {
        dst: idx,
        field: CtxField::Pid,
        slot: None,
    });
    entry.instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Gt,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::Const(0),
    });
    entry.terminator = MirInst::Branch {
        cond,
        if_true: then_block,
        if_false: exit,
    };

    let body_block = func.block_mut(then_block);
    body_block.instructions.push(MirInst::BinOp {
        dst: dec,
        op: BinOpKind::Sub,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::Const(1),
    });
    body_block.instructions.push(MirInst::BinOp {
        dst: modded,
        op: BinOpKind::Mod,
        lhs: MirValue::VReg(dec),
        rhs: MirValue::Const(2),
    });
    body_block.instructions.push(MirInst::BinOp {
        dst: scaled,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(modded),
        rhs: MirValue::Const(8),
    });
    body_block.instructions.push(MirInst::BinOp {
        dst: ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(list),
        rhs: MirValue::VReg(scaled),
    });
    body_block.instructions.push(MirInst::Load {
        dst: loaded,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    body_block.terminator = MirInst::Jump { target: exit };

    func.block_mut(exit).terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(
        ti.infer(&func).is_ok(),
        "true-branch compare refinement should make ctx-field subtraction non-negative"
    );
}

#[test]
fn test_stack_pointer_add_with_branch_refined_reloaded_ctx_u32_minus_one_mod_index() {
    let mut func = make_test_function();
    let list = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let reloaded = func.alloc_vreg();
    let dec = func.alloc_vreg();
    let modded = func.alloc_vreg();
    let scaled = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let loaded = func.alloc_vreg();

    let then_block = func.alloc_block();
    let exit = func.alloc_block();
    let slot = func.alloc_stack_slot(16, 8, StackSlotKind::ListBuffer);

    let entry = func.block_mut(BlockId(0));
    entry.instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 2,
    });
    entry.instructions.push(MirInst::LoadCtxField {
        dst: idx,
        field: CtxField::Pid,
        slot: None,
    });
    entry.instructions.push(MirInst::BinOp {
        dst: cond,
        op: BinOpKind::Gt,
        lhs: MirValue::VReg(idx),
        rhs: MirValue::Const(0),
    });
    entry.terminator = MirInst::Branch {
        cond,
        if_true: then_block,
        if_false: exit,
    };

    let body_block = func.block_mut(then_block);
    body_block.instructions.push(MirInst::LoadCtxField {
        dst: reloaded,
        field: CtxField::Pid,
        slot: None,
    });
    body_block.instructions.push(MirInst::BinOp {
        dst: dec,
        op: BinOpKind::Sub,
        lhs: MirValue::VReg(reloaded),
        rhs: MirValue::Const(1),
    });
    body_block.instructions.push(MirInst::BinOp {
        dst: modded,
        op: BinOpKind::Mod,
        lhs: MirValue::VReg(dec),
        rhs: MirValue::Const(2),
    });
    body_block.instructions.push(MirInst::BinOp {
        dst: scaled,
        op: BinOpKind::Mul,
        lhs: MirValue::VReg(modded),
        rhs: MirValue::Const(8),
    });
    body_block.instructions.push(MirInst::BinOp {
        dst: ptr,
        op: BinOpKind::Add,
        lhs: MirValue::VReg(list),
        rhs: MirValue::VReg(scaled),
    });
    body_block.instructions.push(MirInst::Load {
        dst: loaded,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    body_block.terminator = MirInst::Jump { target: exit };

    func.block_mut(exit).terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    assert!(
        ti.infer(&func).is_ok(),
        "true-branch compare refinement should apply to reloaded ctx fields too"
    );
}

#[test]
fn test_stack_pointer_add_with_branch_refined_reloaded_probe_read_path_minus_one_mod_index() {
    let mut func = make_test_function();
    let list = func.alloc_vreg();
    let root = func.alloc_vreg();
    let field_ptr = func.alloc_vreg();
    let nested_ptr = func.alloc_vreg();
    let scalar_ptr = func.alloc_vreg();
    let loaded_scalar = func.alloc_vreg();
    let cond = func.alloc_vreg();

    let root2 = func.alloc_vreg();
    let field_ptr2 = func.alloc_vreg();
    let nested_ptr2 = func.alloc_vreg();
    let scalar_ptr2 = func.alloc_vreg();
    let reloaded_scalar = func.alloc_vreg();
    let dec = func.alloc_vreg();
    let modded = func.alloc_vreg();
    let scaled = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let loaded = func.alloc_vreg();

    let then_block = func.alloc_block();
    let exit = func.alloc_block();

    let list_slot = func.alloc_stack_slot(16, 8, StackSlotKind::ListBuffer);
    let ptr_slot = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let scalar_slot = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let ptr_slot2 = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let scalar_slot2 = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let read_ptr_status = func.alloc_vreg();
    let read_scalar_status = func.alloc_vreg();
    let read_ptr_status2 = func.alloc_vreg();
    let read_scalar_status2 = func.alloc_vreg();

    let nested_ptr_ty = MirType::Ptr {
        pointee: Box::new(MirType::I64),
        address_space: AddressSpace::Kernel,
    };
    let generic_kernel_ptr = MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::Kernel,
    };

    {
        let entry = func.block_mut(BlockId(0));
        entry.instructions.push(MirInst::ListNew {
            dst: list,
            buffer: list_slot,
            max_len: 2,
        });
        entry.instructions.push(MirInst::LoadCtxField {
            dst: root,
            field: CtxField::Arg(0),
            slot: None,
        });
        entry.instructions.push(MirInst::BinOp {
            dst: field_ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(root),
            rhs: MirValue::Const(8),
        });
        entry.instructions.push(MirInst::CallHelper {
            dst: read_ptr_status,
            helper: BpfHelper::ProbeReadKernel as u32,
            args: vec![
                MirValue::StackSlot(ptr_slot),
                MirValue::Const(8),
                MirValue::VReg(field_ptr),
            ],
        });
        entry.instructions.push(MirInst::LoadSlot {
            dst: nested_ptr,
            slot: ptr_slot,
            offset: 0,
            ty: nested_ptr_ty.clone(),
        });
        entry.instructions.push(MirInst::BinOp {
            dst: scalar_ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(nested_ptr),
            rhs: MirValue::Const(4),
        });
        entry.instructions.push(MirInst::CallHelper {
            dst: read_scalar_status,
            helper: BpfHelper::ProbeReadKernel as u32,
            args: vec![
                MirValue::StackSlot(scalar_slot),
                MirValue::Const(4),
                MirValue::VReg(scalar_ptr),
            ],
        });
        entry.instructions.push(MirInst::LoadSlot {
            dst: loaded_scalar,
            slot: scalar_slot,
            offset: 0,
            ty: MirType::U32,
        });
        entry.instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Gt,
            lhs: MirValue::VReg(loaded_scalar),
            rhs: MirValue::Const(0),
        });
        entry.terminator = MirInst::Branch {
            cond,
            if_true: then_block,
            if_false: exit,
        };
    }

    {
        let then_entry = func.block_mut(then_block);
        then_entry.instructions.push(MirInst::LoadCtxField {
            dst: root2,
            field: CtxField::Arg(0),
            slot: None,
        });
        then_entry.instructions.push(MirInst::BinOp {
            dst: field_ptr2,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(root2),
            rhs: MirValue::Const(8),
        });
        then_entry.instructions.push(MirInst::CallHelper {
            dst: read_ptr_status2,
            helper: BpfHelper::ProbeReadKernel as u32,
            args: vec![
                MirValue::StackSlot(ptr_slot2),
                MirValue::Const(8),
                MirValue::VReg(field_ptr2),
            ],
        });
        then_entry.instructions.push(MirInst::LoadSlot {
            dst: nested_ptr2,
            slot: ptr_slot2,
            offset: 0,
            ty: nested_ptr_ty.clone(),
        });
        then_entry.instructions.push(MirInst::BinOp {
            dst: scalar_ptr2,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(nested_ptr2),
            rhs: MirValue::Const(4),
        });
        then_entry.instructions.push(MirInst::CallHelper {
            dst: read_scalar_status2,
            helper: BpfHelper::ProbeReadKernel as u32,
            args: vec![
                MirValue::StackSlot(scalar_slot2),
                MirValue::Const(4),
                MirValue::VReg(scalar_ptr2),
            ],
        });
        then_entry.instructions.push(MirInst::LoadSlot {
            dst: reloaded_scalar,
            slot: scalar_slot2,
            offset: 0,
            ty: MirType::U32,
        });
        then_entry.instructions.push(MirInst::BinOp {
            dst: dec,
            op: BinOpKind::Sub,
            lhs: MirValue::VReg(reloaded_scalar),
            rhs: MirValue::Const(1),
        });
        then_entry.instructions.push(MirInst::BinOp {
            dst: modded,
            op: BinOpKind::Mod,
            lhs: MirValue::VReg(dec),
            rhs: MirValue::Const(2),
        });
        then_entry.instructions.push(MirInst::BinOp {
            dst: scaled,
            op: BinOpKind::Mul,
            lhs: MirValue::VReg(modded),
            rhs: MirValue::Const(8),
        });
        then_entry.instructions.push(MirInst::BinOp {
            dst: ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(list),
            rhs: MirValue::VReg(scaled),
        });
        then_entry.instructions.push(MirInst::Load {
            dst: loaded,
            ptr,
            offset: 0,
            ty: MirType::I64,
        });
        then_entry.terminator = MirInst::Jump { target: exit };
    }

    func.block_mut(exit).terminator = MirInst::Return { val: None };

    let mut hints = HashMap::new();
    hints.insert(field_ptr, generic_kernel_ptr.clone());
    hints.insert(scalar_ptr, generic_kernel_ptr.clone());
    hints.insert(field_ptr2, generic_kernel_ptr.clone());
    hints.insert(scalar_ptr2, generic_kernel_ptr);

    let ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");
    let mut ti = TypeInference::new_with_env(Some(ctx), None, None, Some(&hints), None);
    let result = ti.infer(&func);
    assert!(
        result.is_ok(),
        "true-branch refinement should apply to reloaded helper-backed typed paths: {:?}",
        result.err()
    );
}

#[test]
fn test_stack_pointer_add_with_branch_refined_copied_probe_read_path_minus_one_mod_index() {
    let mut func = make_test_function();
    let list = func.alloc_vreg();
    let root = func.alloc_vreg();
    let field_ptr = func.alloc_vreg();
    let nested_ptr = func.alloc_vreg();
    let scalar_ptr = func.alloc_vreg();
    let loaded_scalar = func.alloc_vreg();
    let bound_scalar = func.alloc_vreg();
    let cond_input = func.alloc_vreg();
    let cond = func.alloc_vreg();
    let reloaded_scalar = func.alloc_vreg();
    let dec = func.alloc_vreg();
    let modded = func.alloc_vreg();
    let scaled = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let loaded = func.alloc_vreg();

    let then_block = func.alloc_block();
    let exit = func.alloc_block();

    let list_slot = func.alloc_stack_slot(16, 8, StackSlotKind::ListBuffer);
    let ptr_slot = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let scalar_slot = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    let read_ptr_status = func.alloc_vreg();
    let read_scalar_status = func.alloc_vreg();

    let nested_ptr_ty = MirType::Ptr {
        pointee: Box::new(MirType::I64),
        address_space: AddressSpace::Kernel,
    };
    let generic_kernel_ptr = MirType::Ptr {
        pointee: Box::new(MirType::Unknown),
        address_space: AddressSpace::Kernel,
    };

    {
        let entry = func.block_mut(BlockId(0));
        entry.instructions.push(MirInst::ListNew {
            dst: list,
            buffer: list_slot,
            max_len: 2,
        });
        entry.instructions.push(MirInst::LoadCtxField {
            dst: root,
            field: CtxField::Arg(0),
            slot: None,
        });
        entry.instructions.push(MirInst::BinOp {
            dst: field_ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(root),
            rhs: MirValue::Const(8),
        });
        entry.instructions.push(MirInst::CallHelper {
            dst: read_ptr_status,
            helper: BpfHelper::ProbeReadKernel as u32,
            args: vec![
                MirValue::StackSlot(ptr_slot),
                MirValue::Const(8),
                MirValue::VReg(field_ptr),
            ],
        });
        entry.instructions.push(MirInst::LoadSlot {
            dst: nested_ptr,
            slot: ptr_slot,
            offset: 0,
            ty: nested_ptr_ty.clone(),
        });
        entry.instructions.push(MirInst::BinOp {
            dst: scalar_ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(nested_ptr),
            rhs: MirValue::Const(4),
        });
        entry.instructions.push(MirInst::CallHelper {
            dst: read_scalar_status,
            helper: BpfHelper::ProbeReadKernel as u32,
            args: vec![
                MirValue::StackSlot(scalar_slot),
                MirValue::Const(4),
                MirValue::VReg(scalar_ptr),
            ],
        });
        entry.instructions.push(MirInst::LoadSlot {
            dst: loaded_scalar,
            slot: scalar_slot,
            offset: 0,
            ty: MirType::I64,
        });
        entry.instructions.push(MirInst::Copy {
            dst: bound_scalar,
            src: MirValue::VReg(loaded_scalar),
        });
        entry.instructions.push(MirInst::Copy {
            dst: cond_input,
            src: MirValue::VReg(bound_scalar),
        });
        entry.instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Gt,
            lhs: MirValue::VReg(cond_input),
            rhs: MirValue::Const(0),
        });
        entry.terminator = MirInst::Branch {
            cond,
            if_true: then_block,
            if_false: exit,
        };
    }

    {
        let then_entry = func.block_mut(then_block);
        then_entry.instructions.push(MirInst::Copy {
            dst: reloaded_scalar,
            src: MirValue::VReg(bound_scalar),
        });
        then_entry.instructions.push(MirInst::BinOp {
            dst: dec,
            op: BinOpKind::Sub,
            lhs: MirValue::VReg(reloaded_scalar),
            rhs: MirValue::Const(1),
        });
        then_entry.instructions.push(MirInst::BinOp {
            dst: modded,
            op: BinOpKind::Mod,
            lhs: MirValue::VReg(dec),
            rhs: MirValue::Const(2),
        });
        then_entry.instructions.push(MirInst::BinOp {
            dst: scaled,
            op: BinOpKind::Mul,
            lhs: MirValue::VReg(modded),
            rhs: MirValue::Const(8),
        });
        then_entry.instructions.push(MirInst::BinOp {
            dst: ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(list),
            rhs: MirValue::VReg(scaled),
        });
        then_entry.instructions.push(MirInst::Load {
            dst: loaded,
            ptr,
            offset: 0,
            ty: MirType::I64,
        });
        then_entry.terminator = MirInst::Jump { target: exit };
    }

    func.block_mut(exit).terminator = MirInst::Return { val: None };

    let mut hints = HashMap::new();
    hints.insert(field_ptr, generic_kernel_ptr.clone());
    hints.insert(scalar_ptr, generic_kernel_ptr);

    let ctx = ProbeContext::new(EbpfProgramType::Fentry, "do_close_on_exec");
    let mut ti = TypeInference::new_with_env(Some(ctx), None, None, Some(&hints), None);
    let result = ti.infer(&func);
    assert!(
        result.is_ok(),
        "true-branch refinement should apply when a helper-backed path is rebound and copied: {:?}",
        result.err()
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

#[test]
fn test_required_program_capability_classifies_counter_map_updates() {
    let inst = MirInst::MapUpdate {
        map: MapRef {
            name: COUNTER_MAP_NAME.to_string(),
            kind: MapKind::Hash,
        },
        key: VReg(0),
        val: VReg(1),
        flags: 0,
    };

    assert_eq!(
        TypeInference::required_program_capability(&inst),
        Some(ProgramCapability::Counters)
    );
}

#[test]
fn test_required_program_capability_classifies_generic_map_lookup() {
    let inst = MirInst::MapLookup {
        dst: VReg(2),
        map: MapRef {
            name: "shared_state".to_string(),
            kind: MapKind::Hash,
        },
        key: VReg(0),
    };

    assert_eq!(
        TypeInference::required_program_capability(&inst),
        Some(ProgramCapability::GenericMaps)
    );
}

#[test]
fn test_required_program_capability_classifies_stack_trace_ctx_load() {
    let inst = MirInst::LoadCtxField {
        dst: VReg(0),
        field: CtxField::KStack,
        slot: None,
    };

    assert_eq!(
        TypeInference::required_program_capability(&inst),
        Some(ProgramCapability::StackTraces)
    );
}

#[test]
fn test_required_program_capability_classifies_helper_calls() {
    let inst = MirInst::CallHelper {
        dst: VReg(0),
        helper: BpfHelper::GetCurrentPidTgid as u32,
        args: vec![],
    };

    assert_eq!(
        TypeInference::required_program_capability(&inst),
        Some(ProgramCapability::HelperCalls)
    );
}

#[test]
fn test_validate_program_capability_rejects_helpers_when_capability_missing() {
    const LIMITED_CAPABILITIES: &[ProgramCapability] = &[ProgramCapability::Emit];

    let limited_program = ProgramTypeInfo {
        supported_capabilities: LIMITED_CAPABILITIES,
        ..*EbpfProgramType::Kprobe.info()
    };
    let inst = MirInst::CallHelper {
        dst: VReg(0),
        helper: BpfHelper::GetCurrentPidTgid as u32,
        args: vec![],
    };
    let mut errors = Vec::new();

    TypeInference::validate_program_capability_for_info(&inst, &limited_program, &mut errors);

    assert_eq!(errors.len(), 1);
    assert!(errors[0].message.contains("helper calls"));
    assert!(errors[0].message.contains("kprobe programs"));
}

#[test]
fn test_validate_program_capability_rejects_kfuncs_when_capability_missing() {
    const LIMITED_CAPABILITIES: &[ProgramCapability] = &[ProgramCapability::Emit];

    let limited_program = ProgramTypeInfo {
        supported_capabilities: LIMITED_CAPABILITIES,
        ..*EbpfProgramType::Kprobe.info()
    };
    let inst = MirInst::CallKfunc {
        dst: VReg(0),
        kfunc: "bpf_task_release".to_string(),
        btf_id: None,
        args: vec![VReg(1)],
    };
    let mut errors = Vec::new();

    TypeInference::validate_program_capability_for_info(&inst, &limited_program, &mut errors);

    assert_eq!(errors.len(), 1);
    assert!(errors[0].message.contains("kfunc calls"));
    assert!(errors[0].message.contains("kprobe programs"));
}

#[test]
fn test_validate_program_capabilities_for_function_rejects_missing_tail_call_capability() {
    const LIMITED_CAPABILITIES: &[ProgramCapability] = &[ProgramCapability::Emit];

    let limited_program = ProgramTypeInfo {
        supported_capabilities: LIMITED_CAPABILITIES,
        ..*EbpfProgramType::Kprobe.info()
    };
    let mut func = make_test_function();

    func.block_mut(BlockId(0)).terminator = MirInst::TailCall {
        prog_map: MapRef {
            name: "dispatch".to_string(),
            kind: MapKind::ProgArray,
        },
        index: MirValue::Const(0),
    };

    let errors = validate_program_capabilities_for_info(&func, &limited_program)
        .expect_err("expected missing tail-call capability to be rejected");

    assert_eq!(errors.len(), 1);
    assert!(errors[0].message.contains("tail calls"));
    assert!(errors[0].message.contains("kprobe programs"));
}

#[test]
fn test_type_infer_rejects_array_map_delete() {
    let mut func = make_test_function();
    let key = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::MapDelete {
        map: MapRef {
            name: "slots".to_string(),
            kind: MapKind::Array,
        },
        key,
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errors = ti
        .infer(&func)
        .expect_err("array map delete should be rejected during validation");

    assert!(errors.iter().any(|e| {
        e.message
            .contains("map delete is not supported for array map kind")
            && e.message.contains("slots")
    }));
}

#[test]
fn test_type_infer_rejects_queue_map_lookup() {
    let mut func = make_test_function();
    let key = func.alloc_vreg();
    let dst = func.alloc_vreg();

    let block = func.block_mut(BlockId(0));
    block.instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    block.instructions.push(MirInst::MapLookup {
        dst,
        map: MapRef {
            name: "queue_lookup".to_string(),
            kind: MapKind::Queue,
        },
        key,
    });
    block.terminator = MirInst::Return { val: None };

    let mut ti = TypeInference::new(None);
    let errors = ti
        .infer(&func)
        .expect_err("queue map lookup should be rejected during validation");

    assert!(errors.iter().any(|e| {
        e.message
            .contains("map lookup is not supported for map kind Queue")
    }));
}
