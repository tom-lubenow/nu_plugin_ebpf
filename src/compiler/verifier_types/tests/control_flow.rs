use super::*;
use crate::compiler::mir::UnaryOpKind;

#[test]
fn test_branch_rejects_unknown_condition() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let if_true = func.alloc_block();
    let if_false = func.alloc_block();
    func.entry = entry;
    func.param_count = 1;

    let cond = VReg(0);
    func.block_mut(entry).terminator = MirInst::Branch {
        cond,
        if_true,
        if_false,
    };
    func.block_mut(if_true).terminator = MirInst::Return { val: None };
    func.block_mut(if_false).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected branch condition error");
    assert!(
        err.iter().any(|e| e
            .message
            .contains("branch condition expects scalar or pointer")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_branch_on_pointer_refines_non_null_path() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let load_block = func.alloc_block();
    let done = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: ptr,
        map: MapRef {
            name: "values".to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: ptr,
        if_true: load_block,
        if_false: done,
    };

    func.block_mut(load_block).instructions.push(MirInst::Load {
        dst,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(load_block).terminator = MirInst::Return { val: None };
    func.block_mut(done).terminator = MirInst::Return { val: None };

    let types = map_lookup_types(&func, ptr);
    verify_mir(&func, &types).expect("expected direct pointer branch to refine non-null path");
}

#[test]
fn test_not_pointer_branch_refines_null_and_non_null_paths() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    let null_block = func.alloc_block();
    let load_block = func.alloc_block();
    func.entry = entry;

    let key = func.alloc_vreg();
    let ptr = func.alloc_vreg();
    let is_null = func.alloc_vreg();
    let dst = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: key,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::MapLookup {
        dst: ptr,
        map: MapRef {
            name: "values".to_string(),
            kind: MapKind::Hash,
        },
        key,
    });
    func.block_mut(entry).instructions.push(MirInst::UnaryOp {
        dst: is_null,
        op: UnaryOpKind::Not,
        src: MirValue::VReg(ptr),
    });
    func.block_mut(entry).terminator = MirInst::Branch {
        cond: is_null,
        if_true: null_block,
        if_false: load_block,
    };

    func.block_mut(null_block).terminator = MirInst::Return { val: None };
    func.block_mut(load_block).instructions.push(MirInst::Load {
        dst,
        ptr,
        offset: 0,
        ty: MirType::I64,
    });
    func.block_mut(load_block).terminator = MirInst::Return { val: None };

    let types = map_lookup_types(&func, ptr);
    verify_mir(&func, &types).expect("expected not-pointer branch to refine false path");
}

#[test]
fn test_tail_call_rejects_non_prog_array_map() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    func.block_mut(entry).terminator = MirInst::TailCall {
        prog_map: MapRef {
            name: "dispatch".to_string(),
            kind: MapKind::Hash,
        },
        index: MirValue::Const(0),
    };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected tail-call map error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("tail_call requires prog-array map")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_tail_call_rejects_pointer_index() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let index = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::Local);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: index,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry).terminator = MirInst::TailCall {
        prog_map: MapRef {
            name: "dispatch".to_string(),
            kind: MapKind::ProgArray,
        },
        index: MirValue::VReg(index),
    };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected tail-call index error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("tail_call index expects scalar")),
        "unexpected errors: {:?}",
        err
    );
}
