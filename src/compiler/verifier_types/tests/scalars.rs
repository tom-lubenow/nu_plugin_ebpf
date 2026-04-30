use super::*;

#[test]
fn test_histogram_rejects_pointer_value() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let value = func.alloc_vreg();
    let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: value,
        src: MirValue::StackSlot(slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::Histogram { value });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected histogram scalar error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("histogram expects scalar")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_list_push_rejects_pointer_item() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let list = func.alloc_vreg();
    let item = func.alloc_vreg();
    let list_slot = func.alloc_stack_slot(40, 8, StackSlotKind::ListBuffer);
    let item_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::ListNew {
        dst: list,
        buffer: list_slot,
        max_len: 4,
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: item,
        src: MirValue::StackSlot(item_slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::ListPush { list, item });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected list item scalar error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("list push item expects scalar")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_list_get_rejects_pointer_index() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let list = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let dst = func.alloc_vreg();
    let list_slot = func.alloc_stack_slot(40, 8, StackSlotKind::ListBuffer);
    let idx_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::ListNew {
        dst: list,
        buffer: list_slot,
        max_len: 4,
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: idx,
        src: MirValue::StackSlot(idx_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::ListGet {
        dst,
        list,
        idx: MirValue::VReg(idx),
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected list index scalar error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("list index expects scalar")),
        "unexpected errors: {:?}",
        err
    );
}
