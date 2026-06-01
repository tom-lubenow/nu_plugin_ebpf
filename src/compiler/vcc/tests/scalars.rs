use super::*;

#[test]
fn test_verify_mir_histogram_rejects_pointer_value() {
    let (mut func, entry) = new_mir_function();

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
            .any(|e| matches!(e.kind, VccErrorKind::TypeMismatch { .. })
                && e.message.contains("histogram expects scalar")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_string_append_integer_rejects_pointer_value() {
    let (mut func, entry) = new_mir_function();

    let len = func.alloc_vreg();
    let value = func.alloc_vreg();
    let dst = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: len,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: value,
        src: MirValue::StackSlot(value_slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::StringAppend {
            dst_buffer: dst,
            dst_len: len,
            val: MirValue::VReg(value),
            val_type: StringAppendType::Integer,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected string append scalar error");
    assert!(
        err.iter()
            .any(|e| matches!(e.kind, VccErrorKind::TypeMismatch { .. })
                && e.message.contains("string append integer expects scalar")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_string_append_rejects_pointer_length() {
    let (mut func, entry) = new_mir_function();

    let len = func.alloc_vreg();
    let dst = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let len_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: len,
        src: MirValue::StackSlot(len_slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::StringAppend {
            dst_buffer: dst,
            dst_len: len,
            val: MirValue::Const(1),
            val_type: StringAppendType::Integer,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected string length scalar error");
    assert!(
        err.iter()
            .any(|e| matches!(e.kind, VccErrorKind::TypeMismatch { .. })
                && e.message.contains("string append length expects scalar")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_int_to_string_rejects_pointer_value() {
    let (mut func, entry) = new_mir_function();

    let len = func.alloc_vreg();
    let value = func.alloc_vreg();
    let dst = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
    let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: len,
        src: MirValue::Const(0),
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: value,
        src: MirValue::StackSlot(value_slot),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::IntToString {
            dst_buffer: dst,
            dst_len: len,
            val: value,
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected int string scalar error");
    assert!(
        err.iter()
            .any(|e| matches!(e.kind, VccErrorKind::TypeMismatch { .. })
                && e.message.contains("int to string value expects scalar")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_list_push_rejects_pointer_item() {
    let (mut func, entry) = new_mir_function();
    let list_slot = func.alloc_stack_slot(24, 8, StackSlotKind::ListBuffer);
    let item_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let list = func.alloc_vreg();
    let item = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::ListNew {
        dst: list,
        buffer: list_slot,
        max_len: 2,
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
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_list_get_rejects_pointer_index() {
    let (mut func, entry) = new_mir_function();
    let list_slot = func.alloc_stack_slot(24, 8, StackSlotKind::ListBuffer);
    let idx_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
    let list = func.alloc_vreg();
    let idx = func.alloc_vreg();
    let out = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::ListNew {
        dst: list,
        buffer: list_slot,
        max_len: 2,
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: idx,
        src: MirValue::StackSlot(idx_slot),
    });
    func.block_mut(entry).instructions.push(MirInst::ListGet {
        dst: out,
        list,
        idx: MirValue::VReg(idx),
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected list index scalar error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("list index expects scalar")),
        "unexpected error messages: {:?}",
        err
    );
}
