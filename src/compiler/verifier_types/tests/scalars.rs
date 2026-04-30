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
