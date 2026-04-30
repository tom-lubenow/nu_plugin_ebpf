use super::*;
use crate::compiler::mir::RecordFieldDef;

#[test]
fn test_emit_record_rejects_scalar_for_array_field() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let value = func.alloc_vreg();
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: value,
        src: MirValue::Const(7),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::EmitRecord {
            fields: vec![RecordFieldDef {
                name: "bytes".to_string(),
                value,
                ty: MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: 16,
                },
            }],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected record pointer error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("emit record requires pointer type")),
        "unexpected errors: {:?}",
        err
    );
}

#[test]
fn test_emit_record_rejects_out_of_bounds_array_pointer() {
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
        .push(MirInst::EmitRecord {
            fields: vec![RecordFieldDef {
                name: "bytes".to_string(),
                value,
                ty: MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: 16,
                },
            }],
        });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let err = verify_mir(&func, &HashMap::new()).expect_err("expected record bounds error");
    assert!(
        err.iter()
            .any(|e| e.message.contains("emit record out of bounds")),
        "unexpected errors: {:?}",
        err
    );
}
