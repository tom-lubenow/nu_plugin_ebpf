use super::*;
use crate::compiler::mir::RecordFieldDef;

#[test]
fn test_verify_mir_emit_record_rejects_scalar_for_array_field() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| matches!(
            e.kind,
            VccErrorKind::TypeMismatch {
                expected: VccTypeClass::Ptr,
                ..
            }
        ) && e.message.contains("emit record requires pointer value")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_emit_record_rejects_user_pointer() {
    let (mut func, entry) = new_mir_function();
    let value = func.alloc_vreg();
    func.param_count = 1;

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

    let mut types = HashMap::new();
    types.insert(
        value,
        MirType::Ptr {
            pointee: Box::new(MirType::U8),
            address_space: AddressSpace::User,
        },
    );

    let err = verify_mir(&func, &types).expect_err("expected record pointer-space error");
    assert!(
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds
            && e.message
                .contains("emit record expects pointer in [Stack, Map], got User")),
        "unexpected error messages: {:?}",
        err
    );
}

#[test]
fn test_verify_mir_emit_record_rejects_out_of_bounds_array_pointer() {
    let (mut func, entry) = new_mir_function();
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
        err.iter().any(|e| e.kind == VccErrorKind::PointerBounds
            && e.message.contains("pointer access out of bounds")),
        "unexpected error messages: {:?}",
        err
    );
}
