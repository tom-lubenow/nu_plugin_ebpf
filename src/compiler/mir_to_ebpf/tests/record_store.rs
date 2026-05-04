use super::*;

#[test]
fn test_record_store_scalar_compiles() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let record = func.alloc_stack_slot(16, 8, StackSlotKind::RecordField);
    let val = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: val,
        src: MirValue::Const(42),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::RecordStore {
            buffer: record,
            field_offset: 4,
            val: MirValue::VReg(val),
            ty: MirType::U32,
        });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };

    let result = compile_mir_to_ebpf(&program, None);
    if let Err(err) = result {
        panic!("scalar RecordStore should compile: {err:?}");
    }
}

#[test]
fn test_record_store_aggregate_pointer_compiles() {
    use crate::compiler::mir::*;

    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let source = func.alloc_stack_slot(16, 8, StackSlotKind::RecordField);
    let record = func.alloc_stack_slot(32, 8, StackSlotKind::RecordField);
    let source_ptr = func.alloc_vreg();
    let array_ty = MirType::Array {
        elem: Box::new(MirType::U8),
        len: 16,
    };

    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: source_ptr,
        src: MirValue::StackSlot(source),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::RecordStore {
            buffer: record,
            field_offset: 8,
            val: MirValue::VReg(source_ptr),
            ty: array_ty.clone(),
        });
    func.block_mut(entry).terminator = MirInst::Return {
        val: Some(MirValue::Const(0)),
    };

    let program = MirProgram {
        main: func,
        subfunctions: vec![],
    };
    let lir = lower_mir_to_lir(&program);
    let mut program_types = ProgramVregTypes::default();
    program_types.main.insert(
        source_ptr,
        MirType::Ptr {
            pointee: Box::new(array_ty),
            address_space: AddressSpace::Stack,
        },
    );

    let result = MirToEbpfCompiler::new_with_types(&lir, None, program_types).compile();
    if let Err(err) = result {
        panic!("aggregate RecordStore should compile: {err:?}");
    }
}
