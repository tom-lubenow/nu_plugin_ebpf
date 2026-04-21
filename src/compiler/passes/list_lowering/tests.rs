use super::*;
use crate::compiler::cfg::CFG;
use crate::compiler::mir::{AddressSpace, MirFunction, MirInst, MirType, MirValue, StackSlotKind};

fn collect_insts(func: &MirFunction) -> Vec<&MirInst> {
    let mut insts = Vec::new();
    for block in &func.blocks {
        for inst in &block.instructions {
            insts.push(inst);
        }
        insts.push(&block.terminator);
    }
    insts
}

#[test]
fn test_list_push_is_lowered() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(24, 8, StackSlotKind::ListBuffer);
    let list = func.alloc_vreg();
    let item = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 2,
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: item,
        src: MirValue::Const(7),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::ListPush { list, item });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let cfg = CFG::build(&func);
    let mut func = func;
    let pass = ListLowering;
    assert!(pass.run(&mut func, &cfg));

    let insts = collect_insts(&func);
    assert!(
        !insts
            .iter()
            .any(|inst| matches!(inst, MirInst::ListPush { .. })),
        "ListPush should be lowered"
    );
    assert!(
        insts
            .iter()
            .any(|inst| matches!(inst, MirInst::Branch { .. })),
        "ListPush lowering should insert a bounds branch"
    );
    assert!(
        insts.iter().any(|inst| matches!(
            inst,
            MirInst::StoreSlot {
                slot: lowered_slot,
                offset,
                ..
            } if *lowered_slot == slot && (*offset == 8 || *offset == 16)
        )),
        "ListPush lowering should emit slot stores for list elements"
    );
}

#[test]
fn test_list_get_const_is_lowered() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(32, 8, StackSlotKind::ListBuffer);
    let list = func.alloc_vreg();
    let out = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 3,
    });
    func.block_mut(entry).instructions.push(MirInst::ListGet {
        dst: out,
        list,
        idx: MirValue::Const(1),
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let cfg = CFG::build(&func);
    let mut func = func;
    let pass = ListLowering;
    assert!(pass.run(&mut func, &cfg));

    let insts = collect_insts(&func);
    assert!(
        !insts
            .iter()
            .any(|inst| matches!(inst, MirInst::ListGet { .. })),
        "ListGet should be lowered"
    );
    assert!(
        insts
            .iter()
            .any(|inst| matches!(inst, MirInst::LoadSlot { offset: 16, .. })),
        "ListGet constant index should load from constant offset"
    );
}

#[test]
fn test_emit_event_list_ptr_is_rematerialized() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(32, 8, StackSlotKind::ListBuffer);
    let list = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 3,
    });
    func.block_mut(entry).instructions.push(MirInst::EmitEvent {
        data: list,
        size: 24,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let cfg = CFG::build(&func);
    let mut func = func;
    let pass = ListLowering;
    assert!(pass.run(&mut func, &cfg));

    let insts = collect_insts(&func);
    let mut emit_data = None;
    for inst in &insts {
        if let MirInst::EmitEvent { data, .. } = inst {
            emit_data = Some(*data);
        }
    }
    let Some(data_vreg) = emit_data else {
        panic!("EmitEvent missing after lowering");
    };
    assert_ne!(
        data_vreg, list,
        "EmitEvent should use a rematerialized list pointer"
    );
    assert!(
        insts.iter().any(|inst| matches!(
            inst,
            MirInst::Copy {
                dst,
                src: MirValue::StackSlot(s),
            } if *dst == data_vreg && *s == slot
        )),
        "EmitEvent should be preceded by Copy from list stack slot"
    );
}

#[test]
fn test_run_with_type_hints_seeds_list_push_temps() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(24, 8, StackSlotKind::ListBuffer);
    let list = func.alloc_vreg();
    let item = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 2,
    });
    func.block_mut(entry).instructions.push(MirInst::Copy {
        dst: item,
        src: MirValue::Const(7),
    });
    func.block_mut(entry)
        .instructions
        .push(MirInst::ListPush { list, item });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut func = func;
    let pass = ListLowering;
    let mut hints = HashMap::new();
    assert!(pass.run_with_type_hints(&mut func, &mut hints));

    let list_ptr_ty = MirType::Ptr {
        pointee: Box::new(MirType::Array {
            elem: Box::new(MirType::I64),
            len: 3,
        }),
        address_space: AddressSpace::Stack,
    };
    let len_vreg = func
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::Load {
                dst,
                ptr,
                offset: 0,
                ty: MirType::U64,
            } if *ptr == list => Some(*dst),
            _ => None,
        })
        .expect("expected lowered list push to materialize the list length load");
    let eq_cond = func
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::BinOp {
                dst,
                op: BinOpKind::Eq,
                lhs: MirValue::VReg(lhs),
                rhs: MirValue::Const(0),
                ..
            } if *lhs == len_vreg => Some(*dst),
            _ => None,
        })
        .expect("expected unrolled list push to compare the lowered length");

    assert_eq!(hints.get(&list), Some(&list_ptr_ty));
    assert_eq!(hints.get(&len_vreg), Some(&MirType::U64));
    assert_eq!(hints.get(&eq_cond), Some(&MirType::Bool));
}

#[test]
fn test_run_with_type_hints_seeds_emit_event_tmp_ptr() {
    let mut func = MirFunction::new();
    let entry = func.alloc_block();
    func.entry = entry;

    let slot = func.alloc_stack_slot(32, 8, StackSlotKind::ListBuffer);
    let list = func.alloc_vreg();

    func.block_mut(entry).instructions.push(MirInst::ListNew {
        dst: list,
        buffer: slot,
        max_len: 3,
    });
    func.block_mut(entry).instructions.push(MirInst::EmitEvent {
        data: list,
        size: 24,
    });
    func.block_mut(entry).terminator = MirInst::Return { val: None };

    let mut func = func;
    let pass = ListLowering;
    let mut hints = HashMap::new();
    assert!(pass.run_with_type_hints(&mut func, &mut hints));

    let list_ptr_ty = MirType::Ptr {
        pointee: Box::new(MirType::Array {
            elem: Box::new(MirType::I64),
            len: 4,
        }),
        address_space: AddressSpace::Stack,
    };

    let tmp_ptr = func
        .blocks
        .iter()
        .flat_map(|block| block.instructions.iter())
        .find_map(|inst| match inst {
            MirInst::Copy {
                dst,
                src: MirValue::StackSlot(s),
            } if *s == slot && *dst != list => Some(*dst),
            _ => None,
        })
        .expect("expected rematerialized emit pointer");

    assert_eq!(hints.get(&tmp_ptr), Some(&list_ptr_ty));
}
