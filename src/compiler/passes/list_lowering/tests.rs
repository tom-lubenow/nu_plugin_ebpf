use super::*;
use crate::compiler::cfg::CFG;
use crate::compiler::mir::{MirFunction, MirInst, MirValue, StackSlotKind};

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
        insts
            .iter()
            .any(|inst| matches!(inst, MirInst::Store { .. })),
        "ListPush lowering should emit stores"
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
