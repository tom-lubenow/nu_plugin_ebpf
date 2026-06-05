use std::collections::HashSet;

use super::mir::{MirFunction, MirInst, MirValue, StackSlotId, VReg};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MirIntegrityError {
    pub message: String,
}

impl MirIntegrityError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub(crate) fn validate_mir_references(func: &MirFunction) -> Result<(), Vec<MirIntegrityError>> {
    let mut errors = Vec::new();
    let mut declared = HashSet::with_capacity(func.stack_slots.len());
    let total_vregs = (func.vreg_count as usize).max(func.param_count);

    for slot in &func.stack_slots {
        if !declared.insert(slot.id) {
            errors.push(MirIntegrityError::new(format!(
                "duplicate stack slot declaration {}",
                slot.id.0
            )));
        }
    }

    for (idx, slot) in &func.param_stack_slots {
        check_slot(
            *slot,
            &format!("param stack slot arg{idx}"),
            &declared,
            &mut errors,
        );
    }
    for slot in &func.entry_initialized_dynptr_slots {
        check_slot(
            *slot,
            "entry initialized dynptr slot",
            &declared,
            &mut errors,
        );
    }

    for block in &func.blocks {
        for inst in &block.instructions {
            check_inst(inst, &declared, total_vregs, &mut errors);
        }
        check_inst(&block.terminator, &declared, total_vregs, &mut errors);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn check_inst(
    inst: &MirInst,
    declared: &HashSet<StackSlotId>,
    total_vregs: usize,
    errors: &mut Vec<MirIntegrityError>,
) {
    if let Some(dst) = inst.def() {
        check_vreg(dst, "destination register", total_vregs, errors);
    }
    for vreg in inst.uses() {
        check_vreg(vreg, "operand register", total_vregs, errors);
    }

    match inst {
        MirInst::Copy { src, .. } => {
            check_value(src, "copy source", declared, errors);
        }
        MirInst::Load { .. } => {}
        MirInst::Store { val, .. } => {
            check_value(val, "store value", declared, errors);
        }
        MirInst::LoadSlot { slot, .. } => {
            check_slot(*slot, "load slot", declared, errors);
        }
        MirInst::StoreSlot { slot, val, .. } => {
            check_slot(*slot, "store slot", declared, errors);
            check_value(val, "store slot value", declared, errors);
        }
        MirInst::BinOp { lhs, rhs, .. } => {
            check_value(lhs, "binary operation lhs", declared, errors);
            check_value(rhs, "binary operation rhs", declared, errors);
        }
        MirInst::UnaryOp { src, .. } => {
            check_value(src, "unary operation source", declared, errors);
        }
        MirInst::CallHelper { args, .. } => {
            for (idx, arg) in args.iter().enumerate() {
                check_value(arg, &format!("helper arg{idx}"), declared, errors);
            }
        }
        MirInst::CallKfunc { .. }
        | MirInst::LoadMapFd { .. }
        | MirInst::MapLookup { .. }
        | MirInst::MapLookupDynamic { .. }
        | MirInst::LoadGlobal { .. }
        | MirInst::LoadSubprogram { .. }
        | MirInst::MapUpdate { .. }
        | MirInst::MapUpdateDynamic { .. }
        | MirInst::MapDelete { .. }
        | MirInst::MapDeleteDynamic { .. }
        | MirInst::MapPush { .. }
        | MirInst::Histogram { .. }
        | MirInst::StartTimer
        | MirInst::StopTimer { .. }
        | MirInst::EmitEvent { .. }
        | MirInst::EmitRecord { .. } => {}
        MirInst::LoadCtxField { slot, .. } => {
            if let Some(slot) = slot {
                check_slot(*slot, "context field backing slot", declared, errors);
            }
        }
        MirInst::StoreCtxField { val, .. } => {
            check_value(val, "context field store value", declared, errors);
        }
        MirInst::ReadStr { dst, .. } => {
            check_slot(*dst, "read_str destination slot", declared, errors);
        }
        MirInst::StrCmp { lhs, rhs, .. } => {
            check_slot(*lhs, "string compare lhs slot", declared, errors);
            check_slot(*rhs, "string compare rhs slot", declared, errors);
        }
        MirInst::StringAppend {
            dst_buffer, val, ..
        } => {
            check_slot(
                *dst_buffer,
                "string append destination slot",
                declared,
                errors,
            );
            check_value(val, "string append value", declared, errors);
        }
        MirInst::IntToString { dst_buffer, .. } => {
            check_slot(
                *dst_buffer,
                "int_to_string destination slot",
                declared,
                errors,
            );
        }
        MirInst::RecordStore { buffer, val, .. } => {
            check_slot(*buffer, "record store buffer slot", declared, errors);
            check_value(val, "record store value", declared, errors);
        }
        MirInst::ListNew { buffer, .. } => {
            check_slot(*buffer, "list buffer slot", declared, errors);
        }
        MirInst::ListPush { .. } | MirInst::ListLen { .. } => {}
        MirInst::ListGet { idx, .. } => {
            check_value(idx, "list index", declared, errors);
        }
        MirInst::Phi { .. }
        | MirInst::Jump { .. }
        | MirInst::Branch { .. }
        | MirInst::CallSubfn { .. }
        | MirInst::LoopHeader { .. }
        | MirInst::LoopBack { .. }
        | MirInst::Placeholder => {}
        MirInst::Return { val } => {
            if let Some(val) = val {
                check_value(val, "return value", declared, errors);
            }
        }
        MirInst::TailCall { index, .. } => {
            check_value(index, "tail call index", declared, errors);
        }
    }
}

fn check_vreg(vreg: VReg, context: &str, total_vregs: usize, errors: &mut Vec<MirIntegrityError>) {
    if (vreg.0 as usize) >= total_vregs {
        errors.push(MirIntegrityError::new(format!(
            "{context} references out-of-range virtual register {} (valid range 0..{})",
            vreg.0, total_vregs
        )));
    }
}

fn check_value(
    value: &MirValue,
    context: &str,
    declared: &HashSet<StackSlotId>,
    errors: &mut Vec<MirIntegrityError>,
) {
    if let MirValue::StackSlot(slot) = value {
        check_slot(*slot, context, declared, errors);
    }
}

fn check_slot(
    slot: StackSlotId,
    context: &str,
    declared: &HashSet<StackSlotId>,
    errors: &mut Vec<MirIntegrityError>,
) {
    if !declared.contains(&slot) {
        errors.push(MirIntegrityError::new(format!(
            "{context} references undeclared stack slot {}",
            slot.0
        )));
    }
}
