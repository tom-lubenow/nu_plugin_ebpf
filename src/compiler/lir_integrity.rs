use std::collections::{HashMap, HashSet};

use super::lir::{LirFunction, LirInst, LirProgram};
use super::mir::{BlockId, MapKind, MapRef, MirValue, StackSlotId, SubfunctionId, VReg};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LirIntegrityError {
    pub message: String,
}

impl LirIntegrityError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub(crate) fn validate_lir_program(program: &LirProgram) -> Result<(), Vec<LirIntegrityError>> {
    let mut errors = Vec::new();
    validate_function(&program.main, Some(program.subfunctions.len()), &mut errors);
    for subfn in &program.subfunctions {
        validate_function(subfn, Some(program.subfunctions.len()), &mut errors);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

pub(crate) fn validate_lir_function(func: &LirFunction) -> Result<(), Vec<LirIntegrityError>> {
    let mut errors = Vec::new();
    validate_function(func, None, &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_function(
    func: &LirFunction,
    subfn_count: Option<usize>,
    errors: &mut Vec<LirIntegrityError>,
) {
    let mut declared_slots = HashSet::with_capacity(func.stack_slots.len());
    let mut block_ids = HashSet::with_capacity(func.blocks.len());
    let mut map_kinds = HashMap::new();
    let total_vregs = (func.vreg_count as usize).max(func.param_count);

    if func.param_count > 5 {
        errors.push(LirIntegrityError::new(format!(
            "BPF subfunctions support at most 5 arguments, got {}",
            func.param_count
        )));
    }

    for block in &func.blocks {
        if !block_ids.insert(block.id) {
            errors.push(LirIntegrityError::new(format!(
                "duplicate LIR basic block declaration {}",
                block.id.0
            )));
        }
    }
    if func.blocks.is_empty() {
        errors.push(LirIntegrityError::new(
            "LIR function must contain at least one basic block",
        ));
    } else {
        check_block(func.entry, "function entry", &block_ids, errors);
    }

    for slot in &func.stack_slots {
        if !declared_slots.insert(slot.id) {
            errors.push(LirIntegrityError::new(format!(
                "duplicate LIR stack slot declaration {}",
                slot.id.0
            )));
        }
    }

    for (&vreg, &reg) in &func.precolored {
        check_vreg(vreg, "precolored register", total_vregs, errors);
        if matches!(reg, super::instruction::EbpfReg::R10) {
            errors.push(LirIntegrityError::new(format!(
                "precolored register {} uses frame pointer R10",
                vreg.0
            )));
        }
    }

    for map in &func.maps_used {
        check_map_ref(map, "maps_used", &mut map_kinds, errors);
    }

    for block in &func.blocks {
        for inst in &block.instructions {
            if is_lir_terminator(inst) || matches!(inst, LirInst::Placeholder) {
                errors.push(LirIntegrityError::new(format!(
                    "block {} instruction list contains terminator {:?}",
                    block.id.0, inst
                )));
            }
            check_inst(
                inst,
                &declared_slots,
                &block_ids,
                &mut map_kinds,
                total_vregs,
                subfn_count,
                errors,
            );
        }

        if !is_lir_terminator(&block.terminator) {
            errors.push(LirIntegrityError::new(format!(
                "block {} has invalid terminator {:?}",
                block.id.0, block.terminator
            )));
        }
        check_inst(
            &block.terminator,
            &declared_slots,
            &block_ids,
            &mut map_kinds,
            total_vregs,
            subfn_count,
            errors,
        );
    }
}

fn check_inst(
    inst: &LirInst,
    declared_slots: &HashSet<StackSlotId>,
    block_ids: &HashSet<BlockId>,
    map_kinds: &mut HashMap<String, MapKind>,
    total_vregs: usize,
    subfn_count: Option<usize>,
    errors: &mut Vec<LirIntegrityError>,
) {
    for vreg in inst.defs() {
        check_vreg(vreg, "destination register", total_vregs, errors);
    }
    for vreg in inst.uses() {
        check_vreg(vreg, "operand register", total_vregs, errors);
    }

    match inst {
        LirInst::Copy { src, .. } => check_value(src, "copy source", declared_slots, errors),
        LirInst::Store { val, .. } => check_value(val, "store value", declared_slots, errors),
        LirInst::LoadSlot { slot, .. } => check_slot(*slot, "load slot", declared_slots, errors),
        LirInst::StoreSlot { slot, val, .. } => {
            check_slot(*slot, "store slot", declared_slots, errors);
            check_value(val, "store slot value", declared_slots, errors);
        }
        LirInst::BinOp { lhs, rhs, .. } => {
            check_value(lhs, "binary operation lhs", declared_slots, errors);
            check_value(rhs, "binary operation rhs", declared_slots, errors);
        }
        LirInst::UnaryOp { src, .. } => {
            check_value(src, "unary operation source", declared_slots, errors);
        }
        LirInst::CallSubfn { subfn, .. } | LirInst::LoadSubprogram { subfn, .. } => {
            check_subfunction(*subfn, subfn_count, errors);
        }
        LirInst::LoadMapFd { map, .. }
        | LirInst::MapLookup { map, .. }
        | LirInst::MapUpdate { map, .. }
        | LirInst::MapDelete { map, .. }
        | LirInst::MapPush { map, .. } => {
            check_map_ref(map, "map operand", map_kinds, errors);
        }
        LirInst::MapLookupDynamic { inner_map, .. }
        | LirInst::MapUpdateDynamic { inner_map, .. }
        | LirInst::MapDeleteDynamic { inner_map, .. } => {
            check_map_ref(inner_map, "dynamic map inner operand", map_kinds, errors);
        }
        LirInst::TailCall { prog_map, index } => {
            check_map_ref(prog_map, "tail call program map", map_kinds, errors);
            check_value(index, "tail call index", declared_slots, errors);
        }
        LirInst::LoadCtxField { slot, .. } => {
            if let Some(slot) = slot {
                check_slot(*slot, "context field backing slot", declared_slots, errors);
            }
        }
        LirInst::StoreCtxField { val, .. } => {
            check_value(val, "context field store value", declared_slots, errors);
        }
        LirInst::ReadStr { dst, .. } => {
            check_slot(*dst, "read_str destination slot", declared_slots, errors);
        }
        LirInst::StrCmp { lhs, rhs, .. } => {
            check_slot(*lhs, "string compare lhs slot", declared_slots, errors);
            check_slot(*rhs, "string compare rhs slot", declared_slots, errors);
        }
        LirInst::StringAppend {
            dst_buffer, val, ..
        } => {
            check_slot(
                *dst_buffer,
                "string append destination slot",
                declared_slots,
                errors,
            );
            check_value(val, "string append value", declared_slots, errors);
        }
        LirInst::IntToString { dst_buffer, .. } => {
            check_slot(
                *dst_buffer,
                "int_to_string destination slot",
                declared_slots,
                errors,
            );
        }
        LirInst::RecordStore { buffer, val, .. } => {
            check_slot(*buffer, "record store buffer slot", declared_slots, errors);
            check_value(val, "record store value", declared_slots, errors);
        }
        LirInst::ListNew { buffer, .. } => {
            check_slot(*buffer, "list buffer slot", declared_slots, errors);
        }
        LirInst::ListGet { idx, .. } => {
            check_value(idx, "list index", declared_slots, errors);
        }
        LirInst::Jump { target } => check_block(*target, "jump target", block_ids, errors),
        LirInst::Branch {
            if_true, if_false, ..
        } => {
            check_block(*if_true, "branch true target", block_ids, errors);
            check_block(*if_false, "branch false target", block_ids, errors);
        }
        LirInst::Return { val } => {
            if let Some(val) = val {
                check_value(val, "return value", declared_slots, errors);
            }
        }
        LirInst::LoopHeader { body, exit, .. } => {
            check_block(*body, "loop body target", block_ids, errors);
            check_block(*exit, "loop exit target", block_ids, errors);
        }
        LirInst::LoopBack { header, .. } => {
            check_block(*header, "loop back target", block_ids, errors);
        }
        LirInst::Phi { args, .. } => {
            for (pred, _) in args {
                check_block(*pred, "phi predecessor", block_ids, errors);
            }
        }
        LirInst::Load { .. }
        | LirInst::ParallelMove { .. }
        | LirInst::CallHelper { .. }
        | LirInst::CallKfunc { .. }
        | LirInst::LoadGlobal { .. }
        | LirInst::Histogram { .. }
        | LirInst::StartTimer
        | LirInst::StopTimer { .. }
        | LirInst::EmitEvent { .. }
        | LirInst::EmitRecord { .. }
        | LirInst::ListPush { .. }
        | LirInst::ListLen { .. }
        | LirInst::Placeholder => {}
    }
}

fn is_lir_terminator(inst: &LirInst) -> bool {
    matches!(
        inst,
        LirInst::Jump { .. }
            | LirInst::Branch { .. }
            | LirInst::Return { .. }
            | LirInst::TailCall { .. }
            | LirInst::LoopHeader { .. }
            | LirInst::LoopBack { .. }
    )
}

fn check_vreg(vreg: VReg, context: &str, total_vregs: usize, errors: &mut Vec<LirIntegrityError>) {
    if (vreg.0 as usize) >= total_vregs {
        errors.push(LirIntegrityError::new(format!(
            "{context} references out-of-range virtual register {} (valid range 0..{})",
            vreg.0, total_vregs
        )));
    }
}

fn check_block(
    block: BlockId,
    context: &str,
    block_ids: &HashSet<BlockId>,
    errors: &mut Vec<LirIntegrityError>,
) {
    if !block_ids.contains(&block) {
        errors.push(LirIntegrityError::new(format!(
            "{context} references missing basic block {}",
            block.0
        )));
    }
}

fn check_slot(
    slot: StackSlotId,
    context: &str,
    declared_slots: &HashSet<StackSlotId>,
    errors: &mut Vec<LirIntegrityError>,
) {
    if !declared_slots.contains(&slot) {
        errors.push(LirIntegrityError::new(format!(
            "{context} references undeclared stack slot {}",
            slot.0
        )));
    }
}

fn check_value(
    value: &MirValue,
    context: &str,
    declared_slots: &HashSet<StackSlotId>,
    errors: &mut Vec<LirIntegrityError>,
) {
    if let MirValue::StackSlot(slot) = value {
        check_slot(*slot, context, declared_slots, errors);
    }
}

fn check_map_ref(
    map: &MapRef,
    context: &str,
    map_kinds: &mut HashMap<String, MapKind>,
    errors: &mut Vec<LirIntegrityError>,
) {
    if map.name.is_empty() {
        errors.push(LirIntegrityError::new(format!(
            "{context} references map with empty name"
        )));
        return;
    }

    if let Some(previous) = map_kinds.insert(map.name.clone(), map.kind)
        && previous != map.kind
    {
        errors.push(LirIntegrityError::new(format!(
            "map '{}' is referenced with conflicting kinds {} and {}",
            map.name, previous, map.kind
        )));
    }
}

fn check_subfunction(
    subfn: SubfunctionId,
    subfn_count: Option<usize>,
    errors: &mut Vec<LirIntegrityError>,
) {
    let Some(subfn_count) = subfn_count else {
        return;
    };
    if (subfn.0 as usize) >= subfn_count {
        errors.push(LirIntegrityError::new(format!(
            "subfunction reference {} is out of range (valid range 0..{})",
            subfn.0, subfn_count
        )));
    }
}
