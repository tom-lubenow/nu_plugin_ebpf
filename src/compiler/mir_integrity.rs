use std::collections::{HashMap, HashSet};

use super::mir::{BlockId, MapKind, MapRef, MirFunction, MirInst, MirValue, StackSlotId, VReg};

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
    let mut block_ids = HashSet::with_capacity(func.blocks.len());
    let mut map_kinds = HashMap::new();
    let total_vregs = (func.vreg_count as usize).max(func.param_count);

    for block in &func.blocks {
        if !block_ids.insert(block.id) {
            errors.push(MirIntegrityError::new(format!(
                "duplicate basic block declaration {}",
                block.id.0
            )));
        }
    }
    if func.blocks.is_empty() {
        errors.push(MirIntegrityError::new(
            "MIR function must contain at least one basic block",
        ));
    } else {
        check_block(func.entry, "function entry", &block_ids, &mut errors);
    }

    for slot in &func.stack_slots {
        if !declared.insert(slot.id) {
            errors.push(MirIntegrityError::new(format!(
                "duplicate stack slot declaration {}",
                slot.id.0
            )));
        }
    }

    for (idx, slot) in &func.param_stack_slots {
        check_param_index(*idx, "param stack slot", func.param_count, &mut errors);
        check_slot(
            *slot,
            &format!("param stack slot arg{idx}"),
            &declared,
            &mut errors,
        );
    }
    for idx in &func.param_non_null {
        check_param_index(
            *idx,
            "non-null parameter metadata",
            func.param_count,
            &mut errors,
        );
    }
    for idx in &func.param_trusted_btf {
        check_param_index(
            *idx,
            "trusted BTF parameter metadata",
            func.param_count,
            &mut errors,
        );
    }
    for (symbol, idx) in &func.global_param_aliases {
        check_param_index(
            *idx,
            &format!("global parameter alias '{symbol}'"),
            func.param_count,
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
    for map in &func.maps_used {
        check_map_ref(map, "maps_used", &mut map_kinds, &mut errors);
    }

    for block in &func.blocks {
        for inst in &block.instructions {
            if is_block_terminator(inst) || matches!(inst, MirInst::Placeholder) {
                errors.push(MirIntegrityError::new(format!(
                    "block {} instruction list contains terminator {:?}",
                    block.id.0, inst
                )));
            }
            check_inst(
                inst,
                &declared,
                &block_ids,
                &mut map_kinds,
                total_vregs,
                &mut errors,
            );
        }
        if !is_block_terminator(&block.terminator) {
            errors.push(MirIntegrityError::new(format!(
                "block {} has invalid terminator {:?}",
                block.id.0, block.terminator
            )));
        }
        check_inst(
            &block.terminator,
            &declared,
            &block_ids,
            &mut map_kinds,
            total_vregs,
            &mut errors,
        );
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
    block_ids: &HashSet<BlockId>,
    map_kinds: &mut HashMap<String, MapKind>,
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
        | MirInst::LoadGlobal { .. }
        | MirInst::LoadSubprogram { .. }
        | MirInst::Histogram { .. }
        | MirInst::StartTimer
        | MirInst::StopTimer { .. }
        | MirInst::EmitEvent { .. }
        | MirInst::EmitRecord { .. } => {}
        MirInst::LoadMapFd { map, .. }
        | MirInst::MapLookup { map, .. }
        | MirInst::MapUpdate { map, .. }
        | MirInst::MapDelete { map, .. }
        | MirInst::MapPush { map, .. } => {
            check_map_ref(map, "map operand", map_kinds, errors);
        }
        MirInst::MapLookupDynamic { inner_map, .. }
        | MirInst::MapUpdateDynamic { inner_map, .. }
        | MirInst::MapDeleteDynamic { inner_map, .. } => {
            check_map_ref(inner_map, "dynamic map inner operand", map_kinds, errors);
        }
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
        MirInst::Phi { args, .. } => {
            for (pred, _) in args {
                check_block(*pred, "phi predecessor", block_ids, errors);
            }
        }
        MirInst::CallSubfn { .. } | MirInst::Placeholder => {}
        MirInst::Jump { target } => {
            check_block(*target, "jump target", block_ids, errors);
        }
        MirInst::Branch {
            if_true, if_false, ..
        } => {
            check_block(*if_true, "branch true target", block_ids, errors);
            check_block(*if_false, "branch false target", block_ids, errors);
        }
        MirInst::Return { val } => {
            if let Some(val) = val {
                check_value(val, "return value", declared, errors);
            }
        }
        MirInst::TailCall { prog_map, index } => {
            check_map_ref(prog_map, "tail call program map", map_kinds, errors);
            check_value(index, "tail call index", declared, errors);
        }
        MirInst::LoopHeader { body, exit, .. } => {
            check_block(*body, "loop body target", block_ids, errors);
            check_block(*exit, "loop exit target", block_ids, errors);
        }
        MirInst::LoopBack { header, .. } => {
            check_block(*header, "loop back target", block_ids, errors);
        }
    }
}

fn check_map_ref(
    map: &MapRef,
    context: &str,
    map_kinds: &mut HashMap<String, MapKind>,
    errors: &mut Vec<MirIntegrityError>,
) {
    if map.name.is_empty() {
        errors.push(MirIntegrityError::new(format!(
            "{context} references map with empty name"
        )));
        return;
    }

    if let Some(previous) = map_kinds.insert(map.name.clone(), map.kind)
        && previous != map.kind
    {
        errors.push(MirIntegrityError::new(format!(
            "map '{}' is referenced with conflicting kinds {} and {}",
            map.name, previous, map.kind
        )));
    }
}

fn is_block_terminator(inst: &MirInst) -> bool {
    matches!(
        inst,
        MirInst::Jump { .. }
            | MirInst::Branch { .. }
            | MirInst::Return { .. }
            | MirInst::TailCall { .. }
            | MirInst::LoopHeader { .. }
            | MirInst::LoopBack { .. }
    )
}

fn check_vreg(vreg: VReg, context: &str, total_vregs: usize, errors: &mut Vec<MirIntegrityError>) {
    if (vreg.0 as usize) >= total_vregs {
        errors.push(MirIntegrityError::new(format!(
            "{context} references out-of-range virtual register {} (valid range 0..{})",
            vreg.0, total_vregs
        )));
    }
}

fn check_block(
    block: BlockId,
    context: &str,
    block_ids: &HashSet<BlockId>,
    errors: &mut Vec<MirIntegrityError>,
) {
    if !block_ids.contains(&block) {
        errors.push(MirIntegrityError::new(format!(
            "{context} references missing basic block {}",
            block.0
        )));
    }
}

fn check_param_index(
    idx: usize,
    context: &str,
    param_count: usize,
    errors: &mut Vec<MirIntegrityError>,
) {
    if idx >= param_count {
        errors.push(MirIntegrityError::new(format!(
            "{context} references out-of-range parameter {} (valid range 0..{})",
            idx, param_count
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
