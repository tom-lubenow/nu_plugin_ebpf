use std::collections::{HashMap, HashSet, VecDeque};

use super::mir::{BlockId, MirFunction, MirInst, MirValue, SubfunctionId, VReg};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubfunctionReturnSummary {
    Unknown,
    ReturnsArg(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AliasSource {
    Unknown,
    Param(usize),
}

pub(crate) fn infer_subfunction_return_summaries(
    subfunctions: &[MirFunction],
) -> HashMap<SubfunctionId, SubfunctionReturnSummary> {
    let mut summaries = HashMap::new();
    let mut visiting = HashSet::new();

    for idx in 0..subfunctions.len() {
        let subfn = SubfunctionId(idx as u32);
        infer_summary_for_subfunction(subfn, subfunctions, &mut summaries, &mut visiting);
    }

    summaries
}

fn infer_summary_for_subfunction(
    subfn: SubfunctionId,
    subfunctions: &[MirFunction],
    summaries: &mut HashMap<SubfunctionId, SubfunctionReturnSummary>,
    visiting: &mut HashSet<SubfunctionId>,
) -> SubfunctionReturnSummary {
    if let Some(summary) = summaries.get(&subfn) {
        return *summary;
    }

    if !visiting.insert(subfn) {
        return SubfunctionReturnSummary::Unknown;
    }

    let summary = subfunctions
        .get(subfn.0 as usize)
        .map(|func| summarize_function(func, subfunctions, summaries, visiting))
        .unwrap_or(SubfunctionReturnSummary::Unknown);
    visiting.remove(&subfn);
    summaries.insert(subfn, summary);
    summary
}

fn summarize_function(
    func: &MirFunction,
    subfunctions: &[MirFunction],
    summaries: &mut HashMap<SubfunctionId, SubfunctionReturnSummary>,
    visiting: &mut HashSet<SubfunctionId>,
) -> SubfunctionReturnSummary {
    let total_vregs = func.vreg_count.max(func.param_count as u32) as usize;
    let mut in_states: HashMap<BlockId, Vec<AliasSource>> = HashMap::new();
    let mut worklist: VecDeque<BlockId> = VecDeque::new();

    let mut entry_state = vec![AliasSource::Unknown; total_vregs];
    for idx in 0..func.param_count.min(total_vregs) {
        entry_state[idx] = AliasSource::Param(idx);
    }
    in_states.insert(func.entry, entry_state);
    worklist.push_back(func.entry);

    let mut return_alias: Option<Option<usize>> = None;

    while let Some(block_id) = worklist.pop_front() {
        let Some(state_in) = in_states.get(&block_id).cloned() else {
            continue;
        };
        let block = func.block(block_id);
        let mut state = state_in;

        for inst in &block.instructions {
            apply_alias_inst(
                inst,
                &func.global_param_aliases,
                &mut state,
                subfunctions,
                summaries,
                visiting,
            );
        }

        match &block.terminator {
            MirInst::Jump { target } => {
                propagate_alias_state(*target, &state, &mut in_states, &mut worklist);
            }
            MirInst::Branch {
                if_true, if_false, ..
            } => {
                propagate_alias_state(*if_true, &state, &mut in_states, &mut worklist);
                propagate_alias_state(*if_false, &state, &mut in_states, &mut worklist);
            }
            MirInst::LoopHeader {
                counter,
                body,
                exit,
                ..
            } => {
                let mut body_state = state.clone();
                set_alias(&mut body_state, *counter, AliasSource::Unknown);
                propagate_alias_state(*body, &body_state, &mut in_states, &mut worklist);
                propagate_alias_state(*exit, &state, &mut in_states, &mut worklist);
            }
            MirInst::LoopBack { header, .. } => {
                propagate_alias_state(*header, &state, &mut in_states, &mut worklist);
            }
            MirInst::Return { val } => {
                let alias = alias_for_value(val.as_ref(), &state);
                return_alias = match return_alias {
                    None => Some(alias),
                    Some(existing) if existing == alias => Some(existing),
                    Some(_) => return SubfunctionReturnSummary::Unknown,
                };
            }
            MirInst::TailCall { .. } | MirInst::Placeholder => {}
            _ => {}
        }
    }

    match return_alias.flatten() {
        Some(idx) => SubfunctionReturnSummary::ReturnsArg(idx),
        None => SubfunctionReturnSummary::Unknown,
    }
}

fn propagate_alias_state(
    target: BlockId,
    next_state: &[AliasSource],
    in_states: &mut HashMap<BlockId, Vec<AliasSource>>,
    worklist: &mut VecDeque<BlockId>,
) {
    let changed = match in_states.get_mut(&target) {
        Some(existing) => merge_alias_states(existing, next_state),
        None => {
            in_states.insert(target, next_state.to_vec());
            true
        }
    };

    if changed {
        worklist.push_back(target);
    }
}

fn merge_alias_states(existing: &mut [AliasSource], incoming: &[AliasSource]) -> bool {
    let mut changed = false;
    for (dst, src) in existing.iter_mut().zip(incoming.iter().copied()) {
        let merged = match (*dst, src) {
            (AliasSource::Param(lhs), AliasSource::Param(rhs)) if lhs == rhs => *dst,
            _ => AliasSource::Unknown,
        };
        if *dst != merged {
            *dst = merged;
            changed = true;
        }
    }
    changed
}

fn apply_alias_inst(
    inst: &MirInst,
    global_param_aliases: &HashMap<String, usize>,
    state: &mut [AliasSource],
    subfunctions: &[MirFunction],
    summaries: &mut HashMap<SubfunctionId, SubfunctionReturnSummary>,
    visiting: &mut HashSet<SubfunctionId>,
) {
    match inst {
        MirInst::Copy { dst, src } => {
            set_alias(state, *dst, alias_for_mir_value(src, state));
        }
        MirInst::Phi { dst, args } => {
            let mut alias = AliasSource::Unknown;
            let mut first = true;
            for (_, arg) in args {
                let current = get_alias(state, *arg);
                if first {
                    alias = current;
                    first = false;
                } else if alias != current {
                    alias = AliasSource::Unknown;
                    break;
                }
            }
            set_alias(state, *dst, alias);
        }
        MirInst::CallSubfn { dst, subfn, args } => {
            let summary = infer_summary_for_subfunction(*subfn, subfunctions, summaries, visiting);
            let alias = match summary {
                SubfunctionReturnSummary::ReturnsArg(idx) => args
                    .get(idx)
                    .copied()
                    .map(|arg| get_alias(state, arg))
                    .unwrap_or(AliasSource::Unknown),
                SubfunctionReturnSummary::Unknown => AliasSource::Unknown,
            };
            set_alias(state, *dst, alias);
        }
        MirInst::LoadGlobal { dst, symbol, .. } => {
            let alias = global_param_aliases
                .get(symbol)
                .copied()
                .map(AliasSource::Param)
                .unwrap_or(AliasSource::Unknown);
            set_alias(state, *dst, alias);
        }
        MirInst::BinOp { dst, .. }
        | MirInst::UnaryOp { dst, .. }
        | MirInst::CallHelper { dst, .. }
        | MirInst::CallKfunc { dst, .. }
        | MirInst::MapLookup { dst, .. }
        | MirInst::LoadCtxField { dst, .. }
        | MirInst::ListNew { dst, .. }
        | MirInst::ListLen { dst, .. }
        | MirInst::ListGet { dst, .. }
        | MirInst::StopTimer { dst }
        | MirInst::Load { dst, .. }
        | MirInst::LoadSlot { dst, .. }
        | MirInst::StrCmp { dst, .. }
        | MirInst::LoopHeader { counter: dst, .. } => {
            set_alias(state, *dst, AliasSource::Unknown);
        }
        MirInst::Store { .. }
        | MirInst::StoreSlot { .. }
        | MirInst::StoreCtxField { .. }
        | MirInst::ReadStr { .. }
        | MirInst::EmitEvent { .. }
        | MirInst::EmitRecord { .. }
        | MirInst::MapUpdate { .. }
        | MirInst::MapDelete { .. }
        | MirInst::MapPush { .. }
        | MirInst::Histogram { .. }
        | MirInst::StartTimer
        | MirInst::TailCall { .. }
        | MirInst::Jump { .. }
        | MirInst::Branch { .. }
        | MirInst::Return { .. }
        | MirInst::LoopBack { .. }
        | MirInst::Placeholder
        | MirInst::ListPush { .. }
        | MirInst::StringAppend { .. }
        | MirInst::IntToString { .. }
        | MirInst::RecordStore { .. } => {}
    }
}

fn alias_for_value(val: Option<&MirValue>, state: &[AliasSource]) -> Option<usize> {
    match val {
        Some(value) => match alias_for_mir_value(value, state) {
            AliasSource::Param(idx) => Some(idx),
            AliasSource::Unknown => None,
        },
        None => None,
    }
}

fn alias_for_mir_value(value: &MirValue, state: &[AliasSource]) -> AliasSource {
    match value {
        MirValue::VReg(vreg) => get_alias(state, *vreg),
        MirValue::Const(_) | MirValue::StackSlot(_) => AliasSource::Unknown,
    }
}

fn get_alias(state: &[AliasSource], vreg: VReg) -> AliasSource {
    state
        .get(vreg.0 as usize)
        .copied()
        .unwrap_or(AliasSource::Unknown)
}

fn set_alias(state: &mut [AliasSource], vreg: VReg, alias: AliasSource) {
    if let Some(slot) = state.get_mut(vreg.0 as usize) {
        *slot = alias;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::mir::{MirFunction, MirInst, MirValue};

    #[test]
    fn test_infer_return_summary_for_copied_param() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;

        let copied = subfn.alloc_vreg();
        subfn.block_mut(entry).instructions.push(MirInst::Copy {
            dst: copied,
            src: MirValue::VReg(VReg(0)),
        });
        subfn.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(copied)),
        };

        let summaries = infer_subfunction_return_summaries(&[subfn]);
        assert_eq!(
            summaries.get(&SubfunctionId(0)),
            Some(&SubfunctionReturnSummary::ReturnsArg(0))
        );
    }

    #[test]
    fn test_infer_return_summary_through_nested_subfunction_call() {
        let mut callee = MirFunction::new();
        let callee_entry = callee.alloc_block();
        callee.entry = callee_entry;
        callee.param_count = 1;
        callee.block_mut(callee_entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(VReg(0))),
        };

        let mut caller = MirFunction::new();
        let caller_entry = caller.alloc_block();
        caller.entry = caller_entry;
        caller.param_count = 1;
        let ret = caller.alloc_vreg();
        caller
            .block_mut(caller_entry)
            .instructions
            .push(MirInst::CallSubfn {
                dst: ret,
                subfn: SubfunctionId(0),
                args: vec![VReg(0)],
            });
        caller.block_mut(caller_entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(ret)),
        };

        let summaries = infer_subfunction_return_summaries(&[callee, caller]);
        assert_eq!(
            summaries.get(&SubfunctionId(1)),
            Some(&SubfunctionReturnSummary::ReturnsArg(0))
        );
    }

    #[test]
    fn test_infer_return_summary_for_aliased_global_param() {
        let mut subfn = MirFunction::new();
        let entry = subfn.alloc_block();
        subfn.entry = entry;
        subfn.param_count = 1;
        subfn
            .global_param_aliases
            .insert("__nu_local_global_250".to_string(), 0);

        let loaded = subfn.alloc_vreg();
        subfn
            .block_mut(entry)
            .instructions
            .push(MirInst::LoadGlobal {
                dst: loaded,
                symbol: "__nu_local_global_250".to_string(),
                ty: crate::compiler::mir::MirType::Ptr {
                    pointee: Box::new(crate::compiler::mir::MirType::Unknown),
                    address_space: crate::compiler::mir::AddressSpace::Map,
                },
            });
        subfn.block_mut(entry).terminator = MirInst::Return {
            val: Some(MirValue::VReg(loaded)),
        };

        let summaries = infer_subfunction_return_summaries(&[subfn]);
        assert_eq!(
            summaries.get(&SubfunctionId(0)),
            Some(&SubfunctionReturnSummary::ReturnsArg(0))
        );
    }
}
