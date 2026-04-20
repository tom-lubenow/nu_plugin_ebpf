use super::*;
use crate::compiler::instruction::BpfHelper;
use crate::compiler::mir::BlockId;
use std::collections::{HashMap, VecDeque};

mod arithmetic;
mod guards;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeGuard {
    CompareConst {
        reg: VReg,
        op: BinOpKind,
        value: i64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RangeSourceOp {
    Deref,
    Offset(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RangeSource {
    root: CtxField,
    ops: Vec<RangeSourceOp>,
}

impl RangeSource {
    fn root(field: CtxField) -> Self {
        Self {
            root: field,
            ops: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SlotSourceState {
    Unset,
    Zeroed,
    Known(RangeSource),
    Unknown,
}

impl SlotSourceState {
    fn merge(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Unset, other) => other.clone(),
            (known, Self::Unset) => known.clone(),
            (Self::Zeroed, Self::Zeroed) => Self::Zeroed,
            (Self::Zeroed, Self::Known(source)) | (Self::Known(source), Self::Zeroed) => {
                Self::Known(source.clone())
            }
            (Self::Known(lhs), Self::Known(rhs)) if lhs == rhs => Self::Known(lhs.clone()),
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::Unknown,
        }
    }
}

impl<'a> TypeInference<'a> {
    pub(super) fn compute_list_caps(&self, func: &MirFunction) -> HashMap<VReg, usize> {
        let mut caps: HashMap<VReg, usize> = HashMap::new();
        let mut slot_caps: HashMap<StackSlotId, usize> = HashMap::new();
        for slot in &func.stack_slots {
            if matches!(slot.kind, StackSlotKind::ListBuffer) {
                let elems = slot.size / 8;
                slot_caps.insert(slot.id, elems.saturating_sub(1));
            }
        }
        let mut changed = true;
        let max_iters = func.vreg_count.max(1);

        for _ in 0..max_iters {
            if !changed {
                break;
            }
            changed = false;
            for block in &func.blocks {
                for inst in block
                    .instructions
                    .iter()
                    .chain(std::iter::once(&block.terminator))
                {
                    match inst {
                        MirInst::ListNew {
                            dst,
                            buffer,
                            max_len,
                        } => {
                            let cap = slot_caps
                                .get(buffer)
                                .copied()
                                .map(|slot_cap| (*max_len).min(slot_cap))
                                .unwrap_or(*max_len);
                            let entry = caps.entry(*dst).or_insert(cap);
                            if *entry != cap {
                                *entry = cap;
                                changed = true;
                            }
                        }
                        MirInst::Copy {
                            dst,
                            src: MirValue::StackSlot(slot),
                        } => {
                            if let Some(&cap) = slot_caps.get(slot) {
                                let entry = caps.entry(*dst).or_insert(cap);
                                if *entry != cap {
                                    *entry = cap;
                                    changed = true;
                                }
                            }
                        }
                        MirInst::Copy {
                            dst,
                            src: MirValue::VReg(src),
                        } => {
                            if let Some(&cap) = caps.get(src) {
                                let entry = caps.entry(*dst).or_insert(cap);
                                if *entry != cap {
                                    *entry = cap;
                                    changed = true;
                                }
                            }
                        }
                        MirInst::Phi { dst, args } => {
                            let mut cap = None;
                            let mut consistent = true;
                            for (_, vreg) in args {
                                match (cap, caps.get(vreg)) {
                                    (None, Some(&c)) => cap = Some(c),
                                    (Some(c), Some(&c2)) if c == c2 => {}
                                    _ => {
                                        consistent = false;
                                        break;
                                    }
                                }
                            }
                            if consistent {
                                if let Some(c) = cap {
                                    let entry = caps.entry(*dst).or_insert(c);
                                    if *entry != c {
                                        *entry = c;
                                        changed = true;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        caps
    }

    pub(super) fn list_len_range(cap: usize) -> ValueRange {
        // We intentionally cap at max_len-1 to keep list element addressing bounded.
        let max = cap.saturating_sub(1) as i64;
        ValueRange::known(0, max)
    }

    pub(super) fn compute_value_ranges(
        &self,
        func: &MirFunction,
        types: &HashMap<VReg, MirType>,
        list_caps: &HashMap<VReg, usize>,
    ) -> HashMap<VReg, ValueRange> {
        let mut slot_caps: HashMap<StackSlotId, usize> = HashMap::new();
        for slot in &func.stack_slots {
            if matches!(slot.kind, StackSlotKind::ListBuffer) {
                let elems = slot.size / 8;
                slot_caps.insert(slot.id, elems.saturating_sub(1));
            }
        }
        let total_vregs = func.vreg_count.max(func.param_count as u32);
        let mut observed = vec![ValueRange::Unset; total_vregs as usize];
        let mut in_states: HashMap<BlockId, Vec<ValueRange>> = HashMap::new();
        let mut in_source_ranges: HashMap<BlockId, HashMap<RangeSource, ValueRange>> =
            HashMap::new();
        let mut in_reg_sources: HashMap<BlockId, HashMap<VReg, SlotSourceState>> = HashMap::new();
        let mut in_slot_sources: HashMap<BlockId, HashMap<StackSlotId, SlotSourceState>> =
            HashMap::new();
        let mut worklist = VecDeque::new();

        in_states.insert(func.entry, vec![ValueRange::Unset; total_vregs as usize]);
        in_source_ranges.insert(func.entry, HashMap::new());
        in_reg_sources.insert(func.entry, HashMap::new());
        in_slot_sources.insert(func.entry, HashMap::new());
        worklist.push_back(func.entry);

        while let Some(block_id) = worklist.pop_front() {
            let Some(state_in) = in_states.get(&block_id).cloned() else {
                continue;
            };
            let mut source_ranges = in_source_ranges.get(&block_id).cloned().unwrap_or_default();
            let mut reg_sources = in_reg_sources.get(&block_id).cloned().unwrap_or_default();
            let mut slot_sources = in_slot_sources.get(&block_id).cloned().unwrap_or_default();
            let block = func.block(block_id);
            let mut state = state_in;
            let mut guards: HashMap<VReg, RangeGuard> = HashMap::new();

            for inst in &block.instructions {
                self.apply_range_inst(
                    inst,
                    types,
                    list_caps,
                    &slot_caps,
                    &mut state,
                    &mut source_ranges,
                    &mut reg_sources,
                    &mut slot_sources,
                    &mut observed,
                    &mut guards,
                );
            }

            match &block.terminator {
                MirInst::Jump { target } => {
                    self.propagate_range_state(
                        *target,
                        &state,
                        &source_ranges,
                        &reg_sources,
                        &slot_sources,
                        &mut in_states,
                        &mut in_source_ranges,
                        &mut in_reg_sources,
                        &mut in_slot_sources,
                        &mut worklist,
                    );
                }
                MirInst::Branch {
                    cond,
                    if_true,
                    if_false,
                } => {
                    if let Some((true_state, true_fields)) = self.refine_range_branch(
                        &state,
                        &source_ranges,
                        &reg_sources,
                        *cond,
                        &guards,
                        true,
                    ) {
                        self.propagate_range_state(
                            *if_true,
                            &true_state,
                            &true_fields,
                            &reg_sources,
                            &slot_sources,
                            &mut in_states,
                            &mut in_source_ranges,
                            &mut in_reg_sources,
                            &mut in_slot_sources,
                            &mut worklist,
                        );
                    }
                    if let Some((false_state, false_fields)) = self.refine_range_branch(
                        &state,
                        &source_ranges,
                        &reg_sources,
                        *cond,
                        &guards,
                        false,
                    ) {
                        self.propagate_range_state(
                            *if_false,
                            &false_state,
                            &false_fields,
                            &reg_sources,
                            &slot_sources,
                            &mut in_states,
                            &mut in_source_ranges,
                            &mut in_reg_sources,
                            &mut in_slot_sources,
                            &mut worklist,
                        );
                    }
                }
                MirInst::LoopHeader {
                    counter,
                    start,
                    step,
                    limit,
                    body,
                    exit,
                } => {
                    let mut body_state = state.clone();
                    let (min, max) = if *step >= 0 {
                        let max = if *start < *limit {
                            limit.saturating_sub(1)
                        } else {
                            *start
                        };
                        (*start, max)
                    } else {
                        let min = if *start > *limit {
                            limit.saturating_add(1)
                        } else {
                            *start
                        };
                        (min, *start)
                    };
                    let counter_range = ValueRange::known(min, max);
                    self.set_state_range(&mut body_state, *counter, counter_range);
                    self.observe_range(&mut observed, *counter, counter_range);
                    self.propagate_range_state(
                        *body,
                        &body_state,
                        &source_ranges,
                        &reg_sources,
                        &slot_sources,
                        &mut in_states,
                        &mut in_source_ranges,
                        &mut in_reg_sources,
                        &mut in_slot_sources,
                        &mut worklist,
                    );
                    self.propagate_range_state(
                        *exit,
                        &state,
                        &source_ranges,
                        &reg_sources,
                        &slot_sources,
                        &mut in_states,
                        &mut in_source_ranges,
                        &mut in_reg_sources,
                        &mut in_slot_sources,
                        &mut worklist,
                    );
                }
                MirInst::LoopBack { header, .. } => {
                    self.propagate_range_state(
                        *header,
                        &state,
                        &source_ranges,
                        &reg_sources,
                        &slot_sources,
                        &mut in_states,
                        &mut in_source_ranges,
                        &mut in_reg_sources,
                        &mut in_slot_sources,
                        &mut worklist,
                    );
                }
                MirInst::Return { .. } | MirInst::TailCall { .. } | MirInst::Placeholder => {}
                other => panic!("invalid terminator in range analysis: {other:?}"),
            }
        }

        let mut final_observed = vec![ValueRange::Unset; total_vregs as usize];
        for block in &func.blocks {
            let mut state = in_states
                .get(&block.id)
                .cloned()
                .unwrap_or_else(|| vec![ValueRange::Unset; total_vregs as usize]);
            let mut source_ranges = in_source_ranges.get(&block.id).cloned().unwrap_or_default();
            let mut reg_sources = in_reg_sources.get(&block.id).cloned().unwrap_or_default();
            let mut slot_sources = in_slot_sources.get(&block.id).cloned().unwrap_or_default();
            let mut guards: HashMap<VReg, RangeGuard> = HashMap::new();

            for (idx, range) in state.iter().copied().enumerate() {
                if let Some(slot) = final_observed.get_mut(idx) {
                    *slot = slot.merge(range);
                }
            }

            for inst in &block.instructions {
                self.apply_range_inst(
                    inst,
                    types,
                    list_caps,
                    &slot_caps,
                    &mut state,
                    &mut source_ranges,
                    &mut reg_sources,
                    &mut slot_sources,
                    &mut final_observed,
                    &mut guards,
                );
            }
        }

        final_observed
            .into_iter()
            .enumerate()
            .map(|(idx, range)| (VReg(idx as u32), range))
            .collect()
    }

    pub(super) fn compute_direct_ctx_field_sources(
        &self,
        func: &MirFunction,
        types: &HashMap<VReg, MirType>,
        list_caps: &HashMap<VReg, usize>,
    ) -> HashMap<VReg, CtxField> {
        let mut slot_caps: HashMap<StackSlotId, usize> = HashMap::new();
        for slot in &func.stack_slots {
            if matches!(slot.kind, StackSlotKind::ListBuffer) {
                let elems = slot.size / 8;
                slot_caps.insert(slot.id, elems.saturating_sub(1));
            }
        }
        let total_vregs = func.vreg_count.max(func.param_count as u32);
        let mut in_states: HashMap<BlockId, Vec<ValueRange>> = HashMap::new();
        let mut in_source_ranges: HashMap<BlockId, HashMap<RangeSource, ValueRange>> =
            HashMap::new();
        let mut in_reg_sources: HashMap<BlockId, HashMap<VReg, SlotSourceState>> = HashMap::new();
        let mut in_slot_sources: HashMap<BlockId, HashMap<StackSlotId, SlotSourceState>> =
            HashMap::new();
        let mut worklist = VecDeque::new();

        in_states.insert(func.entry, vec![ValueRange::Unset; total_vregs as usize]);
        in_source_ranges.insert(func.entry, HashMap::new());
        in_reg_sources.insert(func.entry, HashMap::new());
        in_slot_sources.insert(func.entry, HashMap::new());
        worklist.push_back(func.entry);

        while let Some(block_id) = worklist.pop_front() {
            let Some(state_in) = in_states.get(&block_id).cloned() else {
                continue;
            };
            let mut source_ranges = in_source_ranges.get(&block_id).cloned().unwrap_or_default();
            let mut reg_sources = in_reg_sources.get(&block_id).cloned().unwrap_or_default();
            let mut slot_sources = in_slot_sources.get(&block_id).cloned().unwrap_or_default();
            let block = func.block(block_id);
            let mut state = state_in;
            let mut observed = vec![ValueRange::Unset; total_vregs as usize];
            let mut guards: HashMap<VReg, RangeGuard> = HashMap::new();

            for inst in &block.instructions {
                self.apply_range_inst(
                    inst,
                    types,
                    list_caps,
                    &slot_caps,
                    &mut state,
                    &mut source_ranges,
                    &mut reg_sources,
                    &mut slot_sources,
                    &mut observed,
                    &mut guards,
                );
            }

            match &block.terminator {
                MirInst::Jump { target } => {
                    self.propagate_range_state(
                        *target,
                        &state,
                        &source_ranges,
                        &reg_sources,
                        &slot_sources,
                        &mut in_states,
                        &mut in_source_ranges,
                        &mut in_reg_sources,
                        &mut in_slot_sources,
                        &mut worklist,
                    );
                }
                MirInst::Branch {
                    cond,
                    if_true,
                    if_false,
                } => {
                    if let Some((true_state, true_fields)) = self.refine_range_branch(
                        &state,
                        &source_ranges,
                        &reg_sources,
                        *cond,
                        &guards,
                        true,
                    ) {
                        self.propagate_range_state(
                            *if_true,
                            &true_state,
                            &true_fields,
                            &reg_sources,
                            &slot_sources,
                            &mut in_states,
                            &mut in_source_ranges,
                            &mut in_reg_sources,
                            &mut in_slot_sources,
                            &mut worklist,
                        );
                    }
                    if let Some((false_state, false_fields)) = self.refine_range_branch(
                        &state,
                        &source_ranges,
                        &reg_sources,
                        *cond,
                        &guards,
                        false,
                    ) {
                        self.propagate_range_state(
                            *if_false,
                            &false_state,
                            &false_fields,
                            &reg_sources,
                            &slot_sources,
                            &mut in_states,
                            &mut in_source_ranges,
                            &mut in_reg_sources,
                            &mut in_slot_sources,
                            &mut worklist,
                        );
                    }
                }
                MirInst::LoopHeader {
                    counter,
                    start,
                    step,
                    limit,
                    body,
                    exit,
                } => {
                    let mut body_state = state.clone();
                    let (min, max) = if *step >= 0 {
                        let max = if *start < *limit {
                            limit.saturating_sub(1)
                        } else {
                            *start
                        };
                        (*start, max)
                    } else {
                        let min = if *start > *limit {
                            limit.saturating_add(1)
                        } else {
                            *start
                        };
                        (min, *start)
                    };
                    self.set_state_range(&mut body_state, *counter, ValueRange::known(min, max));
                    self.propagate_range_state(
                        *body,
                        &body_state,
                        &source_ranges,
                        &reg_sources,
                        &slot_sources,
                        &mut in_states,
                        &mut in_source_ranges,
                        &mut in_reg_sources,
                        &mut in_slot_sources,
                        &mut worklist,
                    );
                    self.propagate_range_state(
                        *exit,
                        &state,
                        &source_ranges,
                        &reg_sources,
                        &slot_sources,
                        &mut in_states,
                        &mut in_source_ranges,
                        &mut in_reg_sources,
                        &mut in_slot_sources,
                        &mut worklist,
                    );
                }
                MirInst::LoopBack { header, .. } => {
                    self.propagate_range_state(
                        *header,
                        &state,
                        &source_ranges,
                        &reg_sources,
                        &slot_sources,
                        &mut in_states,
                        &mut in_source_ranges,
                        &mut in_reg_sources,
                        &mut in_slot_sources,
                        &mut worklist,
                    );
                }
                MirInst::Return { .. } | MirInst::TailCall { .. } | MirInst::Placeholder => {}
                other => panic!("invalid terminator in range analysis: {other:?}"),
            }
        }

        let mut final_sources = vec![SlotSourceState::Unset; total_vregs as usize];
        for block in &func.blocks {
            let mut state = in_states
                .get(&block.id)
                .cloned()
                .unwrap_or_else(|| vec![ValueRange::Unset; total_vregs as usize]);
            let mut source_ranges = in_source_ranges.get(&block.id).cloned().unwrap_or_default();
            let mut reg_sources = in_reg_sources.get(&block.id).cloned().unwrap_or_default();
            let mut slot_sources = in_slot_sources.get(&block.id).cloned().unwrap_or_default();
            let mut observed = vec![ValueRange::Unset; total_vregs as usize];
            let mut guards: HashMap<VReg, RangeGuard> = HashMap::new();

            self.observe_reg_sources(&mut final_sources, &reg_sources);
            for inst in &block.instructions {
                self.apply_range_inst(
                    inst,
                    types,
                    list_caps,
                    &slot_caps,
                    &mut state,
                    &mut source_ranges,
                    &mut reg_sources,
                    &mut slot_sources,
                    &mut observed,
                    &mut guards,
                );
                self.observe_reg_sources(&mut final_sources, &reg_sources);
            }
        }

        final_sources
            .into_iter()
            .enumerate()
            .filter_map(|(idx, source_state)| match source_state {
                SlotSourceState::Known(source) if source.ops.is_empty() => {
                    Some((VReg(idx as u32), source.root))
                }
                _ => None,
            })
            .collect()
    }

    pub(super) fn compute_root_ctx_field_ranges_at_block_entries(
        &self,
        func: &MirFunction,
        types: &HashMap<VReg, MirType>,
        list_caps: &HashMap<VReg, usize>,
    ) -> HashMap<BlockId, HashMap<CtxField, ValueRange>> {
        let mut slot_caps: HashMap<StackSlotId, usize> = HashMap::new();
        for slot in &func.stack_slots {
            if matches!(slot.kind, StackSlotKind::ListBuffer) {
                let elems = slot.size / 8;
                slot_caps.insert(slot.id, elems.saturating_sub(1));
            }
        }
        let total_vregs = func.vreg_count.max(func.param_count as u32);
        let mut in_states: HashMap<BlockId, Vec<ValueRange>> = HashMap::new();
        let mut in_source_ranges: HashMap<BlockId, HashMap<RangeSource, ValueRange>> =
            HashMap::new();
        let mut in_reg_sources: HashMap<BlockId, HashMap<VReg, SlotSourceState>> = HashMap::new();
        let mut in_slot_sources: HashMap<BlockId, HashMap<StackSlotId, SlotSourceState>> =
            HashMap::new();
        let mut worklist = VecDeque::new();

        in_states.insert(func.entry, vec![ValueRange::Unset; total_vregs as usize]);
        in_source_ranges.insert(func.entry, HashMap::new());
        in_reg_sources.insert(func.entry, HashMap::new());
        in_slot_sources.insert(func.entry, HashMap::new());
        worklist.push_back(func.entry);

        while let Some(block_id) = worklist.pop_front() {
            let Some(state_in) = in_states.get(&block_id).cloned() else {
                continue;
            };
            let mut source_ranges = in_source_ranges.get(&block_id).cloned().unwrap_or_default();
            let mut reg_sources = in_reg_sources.get(&block_id).cloned().unwrap_or_default();
            let mut slot_sources = in_slot_sources.get(&block_id).cloned().unwrap_or_default();
            let block = func.block(block_id);
            let mut state = state_in;
            let mut observed = vec![ValueRange::Unset; total_vregs as usize];
            let mut guards: HashMap<VReg, RangeGuard> = HashMap::new();

            for inst in &block.instructions {
                self.apply_range_inst(
                    inst,
                    types,
                    list_caps,
                    &slot_caps,
                    &mut state,
                    &mut source_ranges,
                    &mut reg_sources,
                    &mut slot_sources,
                    &mut observed,
                    &mut guards,
                );
            }

            match &block.terminator {
                MirInst::Jump { target } => {
                    self.propagate_range_state(
                        *target,
                        &state,
                        &source_ranges,
                        &reg_sources,
                        &slot_sources,
                        &mut in_states,
                        &mut in_source_ranges,
                        &mut in_reg_sources,
                        &mut in_slot_sources,
                        &mut worklist,
                    );
                }
                MirInst::Branch {
                    cond,
                    if_true,
                    if_false,
                } => {
                    if let Some((true_state, true_fields)) = self.refine_range_branch(
                        &state,
                        &source_ranges,
                        &reg_sources,
                        *cond,
                        &guards,
                        true,
                    ) {
                        self.propagate_range_state(
                            *if_true,
                            &true_state,
                            &true_fields,
                            &reg_sources,
                            &slot_sources,
                            &mut in_states,
                            &mut in_source_ranges,
                            &mut in_reg_sources,
                            &mut in_slot_sources,
                            &mut worklist,
                        );
                    }
                    if let Some((false_state, false_fields)) = self.refine_range_branch(
                        &state,
                        &source_ranges,
                        &reg_sources,
                        *cond,
                        &guards,
                        false,
                    ) {
                        self.propagate_range_state(
                            *if_false,
                            &false_state,
                            &false_fields,
                            &reg_sources,
                            &slot_sources,
                            &mut in_states,
                            &mut in_source_ranges,
                            &mut in_reg_sources,
                            &mut in_slot_sources,
                            &mut worklist,
                        );
                    }
                }
                MirInst::LoopHeader {
                    counter,
                    start,
                    step,
                    limit,
                    body,
                    exit,
                } => {
                    let mut body_state = state.clone();
                    let (min, max) = if *step >= 0 {
                        let max = if *start < *limit {
                            limit.saturating_sub(1)
                        } else {
                            *start
                        };
                        (*start, max)
                    } else {
                        let min = if *start > *limit {
                            limit.saturating_add(1)
                        } else {
                            *start
                        };
                        (min, *start)
                    };
                    self.set_state_range(&mut body_state, *counter, ValueRange::known(min, max));
                    self.propagate_range_state(
                        *body,
                        &body_state,
                        &source_ranges,
                        &reg_sources,
                        &slot_sources,
                        &mut in_states,
                        &mut in_source_ranges,
                        &mut in_reg_sources,
                        &mut in_slot_sources,
                        &mut worklist,
                    );
                    self.propagate_range_state(
                        *exit,
                        &state,
                        &source_ranges,
                        &reg_sources,
                        &slot_sources,
                        &mut in_states,
                        &mut in_source_ranges,
                        &mut in_reg_sources,
                        &mut in_slot_sources,
                        &mut worklist,
                    );
                }
                MirInst::LoopBack { header, .. } => {
                    self.propagate_range_state(
                        *header,
                        &state,
                        &source_ranges,
                        &reg_sources,
                        &slot_sources,
                        &mut in_states,
                        &mut in_source_ranges,
                        &mut in_reg_sources,
                        &mut in_slot_sources,
                        &mut worklist,
                    );
                }
                MirInst::Return { .. } | MirInst::TailCall { .. } | MirInst::Placeholder => {}
                other => panic!("invalid terminator in range analysis: {other:?}"),
            }
        }

        in_source_ranges
            .into_iter()
            .map(|(block_id, ranges)| {
                let root_ranges = ranges
                    .into_iter()
                    .filter_map(|(source, range)| {
                        if source.ops.is_empty() {
                            Some((source.root, range))
                        } else {
                            None
                        }
                    })
                    .collect();
                (block_id, root_ranges)
            })
            .collect()
    }

    pub(super) fn compute_stack_bounds(
        &self,
        func: &MirFunction,
        types: &HashMap<VReg, MirType>,
        value_ranges: &HashMap<VReg, ValueRange>,
    ) -> HashMap<VReg, StackBounds> {
        let mut slot_limits: HashMap<StackSlotId, i64> = HashMap::new();
        for slot in &func.stack_slots {
            let limit = slot.size.saturating_sub(1) as i64;
            slot_limits.insert(slot.id, limit);
        }

        let mut bounds: HashMap<VReg, StackBounds> = HashMap::new();
        let mut changed = true;
        let max_iters = func.vreg_count.max(1);

        for _ in 0..max_iters {
            if !changed {
                break;
            }
            changed = false;
            for block in &func.blocks {
                for inst in block
                    .instructions
                    .iter()
                    .chain(std::iter::once(&block.terminator))
                {
                    let update = match inst {
                        MirInst::ListNew {
                            dst,
                            buffer,
                            max_len,
                        } => {
                            let list_limit = (*max_len as i64) * 8;
                            let limit = slot_limits
                                .get(buffer)
                                .map(|slot_limit| list_limit.min(*slot_limit))
                                .unwrap_or(list_limit);
                            Some((
                                *dst,
                                StackBounds {
                                    slot: *buffer,
                                    min: 0,
                                    max: 0,
                                    limit,
                                },
                            ))
                        }
                        MirInst::Copy {
                            dst,
                            src: MirValue::StackSlot(slot),
                        } => {
                            let limit = slot_limits.get(slot).copied().unwrap_or(0);
                            Some((
                                *dst,
                                StackBounds {
                                    slot: *slot,
                                    min: 0,
                                    max: 0,
                                    limit,
                                },
                            ))
                        }
                        MirInst::Copy {
                            dst,
                            src: MirValue::VReg(src),
                        } => bounds.get(src).copied().map(|b| (*dst, b)),
                        MirInst::Phi { dst, args } => {
                            let mut merged: Option<StackBounds> = None;
                            let mut consistent = true;
                            for (_, vreg) in args {
                                let Some(b) = bounds.get(vreg).copied() else {
                                    consistent = false;
                                    break;
                                };
                                merged = Some(match merged {
                                    None => b,
                                    Some(existing) => {
                                        if existing.slot != b.slot || existing.limit != b.limit {
                                            consistent = false;
                                            break;
                                        }
                                        StackBounds {
                                            slot: existing.slot,
                                            min: existing.min.min(b.min),
                                            max: existing.max.max(b.max),
                                            limit: existing.limit,
                                        }
                                    }
                                });
                                if !consistent {
                                    break;
                                }
                            }
                            if consistent {
                                merged.map(|b| (*dst, b))
                            } else {
                                None
                            }
                        }
                        MirInst::BinOp { dst, op, lhs, rhs } => {
                            if !matches!(op, BinOpKind::Add | BinOpKind::Sub) {
                                None
                            } else {
                                let dst_ty = types.get(dst).cloned().unwrap_or(MirType::Unknown);
                                if !matches!(
                                    dst_ty,
                                    MirType::Ptr {
                                        address_space: AddressSpace::Stack,
                                        ..
                                    }
                                ) {
                                    None
                                } else {
                                    let base_info = if matches!(op, BinOpKind::Add) {
                                        let lhs_bounds = match lhs {
                                            MirValue::VReg(v) => bounds.get(v).copied(),
                                            _ => None,
                                        };
                                        let rhs_bounds = match rhs {
                                            MirValue::VReg(v) => bounds.get(v).copied(),
                                            _ => None,
                                        };
                                        if lhs_bounds.is_some() {
                                            Some((lhs, rhs, true))
                                        } else if rhs_bounds.is_some() {
                                            Some((rhs, lhs, true))
                                        } else {
                                            None
                                        }
                                    } else {
                                        let lhs_bounds = match lhs {
                                            MirValue::VReg(v) => bounds.get(v).copied(),
                                            _ => None,
                                        };
                                        if lhs_bounds.is_some() {
                                            Some((lhs, rhs, false))
                                        } else {
                                            None
                                        }
                                    };

                                    if let Some((base, offset, is_add)) = base_info {
                                        let base_bounds = match base {
                                            MirValue::VReg(v) => bounds.get(v).copied(),
                                            _ => None,
                                        };
                                        if let Some(base_bounds) = base_bounds {
                                            let offset_range =
                                                self.value_range_for(offset, value_ranges);
                                            if let ValueRange::Known { min, max } = offset_range {
                                                if min < 0 {
                                                    None
                                                } else {
                                                    let (new_min, new_max) = if is_add {
                                                        (
                                                            base_bounds.min + min,
                                                            base_bounds.max + max,
                                                        )
                                                    } else {
                                                        (
                                                            base_bounds.min - max,
                                                            base_bounds.max - min,
                                                        )
                                                    };
                                                    if new_min < 0 || new_max > base_bounds.limit {
                                                        None
                                                    } else {
                                                        Some((
                                                            *dst,
                                                            StackBounds {
                                                                slot: base_bounds.slot,
                                                                min: new_min,
                                                                max: new_max,
                                                                limit: base_bounds.limit,
                                                            },
                                                        ))
                                                    }
                                                }
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                }
                            }
                        }
                        _ => None,
                    };

                    if let Some((dst, new_bounds)) = update {
                        match bounds.get(&dst).copied() {
                            None => {
                                bounds.insert(dst, new_bounds);
                                changed = true;
                            }
                            Some(existing) => {
                                if existing.slot != new_bounds.slot
                                    || existing.limit != new_bounds.limit
                                {
                                    bounds.remove(&dst);
                                    changed = true;
                                } else {
                                    let merged = StackBounds {
                                        slot: existing.slot,
                                        min: existing.min.min(new_bounds.min),
                                        max: existing.max.max(new_bounds.max),
                                        limit: existing.limit,
                                    };
                                    if merged != existing {
                                        bounds.insert(dst, merged);
                                        changed = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        bounds
    }

    pub(super) fn value_range_for(
        &self,
        value: &MirValue,
        ranges: &HashMap<VReg, ValueRange>,
    ) -> ValueRange {
        match value {
            MirValue::Const(c) => ValueRange::known(*c, *c),
            MirValue::VReg(v) => ranges.get(v).copied().unwrap_or(ValueRange::Unknown),
            MirValue::StackSlot(_) => ValueRange::Unknown,
        }
    }

    pub(super) fn scalar_type_range(&self, ty: &MirType) -> Option<ValueRange> {
        ty.scalar_value_range()
            .map(|(min, max)| ValueRange::known(min, max))
    }

    fn value_range_for_state(&self, value: &MirValue, state: &[ValueRange]) -> ValueRange {
        match value {
            MirValue::Const(c) => ValueRange::known(*c, *c),
            MirValue::VReg(v) => state
                .get(v.0 as usize)
                .copied()
                .unwrap_or(ValueRange::Unknown),
            MirValue::StackSlot(_) => ValueRange::Unknown,
        }
    }

    fn set_state_range(&self, state: &mut [ValueRange], dst: VReg, range: ValueRange) {
        if let Some(slot) = state.get_mut(dst.0 as usize) {
            *slot = range;
        }
    }

    fn observe_range(&self, observed: &mut [ValueRange], dst: VReg, range: ValueRange) {
        if let Some(slot) = observed.get_mut(dst.0 as usize) {
            *slot = slot.merge(range);
        }
    }

    fn observe_reg_sources(
        &self,
        observed: &mut [SlotSourceState],
        reg_sources: &HashMap<VReg, SlotSourceState>,
    ) {
        for (idx, slot) in observed.iter_mut().enumerate() {
            let state = reg_sources
                .get(&VReg(idx as u32))
                .cloned()
                .unwrap_or(SlotSourceState::Unset);
            *slot = slot.merge(&state);
        }
    }

    fn clear_guard(&self, guards: &mut HashMap<VReg, RangeGuard>, dst: VReg) {
        guards.remove(&dst);
    }

    fn source_with_offset(&self, source: &RangeSource, offset: i32) -> Option<RangeSource> {
        if offset < 0 {
            return None;
        }
        if offset == 0 {
            return Some(source.clone());
        }
        let mut next = source.clone();
        next.ops.push(RangeSourceOp::Offset(offset as usize));
        Some(next)
    }

    fn source_deref(&self, source: &RangeSource) -> RangeSource {
        let mut next = source.clone();
        next.ops.push(RangeSourceOp::Deref);
        next
    }

    fn pointer_source_for_binop(
        &self,
        op: BinOpKind,
        lhs: &MirValue,
        rhs: &MirValue,
        reg_sources: &HashMap<VReg, SlotSourceState>,
    ) -> Option<RangeSource> {
        match op {
            BinOpKind::Add => match (lhs, rhs) {
                (MirValue::VReg(base), MirValue::Const(offset))
                | (MirValue::Const(offset), MirValue::VReg(base)) => match reg_sources.get(base) {
                    Some(SlotSourceState::Known(source)) => {
                        self.source_with_offset(source, *offset as i32)
                    }
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        }
    }

    fn source_range_for_load(
        &self,
        source_ranges: &HashMap<RangeSource, ValueRange>,
        source: &Option<RangeSource>,
        fallback: Option<ValueRange>,
    ) -> ValueRange {
        source
            .as_ref()
            .and_then(|source| source_ranges.get(source).copied())
            .or(fallback)
            .unwrap_or(ValueRange::Unknown)
    }

    fn reg_source_for_loaded_value(
        &self,
        value_source: &RangeSource,
        _dst_ty: &MirType,
    ) -> Option<RangeSource> {
        Some(value_source.clone())
    }

    fn slot_known_source(
        &self,
        slot_sources: &HashMap<StackSlotId, SlotSourceState>,
        slot: StackSlotId,
    ) -> Option<RangeSource> {
        match slot_sources.get(&slot) {
            Some(SlotSourceState::Known(source)) => Some(source.clone()),
            _ => None,
        }
    }

    fn reg_known_source(
        &self,
        reg_sources: &HashMap<VReg, SlotSourceState>,
        reg: VReg,
    ) -> Option<RangeSource> {
        match reg_sources.get(&reg) {
            Some(SlotSourceState::Known(source)) => Some(source.clone()),
            _ => None,
        }
    }

    fn apply_range_inst(
        &self,
        inst: &MirInst,
        types: &HashMap<VReg, MirType>,
        list_caps: &HashMap<VReg, usize>,
        slot_caps: &HashMap<StackSlotId, usize>,
        state: &mut [ValueRange],
        source_ranges: &mut HashMap<RangeSource, ValueRange>,
        reg_sources: &mut HashMap<VReg, SlotSourceState>,
        slot_sources: &mut HashMap<StackSlotId, SlotSourceState>,
        observed: &mut [ValueRange],
        guards: &mut HashMap<VReg, RangeGuard>,
    ) {
        match inst {
            MirInst::Copy { dst, src } => {
                let dst_ty = types.get(dst).cloned().unwrap_or(MirType::Unknown);
                let mut range = self.value_range_for_state(src, state);
                self.set_state_range(state, *dst, range);
                self.observe_range(observed, *dst, range);
                match src {
                    MirValue::VReg(src_vreg) => {
                        if !matches!(dst_ty, MirType::Ptr { .. })
                            && let Some(source) = self.reg_known_source(reg_sources, *src_vreg)
                            && let ValueRange::Known { min, max } = self.source_range_for_load(
                                source_ranges,
                                &Some(source),
                                self.scalar_type_range(&dst_ty),
                            )
                        {
                            range = self.intersect_range(range, Some(min), Some(max));
                            self.set_state_range(state, *dst, range);
                            self.observe_range(observed, *dst, range);
                        }
                        if let Some(guard) = guards.get(src_vreg).copied() {
                            guards.insert(*dst, guard);
                        } else {
                            self.clear_guard(guards, *dst);
                        }
                        if let Some(source) = reg_sources.get(src_vreg).cloned() {
                            reg_sources.insert(*dst, source);
                        } else {
                            reg_sources.insert(*dst, SlotSourceState::Unknown);
                        }
                    }
                    _ => {
                        self.clear_guard(guards, *dst);
                        reg_sources.insert(*dst, SlotSourceState::Unknown);
                    }
                }
            }
            MirInst::BinOp { dst, op, lhs, rhs } => {
                let lhs_range = self.value_range_for_state(lhs, state);
                let rhs_range = self.value_range_for_state(rhs, state);
                let range = self.range_for_binop(*op, lhs_range, rhs_range);
                self.set_state_range(state, *dst, range);
                self.observe_range(observed, *dst, range);
                if let Some(guard) = self.guard_from_compare(*op, lhs, rhs) {
                    guards.insert(*dst, guard);
                } else {
                    self.clear_guard(guards, *dst);
                }
                let dst_ty = types.get(dst).cloned().unwrap_or(MirType::Unknown);
                if matches!(dst_ty, MirType::Ptr { .. }) {
                    if let Some(source) = self.pointer_source_for_binop(*op, lhs, rhs, reg_sources)
                    {
                        reg_sources.insert(*dst, SlotSourceState::Known(source));
                    } else {
                        reg_sources.insert(*dst, SlotSourceState::Unknown);
                    }
                } else {
                    reg_sources.insert(*dst, SlotSourceState::Unknown);
                }
            }
            MirInst::UnaryOp { dst, op, src } => {
                let src_range = self.value_range_for_state(src, state);
                let range = self.range_for_unary(*op, src_range);
                self.set_state_range(state, *dst, range);
                self.observe_range(observed, *dst, range);
                if matches!(op, UnaryOpKind::Not) {
                    let inverted = match src {
                        MirValue::VReg(src_vreg) => guards
                            .get(src_vreg)
                            .copied()
                            .and_then(|guard| self.invert_guard(guard)),
                        _ => None,
                    };
                    if let Some(guard) = inverted {
                        guards.insert(*dst, guard);
                    } else {
                        self.clear_guard(guards, *dst);
                    }
                } else {
                    self.clear_guard(guards, *dst);
                }
                reg_sources.insert(*dst, SlotSourceState::Unknown);
            }
            MirInst::LoadCtxField { dst, field, .. } => {
                let dst_ty = types.get(dst).cloned().unwrap_or(MirType::Unknown);
                let source = RangeSource::root(field.clone());
                let range = if matches!(dst_ty, MirType::Ptr { .. }) {
                    self.scalar_type_range(&dst_ty)
                        .unwrap_or(ValueRange::Unknown)
                } else {
                    self.source_range_for_load(
                        source_ranges,
                        &Some(source.clone()),
                        self.scalar_type_range(&dst_ty),
                    )
                };
                self.set_state_range(state, *dst, range);
                self.observe_range(observed, *dst, range);
                self.clear_guard(guards, *dst);
                reg_sources.insert(*dst, SlotSourceState::Known(source));
            }
            MirInst::ListLen { dst, list } => {
                let range = list_caps
                    .get(list)
                    .map(|cap| Self::list_len_range(*cap))
                    .unwrap_or(ValueRange::Unknown);
                self.set_state_range(state, *dst, range);
                self.observe_range(observed, *dst, range);
                self.clear_guard(guards, *dst);
                reg_sources.insert(*dst, SlotSourceState::Unknown);
            }
            MirInst::Load {
                dst, ptr, offset, ..
            } => {
                let dst_ty = types.get(dst).cloned().unwrap_or(MirType::Unknown);
                let source = self
                    .reg_known_source(reg_sources, *ptr)
                    .and_then(|source| self.source_with_offset(&source, *offset));
                let fallback = if *offset == 0 {
                    list_caps
                        .get(ptr)
                        .map(|cap| Self::list_len_range(*cap))
                        .or_else(|| self.scalar_type_range(&dst_ty))
                } else {
                    self.scalar_type_range(&dst_ty)
                };
                let range = if matches!(dst_ty, MirType::Ptr { .. }) {
                    fallback.unwrap_or(ValueRange::Unknown)
                } else {
                    self.source_range_for_load(source_ranges, &source, fallback)
                };
                self.set_state_range(state, *dst, range);
                self.observe_range(observed, *dst, range);
                self.clear_guard(guards, *dst);
                if let Some(source) = source
                    .as_ref()
                    .and_then(|source| self.reg_source_for_loaded_value(source, &dst_ty))
                {
                    reg_sources.insert(*dst, SlotSourceState::Known(source));
                } else {
                    reg_sources.insert(*dst, SlotSourceState::Unknown);
                }
            }
            MirInst::LoadSlot {
                dst, slot, offset, ..
            } => {
                let dst_ty = types.get(dst).cloned().unwrap_or(MirType::Unknown);
                let source = self
                    .slot_known_source(slot_sources, *slot)
                    .and_then(|source| self.source_with_offset(&source, *offset));
                let fallback = if *offset == 0 {
                    slot_caps
                        .get(slot)
                        .map(|cap| Self::list_len_range(*cap))
                        .or_else(|| self.scalar_type_range(&dst_ty))
                } else {
                    self.scalar_type_range(&dst_ty)
                };
                let range = if matches!(dst_ty, MirType::Ptr { .. }) {
                    fallback.unwrap_or(ValueRange::Unknown)
                } else {
                    self.source_range_for_load(source_ranges, &source, fallback)
                };
                self.set_state_range(state, *dst, range);
                self.observe_range(observed, *dst, range);
                self.clear_guard(guards, *dst);
                if let Some(source) = source
                    .as_ref()
                    .and_then(|source| self.reg_source_for_loaded_value(source, &dst_ty))
                {
                    reg_sources.insert(*dst, SlotSourceState::Known(source));
                } else {
                    reg_sources.insert(*dst, SlotSourceState::Unknown);
                }
            }
            MirInst::Phi { dst, args } => {
                let mut merged: Option<ValueRange> = None;
                for (_, vreg) in args {
                    let range = state
                        .get(vreg.0 as usize)
                        .copied()
                        .unwrap_or(ValueRange::Unknown);
                    merged = Some(match merged {
                        None => range,
                        Some(existing) => existing.merge(range),
                    });
                }
                let range = merged.unwrap_or(ValueRange::Unknown);
                self.set_state_range(state, *dst, range);
                self.observe_range(observed, *dst, range);
                self.clear_guard(guards, *dst);
                reg_sources.insert(*dst, SlotSourceState::Unknown);
            }
            MirInst::StoreSlot { slot, val, .. } => {
                let state_next = if matches!(val, MirValue::Const(0)) {
                    SlotSourceState::Zeroed
                } else {
                    SlotSourceState::Unknown
                };
                slot_sources.insert(*slot, state_next);
            }
            MirInst::CallHelper { helper, args, .. } => {
                if matches!(
                    BpfHelper::from_u32(*helper),
                    Some(BpfHelper::ProbeReadKernel | BpfHelper::ProbeReadUser)
                ) {
                    if let [MirValue::StackSlot(slot), _, MirValue::VReg(src_ptr)] = args.as_slice()
                    {
                        let state_next = match reg_sources.get(src_ptr) {
                            Some(SlotSourceState::Known(source)) => {
                                SlotSourceState::Known(self.source_deref(source))
                            }
                            _ => SlotSourceState::Unknown,
                        };
                        slot_sources.insert(*slot, state_next);
                    }
                }
                if let Some(dst) = inst.def() {
                    self.set_state_range(state, dst, ValueRange::Unknown);
                    self.clear_guard(guards, dst);
                    reg_sources.insert(dst, SlotSourceState::Unknown);
                }
            }
            _ => {
                if let Some(dst) = inst.def() {
                    self.set_state_range(state, dst, ValueRange::Unknown);
                    self.clear_guard(guards, dst);
                    reg_sources.insert(dst, SlotSourceState::Unknown);
                }
            }
        }
    }

    fn propagate_range_state(
        &self,
        target: BlockId,
        next: &[ValueRange],
        next_source_ranges: &HashMap<RangeSource, ValueRange>,
        next_reg_sources: &HashMap<VReg, SlotSourceState>,
        next_slot_sources: &HashMap<StackSlotId, SlotSourceState>,
        in_states: &mut HashMap<BlockId, Vec<ValueRange>>,
        in_source_ranges: &mut HashMap<BlockId, HashMap<RangeSource, ValueRange>>,
        in_reg_sources: &mut HashMap<BlockId, HashMap<VReg, SlotSourceState>>,
        in_slot_sources: &mut HashMap<BlockId, HashMap<StackSlotId, SlotSourceState>>,
        worklist: &mut VecDeque<BlockId>,
    ) {
        let entry = in_states
            .entry(target)
            .or_insert_with(|| vec![ValueRange::Unset; next.len()]);
        let mut changed = false;
        for (dst, src) in entry.iter_mut().zip(next.iter().copied()) {
            let merged = dst.merge(src);
            if *dst != merged {
                *dst = merged;
                changed = true;
            }
        }
        let source_entry = in_source_ranges.entry(target).or_default();
        for (source, incoming) in next_source_ranges {
            let merged = source_entry
                .get(source)
                .copied()
                .unwrap_or(ValueRange::Unset)
                .merge(*incoming);
            if source_entry.get(source).copied() != Some(merged) {
                source_entry.insert(source.clone(), merged);
                changed = true;
            }
        }
        let reg_entry = in_reg_sources.entry(target).or_default();
        for (reg, incoming) in next_reg_sources {
            let merged = reg_entry
                .get(reg)
                .cloned()
                .unwrap_or(SlotSourceState::Unset)
                .merge(incoming);
            if reg_entry.get(reg).cloned() != Some(merged.clone()) {
                reg_entry.insert(*reg, merged);
                changed = true;
            }
        }
        let slot_entry = in_slot_sources.entry(target).or_default();
        for (slot, incoming) in next_slot_sources {
            let merged = slot_entry
                .get(slot)
                .cloned()
                .unwrap_or(SlotSourceState::Unset)
                .merge(incoming);
            if slot_entry.get(slot).cloned() != Some(merged.clone()) {
                slot_entry.insert(*slot, merged);
                changed = true;
            }
        }
        if changed {
            worklist.push_back(target);
        }
    }

    pub(super) fn stack_bounds_for_value<'b>(
        &self,
        value: &MirValue,
        stack_bounds: &'b HashMap<VReg, StackBounds>,
    ) -> Option<&'b StackBounds> {
        match value {
            MirValue::VReg(v) => stack_bounds.get(v),
            _ => None,
        }
    }
}
