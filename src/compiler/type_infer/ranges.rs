use super::*;
use crate::compiler::mir::BlockId;
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeGuard {
    CompareConst {
        reg: VReg,
        op: BinOpKind,
        value: i64,
    },
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
        let mut in_ctx_field_ranges: HashMap<BlockId, HashMap<CtxField, ValueRange>> =
            HashMap::new();
        let mut worklist = VecDeque::new();

        in_states.insert(func.entry, vec![ValueRange::Unset; total_vregs as usize]);
        in_ctx_field_ranges.insert(func.entry, HashMap::new());
        worklist.push_back(func.entry);

        while let Some(block_id) = worklist.pop_front() {
            let Some(state_in) = in_states.get(&block_id).cloned() else {
                continue;
            };
            let mut ctx_field_ranges = in_ctx_field_ranges
                .get(&block_id)
                .cloned()
                .unwrap_or_default();
            let block = func.block(block_id);
            let mut state = state_in;
            let mut guards: HashMap<VReg, RangeGuard> = HashMap::new();
            let mut ctx_field_sources: HashMap<VReg, CtxField> = HashMap::new();

            for inst in &block.instructions {
                self.apply_range_inst(
                    inst,
                    types,
                    list_caps,
                    &slot_caps,
                    &mut state,
                    &mut ctx_field_ranges,
                    &mut observed,
                    &mut guards,
                    &mut ctx_field_sources,
                );
            }

            match &block.terminator {
                MirInst::Jump { target } => {
                    self.propagate_range_state(
                        *target,
                        &state,
                        &ctx_field_ranges,
                        &mut in_states,
                        &mut in_ctx_field_ranges,
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
                        &ctx_field_ranges,
                        &ctx_field_sources,
                        *cond,
                        &guards,
                        true,
                    ) {
                        self.propagate_range_state(
                            *if_true,
                            &true_state,
                            &true_fields,
                            &mut in_states,
                            &mut in_ctx_field_ranges,
                            &mut worklist,
                        );
                    }
                    if let Some((false_state, false_fields)) = self.refine_range_branch(
                        &state,
                        &ctx_field_ranges,
                        &ctx_field_sources,
                        *cond,
                        &guards,
                        false,
                    ) {
                        self.propagate_range_state(
                            *if_false,
                            &false_state,
                            &false_fields,
                            &mut in_states,
                            &mut in_ctx_field_ranges,
                            &mut worklist,
                        );
                    }
                }
                MirInst::LoopHeader {
                    counter,
                    start,
                    limit,
                    body,
                    exit,
                } => {
                    let mut body_state = state.clone();
                    let max = if *start < *limit {
                        limit.saturating_sub(1)
                    } else {
                        *start
                    };
                    let counter_range = ValueRange::known(*start, max);
                    self.set_state_range(&mut body_state, *counter, counter_range);
                    self.observe_range(&mut observed, *counter, counter_range);
                    self.propagate_range_state(
                        *body,
                        &body_state,
                        &ctx_field_ranges,
                        &mut in_states,
                        &mut in_ctx_field_ranges,
                        &mut worklist,
                    );
                    self.propagate_range_state(
                        *exit,
                        &state,
                        &ctx_field_ranges,
                        &mut in_states,
                        &mut in_ctx_field_ranges,
                        &mut worklist,
                    );
                }
                MirInst::LoopBack { header, .. } => {
                    self.propagate_range_state(
                        *header,
                        &state,
                        &ctx_field_ranges,
                        &mut in_states,
                        &mut in_ctx_field_ranges,
                        &mut worklist,
                    );
                }
                MirInst::Return { .. } | MirInst::TailCall { .. } | MirInst::Placeholder => {}
                other => panic!("invalid terminator in range analysis: {other:?}"),
            }
        }

        observed
            .into_iter()
            .enumerate()
            .map(|(idx, range)| (VReg(idx as u32), range))
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

    fn clear_guard(&self, guards: &mut HashMap<VReg, RangeGuard>, dst: VReg) {
        guards.remove(&dst);
    }

    fn apply_range_inst(
        &self,
        inst: &MirInst,
        types: &HashMap<VReg, MirType>,
        list_caps: &HashMap<VReg, usize>,
        slot_caps: &HashMap<StackSlotId, usize>,
        state: &mut [ValueRange],
        ctx_field_ranges: &mut HashMap<CtxField, ValueRange>,
        observed: &mut [ValueRange],
        guards: &mut HashMap<VReg, RangeGuard>,
        ctx_field_sources: &mut HashMap<VReg, CtxField>,
    ) {
        match inst {
            MirInst::Copy { dst, src } => {
                let range = self.value_range_for_state(src, state);
                self.set_state_range(state, *dst, range);
                self.observe_range(observed, *dst, range);
                match src {
                    MirValue::VReg(src_vreg) => {
                        if let Some(guard) = guards.get(src_vreg).copied() {
                            guards.insert(*dst, guard);
                        } else {
                            self.clear_guard(guards, *dst);
                        }
                        if let Some(field) = ctx_field_sources.get(src_vreg).cloned() {
                            ctx_field_sources.insert(*dst, field);
                        } else {
                            ctx_field_sources.remove(dst);
                        }
                    }
                    _ => {
                        self.clear_guard(guards, *dst);
                        ctx_field_sources.remove(dst);
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
                ctx_field_sources.remove(dst);
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
                ctx_field_sources.remove(dst);
            }
            MirInst::LoadCtxField { dst, field, .. } => {
                let dst_ty = types.get(dst).cloned().unwrap_or(MirType::Unknown);
                let range = ctx_field_ranges
                    .get(field)
                    .copied()
                    .or_else(|| self.scalar_type_range(&dst_ty))
                    .unwrap_or(ValueRange::Unknown);
                self.set_state_range(state, *dst, range);
                self.observe_range(observed, *dst, range);
                self.clear_guard(guards, *dst);
                ctx_field_sources.insert(*dst, field.clone());
            }
            MirInst::ListLen { dst, list } => {
                let range = list_caps
                    .get(list)
                    .map(|cap| Self::list_len_range(*cap))
                    .unwrap_or(ValueRange::Unknown);
                self.set_state_range(state, *dst, range);
                self.observe_range(observed, *dst, range);
                self.clear_guard(guards, *dst);
                ctx_field_sources.remove(dst);
            }
            MirInst::Load {
                dst, ptr, offset, ..
            } => {
                let dst_ty = types.get(dst).cloned().unwrap_or(MirType::Unknown);
                let range = if *offset == 0 {
                    list_caps
                        .get(ptr)
                        .map(|cap| Self::list_len_range(*cap))
                        .or_else(|| self.scalar_type_range(&dst_ty))
                        .unwrap_or(ValueRange::Unknown)
                } else {
                    self.scalar_type_range(&dst_ty)
                        .unwrap_or(ValueRange::Unknown)
                };
                self.set_state_range(state, *dst, range);
                self.observe_range(observed, *dst, range);
                self.clear_guard(guards, *dst);
                ctx_field_sources.remove(dst);
            }
            MirInst::LoadSlot {
                dst, slot, offset, ..
            } => {
                let dst_ty = types.get(dst).cloned().unwrap_or(MirType::Unknown);
                let range = if *offset == 0 {
                    slot_caps
                        .get(slot)
                        .map(|cap| Self::list_len_range(*cap))
                        .or_else(|| self.scalar_type_range(&dst_ty))
                        .unwrap_or(ValueRange::Unknown)
                } else {
                    self.scalar_type_range(&dst_ty)
                        .unwrap_or(ValueRange::Unknown)
                };
                self.set_state_range(state, *dst, range);
                self.observe_range(observed, *dst, range);
                self.clear_guard(guards, *dst);
                ctx_field_sources.remove(dst);
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
                ctx_field_sources.remove(dst);
            }
            _ => {
                if let Some(dst) = inst.def() {
                    self.set_state_range(state, dst, ValueRange::Unknown);
                    self.clear_guard(guards, dst);
                    ctx_field_sources.remove(&dst);
                }
            }
        }
    }

    fn propagate_range_state(
        &self,
        target: BlockId,
        next: &[ValueRange],
        next_ctx_field_ranges: &HashMap<CtxField, ValueRange>,
        in_states: &mut HashMap<BlockId, Vec<ValueRange>>,
        in_ctx_field_ranges: &mut HashMap<BlockId, HashMap<CtxField, ValueRange>>,
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
        let field_entry = in_ctx_field_ranges.entry(target).or_default();
        for (field, incoming) in next_ctx_field_ranges {
            let merged = field_entry
                .get(field)
                .copied()
                .unwrap_or(ValueRange::Unset)
                .merge(*incoming);
            if field_entry.get(field).copied() != Some(merged) {
                field_entry.insert(field.clone(), merged);
                changed = true;
            }
        }
        if changed {
            worklist.push_back(target);
        }
    }

    fn guard_from_compare(
        &self,
        op: BinOpKind,
        lhs: &MirValue,
        rhs: &MirValue,
    ) -> Option<RangeGuard> {
        match (lhs, rhs) {
            (MirValue::VReg(vreg), MirValue::Const(value)) => {
                self.guard_from_compare_reg_const(op, *vreg, *value)
            }
            (MirValue::Const(value), MirValue::VReg(vreg)) => self
                .swap_compare(op)
                .and_then(|swapped| self.guard_from_compare_reg_const(swapped, *vreg, *value)),
            _ => None,
        }
    }

    fn guard_from_compare_reg_const(
        &self,
        op: BinOpKind,
        reg: VReg,
        value: i64,
    ) -> Option<RangeGuard> {
        match op {
            BinOpKind::Eq
            | BinOpKind::Ne
            | BinOpKind::Lt
            | BinOpKind::Le
            | BinOpKind::Gt
            | BinOpKind::Ge => Some(RangeGuard::CompareConst { reg, op, value }),
            _ => None,
        }
    }

    fn swap_compare(&self, op: BinOpKind) -> Option<BinOpKind> {
        Some(match op {
            BinOpKind::Eq => BinOpKind::Eq,
            BinOpKind::Ne => BinOpKind::Ne,
            BinOpKind::Lt => BinOpKind::Gt,
            BinOpKind::Le => BinOpKind::Ge,
            BinOpKind::Gt => BinOpKind::Lt,
            BinOpKind::Ge => BinOpKind::Le,
            _ => return None,
        })
    }

    fn negate_compare(&self, op: BinOpKind) -> Option<BinOpKind> {
        Some(match op {
            BinOpKind::Eq => BinOpKind::Ne,
            BinOpKind::Ne => BinOpKind::Eq,
            BinOpKind::Lt => BinOpKind::Ge,
            BinOpKind::Le => BinOpKind::Gt,
            BinOpKind::Gt => BinOpKind::Le,
            BinOpKind::Ge => BinOpKind::Lt,
            _ => return None,
        })
    }

    fn invert_guard(&self, guard: RangeGuard) -> Option<RangeGuard> {
        match guard {
            RangeGuard::CompareConst { reg, op, value } => Some(RangeGuard::CompareConst {
                reg,
                op: self.negate_compare(op)?,
                value,
            }),
        }
    }

    fn effective_branch_compare(&self, op: BinOpKind, take_true: bool) -> Option<BinOpKind> {
        if take_true {
            Some(op)
        } else {
            self.negate_compare(op)
        }
    }

    fn range_may_equal(&self, range: ValueRange, value: i64) -> bool {
        match range {
            ValueRange::Known { min, max } => value >= min && value <= max,
            ValueRange::Unknown | ValueRange::Unset => true,
        }
    }

    fn range_can_satisfy_const_compare(
        &self,
        range: ValueRange,
        op: BinOpKind,
        value: i64,
    ) -> bool {
        match op {
            BinOpKind::Eq => self.range_may_equal(range, value),
            BinOpKind::Ne => match range {
                ValueRange::Known { min, max } => !(min == max && min == value),
                ValueRange::Unknown | ValueRange::Unset => true,
            },
            BinOpKind::Lt => match range {
                ValueRange::Known { min, .. } => min < value,
                ValueRange::Unknown | ValueRange::Unset => true,
            },
            BinOpKind::Le => match range {
                ValueRange::Known { min, .. } => min <= value,
                ValueRange::Unknown | ValueRange::Unset => true,
            },
            BinOpKind::Gt => match range {
                ValueRange::Known { max, .. } => max > value,
                ValueRange::Unknown | ValueRange::Unset => true,
            },
            BinOpKind::Ge => match range {
                ValueRange::Known { max, .. } => max >= value,
                ValueRange::Unknown | ValueRange::Unset => true,
            },
            _ => true,
        }
    }

    fn intersect_range(
        &self,
        current: ValueRange,
        min: Option<i64>,
        max: Option<i64>,
    ) -> ValueRange {
        let (cur_min, cur_max) = match current {
            ValueRange::Known { min, max } => (min, max),
            ValueRange::Unknown | ValueRange::Unset => (i64::MIN, i64::MAX),
        };
        let next_min = min.unwrap_or(cur_min).max(cur_min);
        let next_max = max.unwrap_or(cur_max).min(cur_max);
        if next_min > next_max {
            ValueRange::Unknown
        } else {
            ValueRange::known(next_min, next_max)
        }
    }

    fn refine_range(
        &self,
        current: ValueRange,
        op: BinOpKind,
        value: i64,
        take_true: bool,
    ) -> ValueRange {
        let op = if take_true {
            op
        } else {
            let Some(negated) = self.negate_compare(op) else {
                return current;
            };
            negated
        };

        if matches!(op, BinOpKind::Ne) {
            return match current {
                ValueRange::Known { min, max } => {
                    if value < min || value > max {
                        ValueRange::Known { min, max }
                    } else if min == max {
                        ValueRange::Unknown
                    } else if value == min {
                        ValueRange::Known {
                            min: min.saturating_add(1),
                            max,
                        }
                    } else if value == max {
                        ValueRange::Known {
                            min,
                            max: max.saturating_sub(1),
                        }
                    } else {
                        ValueRange::Known { min, max }
                    }
                }
                ValueRange::Unknown | ValueRange::Unset => ValueRange::Unknown,
            };
        }

        let (min, max) = match op {
            BinOpKind::Eq => (Some(value), Some(value)),
            BinOpKind::Lt => (None, Some(value.saturating_sub(1))),
            BinOpKind::Le => (None, Some(value)),
            BinOpKind::Gt => (Some(value.saturating_add(1)), None),
            BinOpKind::Ge => (Some(value), None),
            _ => return current,
        };

        self.intersect_range(current, min, max)
    }

    fn refine_range_branch(
        &self,
        state: &[ValueRange],
        ctx_field_ranges: &HashMap<CtxField, ValueRange>,
        ctx_field_sources: &HashMap<VReg, CtxField>,
        cond: VReg,
        guards: &HashMap<VReg, RangeGuard>,
        take_true: bool,
    ) -> Option<(Vec<ValueRange>, HashMap<CtxField, ValueRange>)> {
        let Some(guard) = guards.get(&cond).copied() else {
            return Some((state.to_vec(), ctx_field_ranges.clone()));
        };

        match guard {
            RangeGuard::CompareConst { reg, op, value } => {
                let effective_op = self.effective_branch_compare(op, take_true)?;
                let current = state
                    .get(reg.0 as usize)
                    .copied()
                    .unwrap_or(ValueRange::Unknown);
                if !self.range_can_satisfy_const_compare(current, effective_op, value) {
                    return None;
                }
                let mut next = state.to_vec();
                let mut next_ctx_field_ranges = ctx_field_ranges.clone();
                let refined = self.refine_range(current, op, value, take_true);
                self.set_state_range(&mut next, reg, refined);
                if let Some(field) = ctx_field_sources.get(&reg).cloned() {
                    next_ctx_field_ranges.insert(field, refined);
                }
                Some((next, next_ctx_field_ranges))
            }
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

    pub(super) fn range_for_binop(
        &self,
        op: BinOpKind,
        lhs: ValueRange,
        rhs: ValueRange,
    ) -> ValueRange {
        match op {
            BinOpKind::Add => self.range_add(lhs, rhs),
            BinOpKind::Sub => self.range_sub(lhs, rhs),
            BinOpKind::Mul => self.range_mul(lhs, rhs),
            BinOpKind::Div => self.range_div(lhs, rhs),
            BinOpKind::Mod => self.range_mod(lhs, rhs),
            BinOpKind::Shl => self.range_shift(lhs, rhs, true),
            BinOpKind::Shr => self.range_shift(lhs, rhs, false),
            BinOpKind::And => self.range_and(lhs, rhs),
            BinOpKind::Or => self.range_or(lhs, rhs),
            BinOpKind::Xor => self.range_xor(lhs, rhs),
            _ => ValueRange::Unknown,
        }
    }

    pub(super) fn range_for_unary(&self, op: UnaryOpKind, src: ValueRange) -> ValueRange {
        match op {
            UnaryOpKind::Neg => match src {
                ValueRange::Known { min, max } => ValueRange::known(-max, -min),
                ValueRange::Unknown | ValueRange::Unset => ValueRange::Unknown,
            },
            UnaryOpKind::Not => ValueRange::known(0, 1),
            _ => ValueRange::Unknown,
        }
    }

    pub(super) fn range_add(&self, lhs: ValueRange, rhs: ValueRange) -> ValueRange {
        match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lmin,
                    max: lmax,
                },
                ValueRange::Known {
                    min: rmin,
                    max: rmax,
                },
            ) => ValueRange::known(lmin + rmin, lmax + rmax),
            _ => ValueRange::Unknown,
        }
    }

    pub(super) fn range_sub(&self, lhs: ValueRange, rhs: ValueRange) -> ValueRange {
        match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lmin,
                    max: lmax,
                },
                ValueRange::Known {
                    min: rmin,
                    max: rmax,
                },
            ) => ValueRange::known(lmin - rmax, lmax - rmin),
            _ => ValueRange::Unknown,
        }
    }

    pub(super) fn range_mul(&self, lhs: ValueRange, rhs: ValueRange) -> ValueRange {
        let (lmin, lmax, rmin, rmax) = match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lmin,
                    max: lmax,
                },
                ValueRange::Known {
                    min: rmin,
                    max: rmax,
                },
            ) => (lmin, lmax, rmin, rmax),
            _ => return ValueRange::Unknown,
        };
        let candidates = [
            (lmin as i128) * (rmin as i128),
            (lmin as i128) * (rmax as i128),
            (lmax as i128) * (rmin as i128),
            (lmax as i128) * (rmax as i128),
        ];
        let min = candidates.iter().copied().min().unwrap_or(0);
        let max = candidates.iter().copied().max().unwrap_or(0);
        ValueRange::known(self.clamp_i128_to_i64(min), self.clamp_i128_to_i64(max))
    }

    pub(super) fn range_div(&self, lhs: ValueRange, rhs: ValueRange) -> ValueRange {
        match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lhs_min,
                    max: lhs_max,
                },
                ValueRange::Known {
                    min: rhs_min,
                    max: rhs_max,
                },
            ) => {
                if rhs_min <= 0 && rhs_max >= 0 {
                    return ValueRange::Unknown;
                }
                let candidates = [
                    (lhs_min as i128) / (rhs_min as i128),
                    (lhs_min as i128) / (rhs_max as i128),
                    (lhs_max as i128) / (rhs_min as i128),
                    (lhs_max as i128) / (rhs_max as i128),
                ];
                let min = candidates.iter().copied().min().unwrap_or(0);
                let max = candidates.iter().copied().max().unwrap_or(0);
                ValueRange::known(self.clamp_i128_to_i64(min), self.clamp_i128_to_i64(max))
            }
            _ => ValueRange::Unknown,
        }
    }

    pub(super) fn range_mod(&self, lhs: ValueRange, rhs: ValueRange) -> ValueRange {
        match (lhs, rhs) {
            (
                ValueRange::Known { min: lhs_min, .. },
                ValueRange::Known {
                    min: rhs_min,
                    max: rhs_max,
                },
            ) => {
                if rhs_min <= 0 || rhs_max <= 0 || lhs_min < 0 {
                    return ValueRange::Unknown;
                }
                ValueRange::known(0, rhs_max.saturating_sub(1))
            }
            _ => ValueRange::Unknown,
        }
    }

    pub(super) fn range_and(&self, lhs: ValueRange, rhs: ValueRange) -> ValueRange {
        let (lhs_min, lhs_max, rhs_min, rhs_max) = match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lhs_min,
                    max: lhs_max,
                },
                ValueRange::Known {
                    min: rhs_min,
                    max: rhs_max,
                },
            ) => (lhs_min, lhs_max, rhs_min, rhs_max),
            _ => return ValueRange::Unknown,
        };
        if lhs_min == lhs_max && rhs_min == rhs_max {
            let val = lhs_min & rhs_min;
            return ValueRange::known(val, val);
        }
        if lhs_min < 0 || rhs_min < 0 {
            return ValueRange::Unknown;
        }
        let mask = self.mask_for_max(lhs_max) & self.mask_for_max(rhs_max);
        let max = lhs_max.min(rhs_max).min(mask as i64);
        ValueRange::known(0, max)
    }

    pub(super) fn range_or(&self, lhs: ValueRange, rhs: ValueRange) -> ValueRange {
        let (lhs_min, lhs_max, rhs_min, rhs_max) = match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lhs_min,
                    max: lhs_max,
                },
                ValueRange::Known {
                    min: rhs_min,
                    max: rhs_max,
                },
            ) => (lhs_min, lhs_max, rhs_min, rhs_max),
            _ => return ValueRange::Unknown,
        };
        if lhs_min == lhs_max && rhs_min == rhs_max {
            let val = lhs_min | rhs_min;
            return ValueRange::known(val, val);
        }
        if lhs_min < 0 || rhs_min < 0 {
            return ValueRange::Unknown;
        }
        let mask = self.mask_for_max(lhs_max) | self.mask_for_max(rhs_max);
        let max = (mask as i64).min(lhs_max.saturating_add(rhs_max));
        ValueRange::known(0, max)
    }

    pub(super) fn range_xor(&self, lhs: ValueRange, rhs: ValueRange) -> ValueRange {
        let (lhs_min, lhs_max, rhs_min, rhs_max) = match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lhs_min,
                    max: lhs_max,
                },
                ValueRange::Known {
                    min: rhs_min,
                    max: rhs_max,
                },
            ) => (lhs_min, lhs_max, rhs_min, rhs_max),
            _ => return ValueRange::Unknown,
        };
        if lhs_min == lhs_max && rhs_min == rhs_max {
            let val = lhs_min ^ rhs_min;
            return ValueRange::known(val, val);
        }
        if lhs_min < 0 || rhs_min < 0 {
            return ValueRange::Unknown;
        }
        let mask = self.mask_for_max(lhs_max) | self.mask_for_max(rhs_max);
        let max = (mask as i64).min(lhs_max.saturating_add(rhs_max));
        ValueRange::known(0, max)
    }

    pub(super) fn range_shift(
        &self,
        lhs: ValueRange,
        rhs: ValueRange,
        is_left: bool,
    ) -> ValueRange {
        let (lhs_min, lhs_max, rhs_min, rhs_max) = match (lhs, rhs) {
            (
                ValueRange::Known {
                    min: lhs_min,
                    max: lhs_max,
                },
                ValueRange::Known {
                    min: rhs_min,
                    max: rhs_max,
                },
            ) => (lhs_min, lhs_max, rhs_min, rhs_max),
            _ => return ValueRange::Unknown,
        };
        if rhs_min < 0 || rhs_max > 63 {
            return ValueRange::Unknown;
        }

        let mut min = i128::MAX;
        let mut max = i128::MIN;
        for lhs_val in [lhs_min, lhs_max] {
            for rhs_val in [rhs_min, rhs_max] {
                let shifted = if is_left {
                    (lhs_val as i128) << rhs_val
                } else {
                    (lhs_val as i128) >> rhs_val
                };
                min = min.min(shifted);
                max = max.max(shifted);
            }
        }

        ValueRange::known(self.clamp_i128_to_i64(min), self.clamp_i128_to_i64(max))
    }

    fn clamp_i128_to_i64(&self, value: i128) -> i64 {
        if value > i64::MAX as i128 {
            i64::MAX
        } else if value < i64::MIN as i128 {
            i64::MIN
        } else {
            value as i64
        }
    }

    fn mask_for_max(&self, max: i64) -> u64 {
        if max <= 0 {
            return 0;
        }
        let max = max as u64;
        if max == u64::MAX {
            return u64::MAX;
        }
        let bit = 64 - max.leading_zeros();
        if bit >= 64 {
            u64::MAX
        } else {
            (1u64 << bit) - 1
        }
    }
}
