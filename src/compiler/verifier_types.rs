//! Flow-sensitive verifier-type analysis over MIR.
//!
//! This pass models a subset of the kernel verifier's type system, focusing on
//! pointer kinds and nullability. It is intended to reject uses that are known
//! to fail the verifier (e.g. dereferencing a map lookup result without a null check).

use std::collections::{HashMap, VecDeque};

use super::instruction::{BpfHelper, HelperArgKind, HelperRetKind, HelperSignature};
use super::mir::{
    AddressSpace, BinOpKind, BlockId, COUNTER_MAP_NAME, HISTOGRAM_MAP_NAME, KSTACK_MAP_NAME,
    MapKind, MapRef, MirFunction, MirInst, MirType, MirValue, STRING_COUNTER_MAP_NAME, StackSlotId,
    TIMESTAMP_MAP_NAME, USTACK_MAP_NAME, VReg,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Nullability {
    NonNull,
    MaybeNull,
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueRange {
    Unknown,
    Known { min: i64, max: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PtrOrigin {
    Stack(StackSlotId),
    Map,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PtrBounds {
    origin: PtrOrigin,
    min: i64,
    max: i64,
    limit: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifierType {
    Uninit,
    Unknown,
    Scalar,
    Bool,
    Ptr {
        space: AddressSpace,
        nullability: Nullability,
        bounds: Option<PtrBounds>,
        ringbuf_ref: Option<VReg>,
    },
}

#[derive(Debug, Clone, Copy)]
enum Guard {
    Ptr {
        ptr: VReg,
        true_is_non_null: bool,
    },
    NonZero {
        reg: VReg,
        true_is_non_zero: bool,
    },
    Range {
        reg: VReg,
        op: BinOpKind,
        value: i64,
    },
    RangeCmp {
        lhs: VReg,
        rhs: VReg,
        op: BinOpKind,
    },
}

#[derive(Debug, Clone)]
struct VerifierState {
    regs: Vec<VerifierType>,
    ranges: Vec<ValueRange>,
    non_zero: Vec<bool>,
    not_equal: Vec<Vec<i64>>,
    live_ringbuf_refs: Vec<bool>,
    reachable: bool,
    guards: HashMap<VReg, Guard>,
}

impl VerifierState {
    const MAX_NOT_EQUAL_FACTS: usize = 8;

    fn new(total_vregs: usize) -> Self {
        Self {
            regs: vec![VerifierType::Uninit; total_vregs],
            ranges: vec![ValueRange::Unknown; total_vregs],
            non_zero: vec![false; total_vregs],
            not_equal: vec![Vec::new(); total_vregs],
            live_ringbuf_refs: vec![false; total_vregs],
            reachable: true,
            guards: HashMap::new(),
        }
    }

    fn with_cleared_guards(&self) -> Self {
        Self {
            regs: self.regs.clone(),
            ranges: self.ranges.clone(),
            non_zero: self.non_zero.clone(),
            not_equal: self.not_equal.clone(),
            live_ringbuf_refs: self.live_ringbuf_refs.clone(),
            reachable: self.reachable,
            guards: HashMap::new(),
        }
    }

    fn get(&self, vreg: VReg) -> VerifierType {
        self.regs
            .get(vreg.0 as usize)
            .copied()
            .unwrap_or(VerifierType::Unknown)
    }

    fn get_range(&self, vreg: VReg) -> ValueRange {
        self.ranges
            .get(vreg.0 as usize)
            .copied()
            .unwrap_or(ValueRange::Unknown)
    }

    fn is_non_zero(&self, vreg: VReg) -> bool {
        self.non_zero.get(vreg.0 as usize).copied().unwrap_or(false)
    }

    fn not_equal_consts(&self, vreg: VReg) -> &[i64] {
        self.not_equal
            .get(vreg.0 as usize)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn set(&mut self, vreg: VReg, ty: VerifierType) {
        self.set_with_range(vreg, ty, ValueRange::Unknown);
    }

    fn set_with_range(&mut self, vreg: VReg, ty: VerifierType, range: ValueRange) {
        if let Some(slot) = self.regs.get_mut(vreg.0 as usize) {
            *slot = ty;
        }
        if let Some(slot) = self.ranges.get_mut(vreg.0 as usize) {
            *slot = range;
        }
        if let Some(slot) = self.non_zero.get_mut(vreg.0 as usize) {
            *slot = false;
        }
        if let Some(slot) = self.not_equal.get_mut(vreg.0 as usize) {
            slot.clear();
        }
        self.guards.remove(&vreg);
    }

    fn set_not_equal_const(&mut self, vreg: VReg, value: i64) {
        if let Some(slot) = self.not_equal.get_mut(vreg.0 as usize) {
            if !slot.contains(&value) {
                slot.push(value);
                slot.sort_unstable();
                if slot.len() > Self::MAX_NOT_EQUAL_FACTS {
                    slot.remove(0);
                }
            }
        }
    }

    fn clear_not_equal_const(&mut self, vreg: VReg) {
        if let Some(slot) = self.not_equal.get_mut(vreg.0 as usize) {
            slot.clear();
        }
    }

    fn retain_not_equal_in_range(&mut self, vreg: VReg, range: ValueRange) {
        if let Some(slot) = self.not_equal.get_mut(vreg.0 as usize) {
            slot.retain(|value| range_may_equal(range, *value));
        }
    }

    fn mark_unreachable(&mut self) {
        self.reachable = false;
    }

    fn set_live_ringbuf_ref(&mut self, id: VReg, live: bool) {
        if let Some(slot) = self.live_ringbuf_refs.get_mut(id.0 as usize) {
            *slot = live;
        }
    }

    fn invalidate_ringbuf_ref(&mut self, id: VReg) {
        self.set_live_ringbuf_ref(id, false);
        for idx in 0..self.regs.len() {
            let reg = VReg(idx as u32);
            let is_ref = matches!(
                self.regs[idx],
                VerifierType::Ptr {
                    ringbuf_ref: Some(ref_id),
                    ..
                } if ref_id == id
            );
            if is_ref {
                self.regs[idx] = VerifierType::Unknown;
                self.ranges[idx] = ValueRange::Unknown;
                self.non_zero[idx] = false;
                self.not_equal[idx].clear();
                self.guards.remove(&reg);
            }
        }
    }

    fn has_live_ringbuf_refs(&self) -> bool {
        self.live_ringbuf_refs
            .iter()
            .copied()
            .any(std::convert::identity)
    }

    fn is_reachable(&self) -> bool {
        self.reachable
    }

    fn join(&self, other: &VerifierState) -> VerifierState {
        if !self.reachable {
            return other.with_cleared_guards();
        }
        if !other.reachable {
            return self.with_cleared_guards();
        }

        let mut regs = Vec::with_capacity(self.regs.len());
        for i in 0..self.regs.len() {
            let a = self.regs[i];
            let b = other.regs[i];
            regs.push(join_type(a, b));
        }
        let mut ranges = Vec::with_capacity(self.ranges.len());
        for i in 0..self.ranges.len() {
            let a = self.ranges[i];
            let b = other.ranges[i];
            ranges.push(join_range(a, b));
        }
        let mut non_zero = Vec::with_capacity(self.non_zero.len());
        for i in 0..self.non_zero.len() {
            non_zero.push(self.non_zero[i] && other.non_zero[i]);
        }
        let mut not_equal = Vec::with_capacity(self.not_equal.len());
        for i in 0..self.not_equal.len() {
            let left = &self.not_equal[i];
            let right = &other.not_equal[i];
            if left.is_empty() || right.is_empty() {
                not_equal.push(Vec::new());
                continue;
            }
            let mut shared = Vec::new();
            for value in left {
                if right.contains(value) {
                    shared.push(*value);
                }
            }
            not_equal.push(shared);
        }
        let mut live_ringbuf_refs = Vec::with_capacity(self.live_ringbuf_refs.len());
        for i in 0..self.live_ringbuf_refs.len() {
            live_ringbuf_refs.push(self.live_ringbuf_refs[i] || other.live_ringbuf_refs[i]);
        }
        VerifierState {
            regs,
            ranges,
            non_zero,
            not_equal,
            live_ringbuf_refs,
            reachable: true,
            guards: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifierTypeError {
    pub message: String,
}

impl VerifierTypeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for VerifierTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for VerifierTypeError {}

pub fn verify_mir(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
) -> Result<(), Vec<VerifierTypeError>> {
    let total_vregs = func.vreg_count.max(func.param_count as u32) as usize;
    let mut slot_sizes: HashMap<StackSlotId, i64> = HashMap::new();
    for slot in &func.stack_slots {
        let limit = slot.size.saturating_sub(1) as i64;
        slot_sizes.insert(slot.id, limit);
    }
    let mut in_states: HashMap<BlockId, VerifierState> = HashMap::new();
    let mut worklist: VecDeque<BlockId> = VecDeque::new();
    let mut errors = Vec::new();

    let mut entry_state = VerifierState::new(total_vregs);
    for i in 0..func.param_count {
        let vreg = VReg(i as u32);
        let ty = types
            .get(&vreg)
            .map(|ty| verifier_type_from_mir(ty))
            .unwrap_or(VerifierType::Unknown);
        entry_state.set(vreg, ty);
    }

    in_states.insert(func.entry, entry_state);
    worklist.push_back(func.entry);

    while let Some(block_id) = worklist.pop_front() {
        let state_in = match in_states.get(&block_id) {
            Some(state) => state.clone(),
            None => continue,
        };
        if !state_in.is_reachable() {
            continue;
        }
        let mut state = state_in.with_cleared_guards();
        let block = func.block(block_id);

        for inst in &block.instructions {
            check_uses_initialized(inst, &state, &mut errors);
            apply_inst(inst, types, &slot_sizes, &mut state, &mut errors);
        }

        check_uses_initialized(&block.terminator, &state, &mut errors);

        match &block.terminator {
            MirInst::Jump { target } => {
                propagate_state(*target, &state, &mut in_states, &mut worklist);
            }
            MirInst::Branch {
                cond,
                if_true,
                if_false,
            } => {
                let guard = state.guards.get(cond).copied();
                let true_state = refine_on_branch(&state, guard, true);
                let false_state = refine_on_branch(&state, guard, false);
                propagate_state(*if_true, &true_state, &mut in_states, &mut worklist);
                propagate_state(*if_false, &false_state, &mut in_states, &mut worklist);
            }
            MirInst::Return { .. } => {
                if state.has_live_ringbuf_refs() {
                    errors.push(VerifierTypeError::new(
                        "unreleased ringbuf record reference at function exit",
                    ));
                }
            }
            MirInst::TailCall { prog_map, index } => {
                if prog_map.kind != MapKind::ProgArray {
                    errors.push(VerifierTypeError::new(format!(
                        "tail_call requires ProgArray map, got {:?}",
                        prog_map.kind
                    )));
                }
                let index_ty = value_type(index, &state, &slot_sizes);
                if !matches!(index_ty, VerifierType::Scalar | VerifierType::Bool) {
                    errors.push(VerifierTypeError::new(format!(
                        "tail_call index expects scalar, got {:?}",
                        index_ty
                    )));
                }
                if state.has_live_ringbuf_refs() {
                    errors.push(VerifierTypeError::new(
                        "unreleased ringbuf record reference at function exit",
                    ));
                }
            }
            _ => {}
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn propagate_state(
    block: BlockId,
    state: &VerifierState,
    in_states: &mut HashMap<BlockId, VerifierState>,
    worklist: &mut VecDeque<BlockId>,
) {
    if !state.is_reachable() {
        return;
    }

    let updated = match in_states.get(&block) {
        None => {
            in_states.insert(block, state.clone());
            true
        }
        Some(existing) => {
            let merged = existing.join(state);
            if merged.regs != existing.regs
                || merged.ranges != existing.ranges
                || merged.non_zero != existing.non_zero
                || merged.not_equal != existing.not_equal
                || merged.live_ringbuf_refs != existing.live_ringbuf_refs
                || merged.reachable != existing.reachable
            {
                in_states.insert(block, merged);
                true
            } else {
                false
            }
        }
    };

    if updated {
        worklist.push_back(block);
    }
}

fn refine_on_branch(state: &VerifierState, guard: Option<Guard>, take_true: bool) -> VerifierState {
    let mut next = state.with_cleared_guards();
    if let Some(guard) = guard {
        match guard {
            Guard::Ptr {
                ptr,
                true_is_non_null,
            } => {
                let wants_non_null = if take_true {
                    true_is_non_null
                } else {
                    !true_is_non_null
                };
                let current = next.get(ptr);
                if let VerifierType::Ptr {
                    space,
                    nullability,
                    bounds,
                    ringbuf_ref,
                } = current
                {
                    if (wants_non_null && nullability == Nullability::Null)
                        || (!wants_non_null && nullability == Nullability::NonNull)
                    {
                        next.mark_unreachable();
                        return next;
                    }
                    let nullability = if wants_non_null {
                        Nullability::NonNull
                    } else {
                        Nullability::Null
                    };
                    if !wants_non_null {
                        if let Some(ref_id) = ringbuf_ref {
                            next.set_live_ringbuf_ref(ref_id, false);
                        }
                    }
                    next.set(
                        ptr,
                        VerifierType::Ptr {
                            space,
                            nullability,
                            bounds,
                            ringbuf_ref,
                        },
                    );
                }
            }
            Guard::NonZero {
                reg,
                true_is_non_zero,
            } => {
                let wants_non_zero = if take_true {
                    true_is_non_zero
                } else {
                    !true_is_non_zero
                };
                if wants_non_zero {
                    if let Some(slot) = next.ranges.get_mut(reg.0 as usize) {
                        if let ValueRange::Known { min, max } = *slot {
                            let new_range = if min == 0 && max > 0 {
                                ValueRange::Known { min: 1, max }
                            } else if max == 0 && min < 0 {
                                ValueRange::Known { min, max: -1 }
                            } else {
                                ValueRange::Known { min, max }
                            };
                            *slot = new_range;
                        }
                    }
                    if let Some(slot) = next.non_zero.get_mut(reg.0 as usize) {
                        *slot = true;
                    }
                    next.set_not_equal_const(reg, 0);
                } else {
                    if let Some(slot) = next.ranges.get_mut(reg.0 as usize) {
                        *slot = ValueRange::Known { min: 0, max: 0 };
                    }
                    if let Some(slot) = next.non_zero.get_mut(reg.0 as usize) {
                        *slot = false;
                    }
                    next.clear_not_equal_const(reg);
                }
            }
            Guard::Range { reg, op, value } => {
                let Some(effective_op) = effective_branch_compare(op, take_true) else {
                    return next;
                };
                let current = next.get_range(reg);
                let excluded = next.not_equal_consts(reg).to_vec();
                if !range_can_satisfy_const_compare(current, &excluded, effective_op, value) {
                    next.mark_unreachable();
                    return next;
                }
                let new_range = refine_range(current, op, value, take_true);
                if let Some(slot) = next.ranges.get_mut(reg.0 as usize) {
                    *slot = new_range;
                }
                match effective_op {
                    BinOpKind::Eq => next.clear_not_equal_const(reg),
                    BinOpKind::Ne => next.set_not_equal_const(reg, value),
                    _ => next.retain_not_equal_in_range(reg, new_range),
                }
                let range_excludes_zero =
                    matches!(new_range, ValueRange::Known { min, max } if min > 0 || max < 0);
                if let Some(slot) = next.non_zero.get_mut(reg.0 as usize) {
                    *slot = *slot || range_excludes_zero;
                }
            }
            Guard::RangeCmp { lhs, rhs, op } => {
                let lhs_range = next.get_range(lhs);
                let rhs_range = next.get_range(rhs);
                let Some(effective_op) = effective_branch_compare(op, take_true) else {
                    return next;
                };
                if !ranges_can_satisfy_compare(lhs_range, rhs_range, effective_op) {
                    next.mark_unreachable();
                    return next;
                }
                let (new_lhs, new_rhs) = refine_compare_ranges(lhs_range, rhs_range, op, take_true);
                if let Some(slot) = next.ranges.get_mut(lhs.0 as usize) {
                    *slot = new_lhs;
                }
                if let Some(slot) = next.ranges.get_mut(rhs.0 as usize) {
                    *slot = new_rhs;
                }
                next.retain_not_equal_in_range(lhs, new_lhs);
                next.retain_not_equal_in_range(rhs, new_rhs);
                let lhs_excludes_zero =
                    matches!(new_lhs, ValueRange::Known { min, max } if min > 0 || max < 0);
                if let Some(slot) = next.non_zero.get_mut(lhs.0 as usize) {
                    *slot = *slot || lhs_excludes_zero;
                }
                let rhs_excludes_zero =
                    matches!(new_rhs, ValueRange::Known { min, max } if min > 0 || max < 0);
                if let Some(slot) = next.non_zero.get_mut(rhs.0 as usize) {
                    *slot = *slot || rhs_excludes_zero;
                }
            }
        }
    }
    next
}

fn apply_inst(
    inst: &MirInst,
    types: &HashMap<VReg, MirType>,
    slot_sizes: &HashMap<StackSlotId, i64>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    match inst {
        MirInst::Copy { dst, src } => {
            let ty = value_type(src, state, slot_sizes);
            let range = value_range(src, state);
            let src_non_zero = match src {
                MirValue::VReg(vreg) => state.is_non_zero(*vreg),
                MirValue::Const(value) => *value != 0,
                _ => false,
            };
            let src_not_equal = match src {
                MirValue::VReg(vreg) => state.not_equal_consts(*vreg).to_vec(),
                MirValue::Const(value) if *value != 0 => vec![0],
                _ => Vec::new(),
            };
            state.set_with_range(*dst, ty, range);
            if src_non_zero {
                if let Some(slot) = state.non_zero.get_mut(dst.0 as usize) {
                    *slot = true;
                }
            }
            for excluded in src_not_equal {
                state.set_not_equal_const(*dst, excluded);
            }
        }
        MirInst::Load {
            dst, ptr, offset, ..
        } => {
            let access_size = types.get(dst).map(|ty| ty.size()).unwrap_or(8);
            check_ptr_access(
                *ptr,
                "load",
                &[AddressSpace::Stack, AddressSpace::Map],
                *offset,
                access_size,
                state,
                errors,
            );
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            state.set(*dst, ty);
        }
        MirInst::Store {
            ptr, offset, ty, ..
        } => {
            let access_size = ty.size();
            check_ptr_access(
                *ptr,
                "store",
                &[AddressSpace::Stack, AddressSpace::Map],
                *offset,
                access_size,
                state,
                errors,
            );
        }
        MirInst::LoadSlot { dst, .. } => {
            if let MirInst::LoadSlot {
                slot, offset, ty, ..
            } = inst
            {
                check_slot_access(*slot, *offset, ty.size(), slot_sizes, "load slot", errors);
            }
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            state.set(*dst, ty);
        }
        MirInst::StoreSlot { .. } => {
            if let MirInst::StoreSlot {
                slot, offset, ty, ..
            } = inst
            {
                check_slot_access(*slot, *offset, ty.size(), slot_sizes, "store slot", errors);
            }
        }
        MirInst::BinOp { dst, op, lhs, rhs } => {
            if matches!(
                op,
                BinOpKind::Eq
                    | BinOpKind::Ne
                    | BinOpKind::Lt
                    | BinOpKind::Le
                    | BinOpKind::Gt
                    | BinOpKind::Ge
            ) {
                state.set_with_range(
                    *dst,
                    VerifierType::Bool,
                    ValueRange::Known { min: 0, max: 1 },
                );
                if let Some(guard) = guard_from_compare(*op, lhs, rhs, state) {
                    state.guards.insert(*dst, guard);
                }
            } else {
                if let Some(ty) = pointer_arith_result(*op, lhs, rhs, state, slot_sizes) {
                    state.set(*dst, ty);
                } else {
                    let range = range_for_binop(*op, lhs, rhs, state);
                    state.set_with_range(*dst, VerifierType::Scalar, range);
                }
            }
        }
        MirInst::UnaryOp { op, .. } => {
            let ty = match op {
                super::mir::UnaryOpKind::Not => VerifierType::Bool,
                _ => VerifierType::Scalar,
            };
            if let Some(dst) = inst.def() {
                let range = if matches!(op, super::mir::UnaryOpKind::Not) {
                    ValueRange::Known { min: 0, max: 1 }
                } else {
                    ValueRange::Unknown
                };
                state.set_with_range(dst, ty, range);
            }
        }
        MirInst::CallHelper { dst, helper, args } => {
            if let Some(sig) = HelperSignature::for_id(*helper) {
                if args.len() < sig.min_args || args.len() > sig.max_args {
                    errors.push(VerifierTypeError::new(format!(
                        "helper {} expects {}..={} args, got {}",
                        helper,
                        sig.min_args,
                        sig.max_args,
                        args.len()
                    )));
                }
                for (idx, arg) in args.iter().take(sig.max_args.min(5)).enumerate() {
                    check_helper_arg(
                        *helper,
                        idx,
                        arg,
                        sig.arg_kind(idx),
                        state,
                        slot_sizes,
                        errors,
                    );
                }
                apply_helper_semantics(*helper, args, state, slot_sizes, errors);

                let ty = match sig.ret_kind {
                    HelperRetKind::Scalar => types
                        .get(dst)
                        .map(verifier_type_from_mir)
                        .unwrap_or(VerifierType::Scalar),
                    HelperRetKind::PointerMaybeNull => match BpfHelper::from_u32(*helper) {
                        Some(BpfHelper::RingbufReserve) => {
                            state.set_live_ringbuf_ref(*dst, true);
                            VerifierType::Ptr {
                                space: AddressSpace::Map,
                                nullability: Nullability::MaybeNull,
                                bounds: None,
                                ringbuf_ref: Some(*dst),
                            }
                        }
                        _ => {
                            let bounds =
                                map_value_limit_from_dst_type(types.get(dst)).map(|limit| {
                                    PtrBounds {
                                        origin: PtrOrigin::Map,
                                        min: 0,
                                        max: 0,
                                        limit,
                                    }
                                });
                            VerifierType::Ptr {
                                space: AddressSpace::Map,
                                nullability: Nullability::MaybeNull,
                                bounds,
                                ringbuf_ref: None,
                            }
                        }
                    },
                };
                state.set_with_range(*dst, ty, ValueRange::Unknown);
            } else {
                let ty = types
                    .get(dst)
                    .map(verifier_type_from_mir)
                    .unwrap_or(VerifierType::Scalar);
                state.set_with_range(*dst, ty, ValueRange::Unknown);
            }
        }
        MirInst::CallSubfn { dst, .. }
        | MirInst::StrCmp { dst, .. }
        | MirInst::StopTimer { dst, .. }
        | MirInst::LoopHeader { counter: dst, .. }
        | MirInst::Phi { dst, .. } => {
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            let range = if let MirInst::Phi { args, .. } = inst {
                range_for_phi(args, state)
            } else {
                ValueRange::Unknown
            };
            let ty = if let MirInst::Phi { args, .. } = inst {
                ptr_type_for_phi(args, state).unwrap_or(ty)
            } else {
                ty
            };
            state.set_with_range(*dst, ty, range);
        }
        MirInst::MapLookup { dst, map, .. } => {
            if !supports_generic_map_kind(map.kind) {
                errors.push(VerifierTypeError::new(format!(
                    "map operations do not support map kind {:?} for '{}'",
                    map.kind, map.name
                )));
            }
            let bounds = map_value_limit(map)
                .or_else(|| map_value_limit_from_dst_type(types.get(dst)))
                .map(|limit| PtrBounds {
                    origin: PtrOrigin::Map,
                    min: 0,
                    max: 0,
                    limit,
                });
            state.set(
                *dst,
                VerifierType::Ptr {
                    space: AddressSpace::Map,
                    nullability: Nullability::MaybeNull,
                    bounds,
                    ringbuf_ref: None,
                },
            );
        }
        MirInst::ListNew { dst, buffer, .. } => {
            let bounds = slot_sizes.get(buffer).copied().map(|limit| PtrBounds {
                origin: PtrOrigin::Stack(*buffer),
                min: 0,
                max: 0,
                limit,
            });
            state.set(
                *dst,
                VerifierType::Ptr {
                    space: AddressSpace::Stack,
                    nullability: Nullability::NonNull,
                    bounds,
                    ringbuf_ref: None,
                },
            );
        }
        MirInst::ListLen { dst, list } => {
            require_ptr_with_space(*list, "list", &[AddressSpace::Stack], state, errors);
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            state.set(*dst, ty);
        }
        MirInst::ListGet { dst, list, .. } => {
            require_ptr_with_space(*list, "list", &[AddressSpace::Stack], state, errors);
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            state.set(*dst, ty);
        }
        MirInst::LoadCtxField { dst, slot, .. } => {
            let mut ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            if let (
                VerifierType::Ptr {
                    space: AddressSpace::Stack,
                    nullability,
                    ..
                },
                Some(slot),
            ) = (ty, slot)
            {
                let bounds = slot_sizes.get(slot).copied().map(|limit| PtrBounds {
                    origin: PtrOrigin::Stack(*slot),
                    min: 0,
                    max: 0,
                    limit,
                });
                ty = VerifierType::Ptr {
                    space: AddressSpace::Stack,
                    nullability,
                    bounds,
                    ringbuf_ref: None,
                };
            }
            state.set(*dst, ty);
        }
        MirInst::ReadStr {
            ptr, user_space, ..
        } => {
            let allowed = if *user_space {
                &[AddressSpace::User][..]
            } else {
                &[AddressSpace::Kernel, AddressSpace::Map, AddressSpace::Stack][..]
            };
            require_ptr_with_space(*ptr, "read_str", allowed, state, errors);
        }
        MirInst::EmitEvent { data, size } => {
            if *size > 8 {
                require_ptr_with_space(
                    *data,
                    "emit",
                    &[AddressSpace::Stack, AddressSpace::Map],
                    state,
                    errors,
                );
            }
        }
        MirInst::EmitRecord { fields } => {
            for field in fields {
                if let Some(MirType::Array { .. }) | Some(MirType::Ptr { .. }) =
                    types.get(&field.value)
                {
                    require_ptr_with_space(
                        field.value,
                        "emit record",
                        &[AddressSpace::Stack, AddressSpace::Map],
                        state,
                        errors,
                    );
                }
            }
        }
        MirInst::MapUpdate { map, key, .. } => {
            if !supports_generic_map_kind(map.kind) {
                errors.push(VerifierTypeError::new(format!(
                    "map operations do not support map kind {:?} for '{}'",
                    map.kind, map.name
                )));
            }
            if let VerifierType::Ptr { .. } = state.get(*key) {
                require_ptr_with_space(
                    *key,
                    "map key",
                    &[AddressSpace::Stack, AddressSpace::Map],
                    state,
                    errors,
                );
            }
        }
        MirInst::MapDelete { map, key } => {
            if !supports_generic_map_kind(map.kind) {
                errors.push(VerifierTypeError::new(format!(
                    "map operations do not support map kind {:?} for '{}'",
                    map.kind, map.name
                )));
            } else if matches!(map.kind, MapKind::Array | MapKind::PerCpuArray) {
                errors.push(VerifierTypeError::new(format!(
                    "map delete is not supported for array map kind {:?} ('{}')",
                    map.kind, map.name
                )));
            }
            if let VerifierType::Ptr { .. } = state.get(*key) {
                require_ptr_with_space(
                    *key,
                    "map key",
                    &[AddressSpace::Stack, AddressSpace::Map],
                    state,
                    errors,
                );
            }
        }
        MirInst::Histogram { .. }
        | MirInst::StartTimer
        | MirInst::TailCall { .. }
        | MirInst::Jump { .. }
        | MirInst::Branch { .. }
        | MirInst::Return { .. }
        | MirInst::LoopBack { .. }
        | MirInst::Placeholder => {}
        MirInst::ListPush { list, .. } => {
            require_ptr_with_space(*list, "list", &[AddressSpace::Stack], state, errors);
        }
        MirInst::StringAppend { dst_len, .. } | MirInst::IntToString { dst_len, .. } => {
            let ty = state.get(*dst_len);
            if matches!(ty, VerifierType::Uninit) {
                errors.push(VerifierTypeError::new(format!(
                    "string length uses uninitialized v{}",
                    dst_len.0
                )));
            }
        }
        MirInst::RecordStore { val, ty, .. } => {
            if matches!(ty, MirType::Array { .. } | MirType::Ptr { .. }) {
                if let MirValue::VReg(vreg) = val {
                    require_ptr_with_space(
                        *vreg,
                        "record store",
                        &[AddressSpace::Stack, AddressSpace::Map],
                        state,
                        errors,
                    );
                }
            }
        }
    }
}

fn check_uses_initialized(
    inst: &MirInst,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    for used in inst.uses() {
        if matches!(state.get(used), VerifierType::Uninit) {
            errors.push(VerifierTypeError::new(format!(
                "instruction uses uninitialized v{}",
                used.0
            )));
        }
    }
}

fn pointer_arith_result(
    op: BinOpKind,
    lhs: &MirValue,
    rhs: &MirValue,
    state: &VerifierState,
    slot_sizes: &HashMap<StackSlotId, i64>,
) -> Option<VerifierType> {
    if !matches!(op, BinOpKind::Add | BinOpKind::Sub) {
        return None;
    }

    let lhs_ty = value_type(lhs, state, slot_sizes);
    let rhs_ty = value_type(rhs, state, slot_sizes);

    let (ptr_ty, offset, is_add) = match op {
        BinOpKind::Add => match (&lhs_ty, &rhs_ty) {
            (VerifierType::Ptr { .. }, VerifierType::Scalar | VerifierType::Bool) => {
                (lhs_ty, rhs, true)
            }
            (VerifierType::Scalar | VerifierType::Bool, VerifierType::Ptr { .. }) => {
                (rhs_ty, lhs, true)
            }
            _ => return None,
        },
        BinOpKind::Sub => match (&lhs_ty, &rhs_ty) {
            (VerifierType::Ptr { .. }, VerifierType::Scalar | VerifierType::Bool) => {
                (lhs_ty, rhs, false)
            }
            _ => return None,
        },
        _ => return None,
    };

    let offset_range = value_range(offset, state);

    if let VerifierType::Ptr {
        space,
        nullability,
        bounds,
        ringbuf_ref,
    } = ptr_ty
    {
        let bounds = match (bounds, offset_range) {
            (Some(bounds), ValueRange::Known { min, max }) => {
                let (min_delta, max_delta) = if is_add { (min, max) } else { (-max, -min) };
                Some(PtrBounds {
                    origin: bounds.origin,
                    min: bounds.min.saturating_add(min_delta),
                    max: bounds.max.saturating_add(max_delta),
                    limit: bounds.limit,
                })
            }
            _ => None,
        };
        return Some(VerifierType::Ptr {
            space,
            nullability,
            bounds,
            ringbuf_ref,
        });
    }

    None
}

fn guard_from_compare(
    op: BinOpKind,
    lhs: &MirValue,
    rhs: &MirValue,
    state: &VerifierState,
) -> Option<Guard> {
    match (lhs, rhs) {
        (MirValue::VReg(v), MirValue::Const(c)) => guard_from_compare_reg_const(op, *v, *c, state),
        (MirValue::Const(c), MirValue::VReg(v)) => {
            guard_from_compare_reg_const(swap_compare(op)?, *v, *c, state)
        }
        (MirValue::VReg(lhs), MirValue::VReg(rhs)) => {
            let op = match op {
                BinOpKind::Eq
                | BinOpKind::Ne
                | BinOpKind::Lt
                | BinOpKind::Le
                | BinOpKind::Gt
                | BinOpKind::Ge => op,
                _ => return None,
            };
            let lhs_ty = state.get(*lhs);
            let rhs_ty = state.get(*rhs);
            if matches!(lhs_ty, VerifierType::Ptr { .. })
                || matches!(rhs_ty, VerifierType::Ptr { .. })
            {
                return None;
            }
            Some(Guard::RangeCmp {
                lhs: *lhs,
                rhs: *rhs,
                op,
            })
        }
        _ => None,
    }
}

fn guard_from_compare_reg_const(
    op: BinOpKind,
    reg: VReg,
    value: i64,
    state: &VerifierState,
) -> Option<Guard> {
    let op = match op {
        BinOpKind::Eq
        | BinOpKind::Ne
        | BinOpKind::Lt
        | BinOpKind::Le
        | BinOpKind::Gt
        | BinOpKind::Ge => op,
        _ => return None,
    };

    let ty = state.get(reg);
    if matches!(ty, VerifierType::Ptr { .. }) {
        if value == 0 && matches!(op, BinOpKind::Eq | BinOpKind::Ne) {
            return Some(Guard::Ptr {
                ptr: reg,
                true_is_non_null: matches!(op, BinOpKind::Ne),
            });
        }
        return None;
    }

    if value == 0 && matches!(op, BinOpKind::Eq | BinOpKind::Ne) {
        return Some(Guard::NonZero {
            reg,
            true_is_non_zero: matches!(op, BinOpKind::Ne),
        });
    }

    Some(Guard::Range { reg, op, value })
}

fn swap_compare(op: BinOpKind) -> Option<BinOpKind> {
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

fn negate_compare(op: BinOpKind) -> Option<BinOpKind> {
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

fn effective_branch_compare(op: BinOpKind, take_true: bool) -> Option<BinOpKind> {
    if take_true {
        Some(op)
    } else {
        negate_compare(op)
    }
}

fn range_may_equal(range: ValueRange, value: i64) -> bool {
    match range {
        ValueRange::Known { min, max } => value >= min && value <= max,
        ValueRange::Unknown => true,
    }
}

fn range_can_satisfy_const_compare(
    range: ValueRange,
    excluded: &[i64],
    op: BinOpKind,
    value: i64,
) -> bool {
    match op {
        BinOpKind::Eq => {
            if excluded.contains(&value) {
                return false;
            }
            range_may_equal(range, value)
        }
        BinOpKind::Ne => match range {
            ValueRange::Known { min, max } => !(min == max && min == value),
            ValueRange::Unknown => true,
        },
        BinOpKind::Lt => match range {
            ValueRange::Known { min, .. } => min < value,
            ValueRange::Unknown => true,
        },
        BinOpKind::Le => match range {
            ValueRange::Known { min, .. } => min <= value,
            ValueRange::Unknown => true,
        },
        BinOpKind::Gt => match range {
            ValueRange::Known { max, .. } => max > value,
            ValueRange::Unknown => true,
        },
        BinOpKind::Ge => match range {
            ValueRange::Known { max, .. } => max >= value,
            ValueRange::Unknown => true,
        },
        _ => true,
    }
}

fn ranges_can_satisfy_compare(lhs: ValueRange, rhs: ValueRange, op: BinOpKind) -> bool {
    let Some((lhs_min, lhs_max)) = range_bounds(lhs) else {
        return true;
    };
    let Some((rhs_min, rhs_max)) = range_bounds(rhs) else {
        return true;
    };

    match op {
        BinOpKind::Eq => lhs_min <= rhs_max && rhs_min <= lhs_max,
        BinOpKind::Ne => !(lhs_min == lhs_max && rhs_min == rhs_max && lhs_min == rhs_min),
        BinOpKind::Lt => lhs_min < rhs_max,
        BinOpKind::Le => lhs_min <= rhs_max,
        BinOpKind::Gt => lhs_max > rhs_min,
        BinOpKind::Ge => lhs_max >= rhs_min,
        _ => true,
    }
}

fn refine_range(current: ValueRange, op: BinOpKind, value: i64, take_true: bool) -> ValueRange {
    let op = if take_true {
        op
    } else {
        let Some(negated) = negate_compare(op) else {
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
            ValueRange::Unknown => ValueRange::Unknown,
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

    intersect_range(current, min, max)
}

fn refine_compare_ranges(
    lhs: ValueRange,
    rhs: ValueRange,
    op: BinOpKind,
    take_true: bool,
) -> (ValueRange, ValueRange) {
    let op = if take_true {
        op
    } else {
        let Some(negated) = negate_compare(op) else {
            return (lhs, rhs);
        };
        negated
    };

    let lhs_bounds = range_bounds(lhs);
    let rhs_bounds = range_bounds(rhs);

    match op {
        BinOpKind::Eq => {
            let lhs = match rhs_bounds {
                Some((min, max)) => intersect_range(lhs, Some(min), Some(max)),
                None => lhs,
            };
            let rhs = match lhs_bounds {
                Some((min, max)) => intersect_range(rhs, Some(min), Some(max)),
                None => rhs,
            };
            (lhs, rhs)
        }
        BinOpKind::Ne => {
            let lhs = if let Some((min, max)) = rhs_bounds {
                if min == max {
                    refine_range(lhs, BinOpKind::Ne, min, true)
                } else {
                    lhs
                }
            } else {
                lhs
            };
            let rhs = if let Some((min, max)) = lhs_bounds {
                if min == max {
                    refine_range(rhs, BinOpKind::Ne, min, true)
                } else {
                    rhs
                }
            } else {
                rhs
            };
            (lhs, rhs)
        }
        BinOpKind::Lt => {
            let lhs = match rhs_bounds {
                Some((_, rhs_max)) => {
                    let max = rhs_max.saturating_sub(1);
                    intersect_range(lhs, None, Some(max))
                }
                None => lhs,
            };
            let rhs = match lhs_bounds {
                Some((lhs_min, _)) => {
                    let min = lhs_min.saturating_add(1);
                    intersect_range(rhs, Some(min), None)
                }
                None => rhs,
            };
            (lhs, rhs)
        }
        BinOpKind::Le => {
            let lhs = match rhs_bounds {
                Some((_, rhs_max)) => intersect_range(lhs, None, Some(rhs_max)),
                None => lhs,
            };
            let rhs = match lhs_bounds {
                Some((lhs_min, _)) => intersect_range(rhs, Some(lhs_min), None),
                None => rhs,
            };
            (lhs, rhs)
        }
        BinOpKind::Gt => {
            let lhs = match rhs_bounds {
                Some((rhs_min, _)) => {
                    let min = rhs_min.saturating_add(1);
                    intersect_range(lhs, Some(min), None)
                }
                None => lhs,
            };
            let rhs = match lhs_bounds {
                Some((_, lhs_max)) => {
                    let max = lhs_max.saturating_sub(1);
                    intersect_range(rhs, None, Some(max))
                }
                None => rhs,
            };
            (lhs, rhs)
        }
        BinOpKind::Ge => {
            let lhs = match rhs_bounds {
                Some((rhs_min, _)) => intersect_range(lhs, Some(rhs_min), None),
                None => lhs,
            };
            let rhs = match lhs_bounds {
                Some((_, lhs_max)) => intersect_range(rhs, None, Some(lhs_max)),
                None => rhs,
            };
            (lhs, rhs)
        }
        _ => (lhs, rhs),
    }
}

fn range_bounds(range: ValueRange) -> Option<(i64, i64)> {
    match range {
        ValueRange::Known { min, max } => Some((min, max)),
        ValueRange::Unknown => None,
    }
}

fn intersect_range(current: ValueRange, min: Option<i64>, max: Option<i64>) -> ValueRange {
    if min.is_none() && max.is_none() {
        return current;
    }
    match current {
        ValueRange::Known {
            min: cur_min,
            max: cur_max,
        } => {
            let min = min.map(|v| cur_min.max(v)).unwrap_or(cur_min);
            let max = max.map(|v| cur_max.min(v)).unwrap_or(cur_max);
            if min <= max {
                ValueRange::Known { min, max }
            } else {
                ValueRange::Known {
                    min: cur_min,
                    max: cur_max,
                }
            }
        }
        ValueRange::Unknown => {
            let min = min.unwrap_or(i64::MIN);
            let max = max.unwrap_or(i64::MAX);
            if min <= max {
                ValueRange::Known { min, max }
            } else {
                ValueRange::Unknown
            }
        }
    }
}

fn require_ptr_with_space(
    ptr: VReg,
    op: &str,
    allowed: &[AddressSpace],
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) -> Option<VerifierType> {
    match state.get(ptr) {
        VerifierType::Ptr {
            nullability: Nullability::NonNull,
            space,
            bounds,
            ringbuf_ref,
        } => {
            if !allowed.contains(&space) {
                errors.push(VerifierTypeError::new(format!(
                    "{op} expects pointer in {:?}, got {:?}",
                    allowed, space
                )));
            }
            Some(VerifierType::Ptr {
                space,
                nullability: Nullability::NonNull,
                bounds,
                ringbuf_ref,
            })
        }
        VerifierType::Ptr {
            nullability: Nullability::Null,
            ..
        } => {
            errors.push(VerifierTypeError::new(format!(
                "{op} uses null pointer v{}",
                ptr.0
            )));
            None
        }
        VerifierType::Ptr {
            nullability: Nullability::MaybeNull,
            ..
        } => {
            errors.push(VerifierTypeError::new(format!(
                "{op} may dereference null pointer v{} (add a null check)",
                ptr.0
            )));
            None
        }
        VerifierType::Uninit => {
            errors.push(VerifierTypeError::new(format!(
                "{op} uses uninitialized pointer v{}",
                ptr.0
            )));
            None
        }
        other => {
            errors.push(VerifierTypeError::new(format!(
                "{op} requires pointer type, got {:?}",
                other
            )));
            None
        }
    }
}

fn check_helper_arg(
    helper_id: u32,
    arg_idx: usize,
    arg: &MirValue,
    expected: HelperArgKind,
    state: &VerifierState,
    slot_sizes: &HashMap<StackSlotId, i64>,
    errors: &mut Vec<VerifierTypeError>,
) {
    let ty = value_type(arg, state, slot_sizes);
    match expected {
        HelperArgKind::Scalar => {
            if !matches!(ty, VerifierType::Scalar | VerifierType::Bool) {
                errors.push(VerifierTypeError::new(format!(
                    "helper {} arg{} expects scalar, got {:?}",
                    helper_id, arg_idx, ty
                )));
            }
        }
        HelperArgKind::Pointer => {
            if !matches!(ty, VerifierType::Ptr { .. }) {
                errors.push(VerifierTypeError::new(format!(
                    "helper {} arg{} expects pointer, got {:?}",
                    helper_id, arg_idx, ty
                )));
            }
        }
    }
}

fn helper_positive_size_upper_bound(
    helper_id: u32,
    arg_idx: usize,
    value: &MirValue,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) -> Option<usize> {
    match value_range(value, state) {
        ValueRange::Known { min, max } => {
            if max <= 0 || min <= 0 {
                errors.push(VerifierTypeError::new(format!(
                    "helper {} arg{} must be > 0",
                    helper_id, arg_idx
                )));
                return None;
            }
            usize::try_from(max).ok()
        }
        _ => None,
    }
}

fn check_helper_ptr_arg_value(
    helper_id: u32,
    arg_idx: usize,
    arg: &MirValue,
    op: &str,
    allow_stack: bool,
    allow_map: bool,
    allow_kernel: bool,
    allow_user: bool,
    access_size: Option<usize>,
    state: &VerifierState,
    slot_sizes: &HashMap<StackSlotId, i64>,
    errors: &mut Vec<VerifierTypeError>,
) {
    let allowed = helper_allowed_spaces(allow_stack, allow_map, allow_kernel, allow_user);
    match arg {
        MirValue::VReg(vreg) => {
            let Some(VerifierType::Ptr { space, bounds, .. }) =
                require_ptr_with_space(*vreg, op, allowed, state, errors)
            else {
                return;
            };
            if let Some(size) = access_size {
                check_ptr_bounds(op, space, bounds, 0, size, errors);
            }
        }
        MirValue::StackSlot(slot) => {
            if !allowed.contains(&AddressSpace::Stack) {
                errors.push(VerifierTypeError::new(format!(
                    "{op} expects pointer in {:?}, got stack slot {}",
                    allowed, slot.0
                )));
                return;
            }
            if let Some(size) = access_size {
                check_slot_access(*slot, 0, size, slot_sizes, op, errors);
            }
        }
        MirValue::Const(_) => {
            errors.push(VerifierTypeError::new(format!(
                "helper {} arg{} expects pointer value",
                helper_id, arg_idx
            )));
        }
    }
}

fn helper_allowed_spaces(
    allow_stack: bool,
    allow_map: bool,
    allow_kernel: bool,
    allow_user: bool,
) -> &'static [AddressSpace] {
    match (allow_stack, allow_map, allow_kernel, allow_user) {
        (true, true, false, false) => &[AddressSpace::Stack, AddressSpace::Map],
        (true, true, true, false) => &[AddressSpace::Stack, AddressSpace::Map, AddressSpace::Kernel],
        (false, false, true, false) => &[AddressSpace::Kernel],
        (false, false, false, true) => &[AddressSpace::User],
        (true, false, false, false) => &[AddressSpace::Stack],
        (false, true, false, false) => &[AddressSpace::Map],
        (false, false, false, false) => &[],
        _ => &[AddressSpace::Stack, AddressSpace::Map, AddressSpace::Kernel, AddressSpace::User],
    }
}

fn apply_helper_semantics(
    helper_id: u32,
    args: &[MirValue],
    state: &mut VerifierState,
    slot_sizes: &HashMap<StackSlotId, i64>,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(helper) = BpfHelper::from_u32(helper_id) else {
        return;
    };

    let semantics = helper.semantics();
    let mut positive_size_bounds: [Option<usize>; 5] = [None; 5];
    for size_arg in semantics.positive_size_args {
        if let Some(value) = args.get(*size_arg) {
            positive_size_bounds[*size_arg] =
                helper_positive_size_upper_bound(helper_id, *size_arg, value, state, errors);
        }
    }

    for rule in semantics.ptr_arg_rules {
        let Some(arg) = args.get(rule.arg_idx) else {
            continue;
        };
        let access_size = match (rule.fixed_size, rule.size_from_arg) {
            (Some(size), _) => Some(size),
            (None, Some(size_arg)) => positive_size_bounds[size_arg],
            (None, None) => None,
        };
        check_helper_ptr_arg_value(
            helper_id,
            rule.arg_idx,
            arg,
            rule.op,
            rule.allowed.allow_stack,
            rule.allowed.allow_map,
            rule.allowed.allow_kernel,
            rule.allowed.allow_user,
            access_size,
            state,
            slot_sizes,
            errors,
        );
    }

    if semantics.ringbuf_record_arg0 {
        if let Some(record) = args.first() {
            match record {
                MirValue::VReg(vreg) => match state.get(*vreg) {
                    VerifierType::Ptr {
                        space: AddressSpace::Map,
                        nullability: Nullability::NonNull,
                        ringbuf_ref: Some(ref_id),
                        ..
                    } => {
                        state.invalidate_ringbuf_ref(ref_id);
                    }
                    VerifierType::Ptr {
                        nullability: Nullability::MaybeNull,
                        ..
                    } => {
                        errors.push(VerifierTypeError::new(format!(
                            "helper {} arg0 may dereference null pointer v{} (add a null check)",
                            helper_id, vreg.0
                        )));
                    }
                    VerifierType::Ptr { .. } => {
                        errors.push(VerifierTypeError::new(format!(
                            "helper {} arg0 expects ringbuf record pointer",
                            helper_id
                        )));
                    }
                    _ => {
                        errors.push(VerifierTypeError::new(format!(
                            "helper {} arg0 expects ringbuf record pointer",
                            helper_id
                        )));
                    }
                },
                _ => {
                    errors.push(VerifierTypeError::new(format!(
                        "helper {} arg0 expects ringbuf record pointer",
                        helper_id
                    )));
                }
            }
        }
    }
}

fn check_ptr_bounds(
    op: &str,
    space: AddressSpace,
    bounds: Option<PtrBounds>,
    offset: i32,
    size: usize,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(bounds) = bounds else {
        return;
    };

    match (space, bounds.origin) {
        (AddressSpace::Stack, PtrOrigin::Stack(_)) | (AddressSpace::Map, PtrOrigin::Map) => {}
        _ => return,
    }

    let size = size as i64;
    let offset = offset as i64;
    let start = bounds.min.saturating_add(offset);
    let end = bounds
        .max
        .saturating_add(offset)
        .saturating_add(size.saturating_sub(1));

    if start < 0 || end > bounds.limit {
        let origin = match bounds.origin {
            PtrOrigin::Stack(slot) => format!("stack slot {}", slot.0),
            PtrOrigin::Map => "map value".to_string(),
        };
        errors.push(VerifierTypeError::new(format!(
            "{op} out of bounds for {origin}: access [{start}..{end}] exceeds 0..{}",
            bounds.limit
        )));
    }
}

fn check_ptr_access(
    ptr: VReg,
    op: &str,
    allowed: &[AddressSpace],
    offset: i32,
    size: usize,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(VerifierType::Ptr { space, bounds, .. }) =
        require_ptr_with_space(ptr, op, allowed, state, errors)
    else {
        return;
    };
    check_ptr_bounds(op, space, bounds, offset, size, errors);
}

fn check_slot_access(
    slot: StackSlotId,
    offset: i32,
    size: usize,
    slot_sizes: &HashMap<StackSlotId, i64>,
    op: &str,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(limit) = slot_sizes.get(&slot).copied() else {
        return;
    };
    let size = size as i64;
    let offset = offset as i64;
    let start = offset;
    let end = offset.saturating_add(size.saturating_sub(1));
    if start < 0 || end > limit {
        errors.push(VerifierTypeError::new(format!(
            "{op} out of bounds for stack slot {}: access [{start}..{end}] exceeds 0..{}",
            slot.0, limit
        )));
    }
}

fn value_type(
    value: &MirValue,
    state: &VerifierState,
    slot_sizes: &HashMap<StackSlotId, i64>,
) -> VerifierType {
    match value {
        MirValue::Const(_) => VerifierType::Scalar,
        MirValue::VReg(v) => state.get(*v),
        MirValue::StackSlot(slot) => {
            let bounds = slot_sizes.get(slot).copied().map(|limit| PtrBounds {
                origin: PtrOrigin::Stack(*slot),
                min: 0,
                max: 0,
                limit,
            });
            VerifierType::Ptr {
                space: AddressSpace::Stack,
                nullability: Nullability::NonNull,
                bounds,
                ringbuf_ref: None,
            }
        }
    }
}

fn value_range(value: &MirValue, state: &VerifierState) -> ValueRange {
    match value {
        MirValue::Const(c) => ValueRange::Known { min: *c, max: *c },
        MirValue::VReg(v) => {
            let mut range = state.get_range(*v);
            if state.is_non_zero(*v) {
                range = match range {
                    ValueRange::Known { min, max } => {
                        if min < 0 && max > 0 {
                            ValueRange::Unknown
                        } else if min == 0 && max > 0 {
                            ValueRange::Known { min: 1, max }
                        } else if max == 0 && min < 0 {
                            ValueRange::Known { min, max: -1 }
                        } else if min == 0 && max == 0 {
                            ValueRange::Unknown
                        } else {
                            ValueRange::Known { min, max }
                        }
                    }
                    ValueRange::Unknown => ValueRange::Unknown,
                };
            }
            range
        }
        MirValue::StackSlot(_) => ValueRange::Unknown,
    }
}

fn verifier_type_from_mir(ty: &MirType) -> VerifierType {
    match ty {
        MirType::Bool => VerifierType::Bool,
        MirType::Array { .. } => VerifierType::Ptr {
            space: AddressSpace::Stack,
            nullability: Nullability::NonNull,
            bounds: None,
            ringbuf_ref: None,
        },
        MirType::Ptr { address_space, .. } => VerifierType::Ptr {
            space: *address_space,
            nullability: match address_space {
                AddressSpace::Stack => Nullability::NonNull,
                AddressSpace::Map => Nullability::MaybeNull,
                AddressSpace::Kernel | AddressSpace::User => Nullability::MaybeNull,
            },
            bounds: None,
            ringbuf_ref: None,
        },
        MirType::Unknown => VerifierType::Unknown,
        _ => VerifierType::Scalar,
    }
}

fn join_type(a: VerifierType, b: VerifierType) -> VerifierType {
    use VerifierType::*;
    match (a, b) {
        (Uninit, other) | (other, Uninit) => other,
        (Unknown, _) | (_, Unknown) => Unknown,
        (Scalar, Scalar) => Scalar,
        (Bool, Bool) => Bool,
        (
            Ptr {
                space: sa,
                nullability: na,
                bounds: ba,
                ringbuf_ref: ra,
            },
            Ptr {
                space: sb,
                nullability: nb,
                bounds: bb,
                ringbuf_ref: rb,
            },
        ) => {
            if sa != sb {
                return Unknown;
            }
            let nullability = join_nullability(na, nb);
            let bounds = join_bounds(ba, bb);
            let ringbuf_ref = join_ringbuf_ref(ra, rb);
            Ptr {
                space: sa,
                nullability,
                bounds,
                ringbuf_ref,
            }
        }
        (Scalar, Bool) | (Bool, Scalar) => Scalar,
        _ => Unknown,
    }
}

fn join_nullability(a: Nullability, b: Nullability) -> Nullability {
    match (a, b) {
        (Nullability::Null, Nullability::Null) => Nullability::Null,
        (Nullability::NonNull, Nullability::NonNull) => Nullability::NonNull,
        _ => Nullability::MaybeNull,
    }
}

fn join_bounds(a: Option<PtrBounds>, b: Option<PtrBounds>) -> Option<PtrBounds> {
    match (a, b) {
        (Some(a), Some(b)) if a.origin == b.origin && a.limit == b.limit => Some(PtrBounds {
            origin: a.origin,
            min: a.min.min(b.min),
            max: a.max.max(b.max),
            limit: a.limit,
        }),
        _ => None,
    }
}

fn join_ringbuf_ref(a: Option<VReg>, b: Option<VReg>) -> Option<VReg> {
    match (a, b) {
        (Some(a), Some(b)) if a == b => Some(a),
        (Some(_), Some(_)) => None,
        (None, None) => None,
        _ => None,
    }
}

fn map_value_limit(map: &MapRef) -> Option<i64> {
    match map.name.as_str() {
        COUNTER_MAP_NAME | STRING_COUNTER_MAP_NAME | HISTOGRAM_MAP_NAME | TIMESTAMP_MAP_NAME => {
            Some(8 - 1)
        }
        KSTACK_MAP_NAME | USTACK_MAP_NAME => Some((127 * 8) - 1),
        _ => None,
    }
}

fn supports_generic_map_kind(kind: MapKind) -> bool {
    matches!(
        kind,
        MapKind::Hash | MapKind::Array | MapKind::PerCpuHash | MapKind::PerCpuArray
    )
}

fn map_value_limit_from_dst_type(dst_ty: Option<&MirType>) -> Option<i64> {
    let pointee = match dst_ty {
        Some(MirType::Ptr { pointee, .. }) => pointee.as_ref(),
        _ => return None,
    };
    if matches!(pointee, MirType::Unknown) {
        return None;
    }
    let size = pointee.size();
    if size == 0 {
        return None;
    }
    Some(size.saturating_sub(1) as i64)
}

fn join_range(a: ValueRange, b: ValueRange) -> ValueRange {
    match (a, b) {
        (
            ValueRange::Known {
                min: a_min,
                max: a_max,
            },
            ValueRange::Known {
                min: b_min,
                max: b_max,
            },
        ) => ValueRange::Known {
            min: a_min.min(b_min),
            max: a_max.max(b_max),
        },
        _ => ValueRange::Unknown,
    }
}

fn range_add(a: ValueRange, b: ValueRange) -> ValueRange {
    match (a, b) {
        (
            ValueRange::Known {
                min: a_min,
                max: a_max,
            },
            ValueRange::Known {
                min: b_min,
                max: b_max,
            },
        ) => ValueRange::Known {
            min: a_min.saturating_add(b_min),
            max: a_max.saturating_add(b_max),
        },
        _ => ValueRange::Unknown,
    }
}

fn range_sub(a: ValueRange, b: ValueRange) -> ValueRange {
    match (a, b) {
        (
            ValueRange::Known {
                min: a_min,
                max: a_max,
            },
            ValueRange::Known {
                min: b_min,
                max: b_max,
            },
        ) => ValueRange::Known {
            min: a_min.saturating_sub(b_max),
            max: a_max.saturating_sub(b_min),
        },
        _ => ValueRange::Unknown,
    }
}

fn range_for_binop(
    op: BinOpKind,
    lhs: &MirValue,
    rhs: &MirValue,
    state: &VerifierState,
) -> ValueRange {
    let lhs_range = value_range(lhs, state);
    let rhs_range = value_range(rhs, state);
    match op {
        BinOpKind::Add => range_add(lhs_range, rhs_range),
        BinOpKind::Sub => range_sub(lhs_range, rhs_range),
        BinOpKind::Mul => range_mul(lhs_range, rhs_range),
        BinOpKind::Div => range_div(lhs_range, rhs_range),
        BinOpKind::Mod => range_mod(lhs_range, rhs_range),
        BinOpKind::Shl => range_shift(lhs_range, rhs_range, true),
        BinOpKind::Shr => range_shift(lhs_range, rhs_range, false),
        BinOpKind::And => range_and(lhs_range, rhs_range),
        BinOpKind::Or => range_or(lhs_range, rhs_range),
        BinOpKind::Xor => range_xor(lhs_range, rhs_range),
        _ => ValueRange::Unknown,
    }
}

fn range_for_phi(args: &[(BlockId, VReg)], state: &VerifierState) -> ValueRange {
    let mut merged = None;
    for (_, vreg) in args {
        let range = state.get_range(*vreg);
        merged = Some(match merged {
            None => range,
            Some(current) => join_range(current, range),
        });
    }
    merged.unwrap_or(ValueRange::Unknown)
}

fn clamp_i128_to_i64(value: i128) -> i64 {
    if value > i64::MAX as i128 {
        i64::MAX
    } else if value < i64::MIN as i128 {
        i64::MIN
    } else {
        value as i64
    }
}

fn range_mul(a: ValueRange, b: ValueRange) -> ValueRange {
    match (a, b) {
        (
            ValueRange::Known {
                min: a_min,
                max: a_max,
            },
            ValueRange::Known {
                min: b_min,
                max: b_max,
            },
        ) => {
            let candidates = [
                (a_min as i128) * (b_min as i128),
                (a_min as i128) * (b_max as i128),
                (a_max as i128) * (b_min as i128),
                (a_max as i128) * (b_max as i128),
            ];
            let mut min = i128::MAX;
            let mut max = i128::MIN;
            for val in candidates {
                min = min.min(val);
                max = max.max(val);
            }
            ValueRange::Known {
                min: clamp_i128_to_i64(min),
                max: clamp_i128_to_i64(max),
            }
        }
        _ => ValueRange::Unknown,
    }
}

fn range_shift(lhs: ValueRange, rhs: ValueRange, is_left: bool) -> ValueRange {
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
    let lhs_vals = [lhs_min, lhs_max];
    let rhs_vals = [rhs_min, rhs_max];
    for lhs_val in lhs_vals {
        for rhs_val in rhs_vals {
            let shifted = if is_left {
                (lhs_val as i128) << rhs_val
            } else {
                (lhs_val as i128) >> rhs_val
            };
            min = min.min(shifted);
            max = max.max(shifted);
        }
    }

    ValueRange::Known {
        min: clamp_i128_to_i64(min),
        max: clamp_i128_to_i64(max),
    }
}

fn range_div(lhs: ValueRange, rhs: ValueRange) -> ValueRange {
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
            let mut min = i128::MAX;
            let mut max = i128::MIN;
            for val in candidates {
                min = min.min(val);
                max = max.max(val);
            }
            ValueRange::Known {
                min: clamp_i128_to_i64(min),
                max: clamp_i128_to_i64(max),
            }
        }
        _ => ValueRange::Unknown,
    }
}

fn range_mod(lhs: ValueRange, rhs: ValueRange) -> ValueRange {
    match (lhs, rhs) {
        (
            ValueRange::Known {
                min: lhs_min,
                max: _lhs_max,
            },
            ValueRange::Known {
                min: rhs_min,
                max: rhs_max,
            },
        ) => {
            if rhs_min <= 0 || rhs_max <= 0 {
                return ValueRange::Unknown;
            }
            if lhs_min < 0 {
                return ValueRange::Unknown;
            }
            let max_mod = rhs_max.saturating_sub(1);
            ValueRange::Known {
                min: 0,
                max: max_mod,
            }
        }
        _ => ValueRange::Unknown,
    }
}

fn range_and(lhs: ValueRange, rhs: ValueRange) -> ValueRange {
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
        return ValueRange::Known { min: val, max: val };
    }
    if lhs_min < 0 || rhs_min < 0 {
        return ValueRange::Unknown;
    }
    let mask = mask_for_max(lhs_max) & mask_for_max(rhs_max);
    let max = lhs_max.min(rhs_max).min(mask as i64);
    ValueRange::Known { min: 0, max }
}

fn range_or(lhs: ValueRange, rhs: ValueRange) -> ValueRange {
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
        return ValueRange::Known { min: val, max: val };
    }
    if lhs_min < 0 || rhs_min < 0 {
        return ValueRange::Unknown;
    }
    let mask = mask_for_max(lhs_max) | mask_for_max(rhs_max);
    let max = (mask as i64).min(lhs_max.saturating_add(rhs_max));
    ValueRange::Known { min: 0, max }
}

fn range_xor(lhs: ValueRange, rhs: ValueRange) -> ValueRange {
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
        return ValueRange::Known { min: val, max: val };
    }
    if lhs_min < 0 || rhs_min < 0 {
        return ValueRange::Unknown;
    }
    let mask = mask_for_max(lhs_max) | mask_for_max(rhs_max);
    let max = (mask as i64).min(lhs_max.saturating_add(rhs_max));
    ValueRange::Known { min: 0, max }
}

fn mask_for_max(max: i64) -> u64 {
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

fn ptr_type_for_phi(args: &[(BlockId, VReg)], state: &VerifierState) -> Option<VerifierType> {
    let mut merged: Option<VerifierType> = None;
    for (_, vreg) in args {
        let ty = state.get(*vreg);
        if !matches!(ty, VerifierType::Ptr { .. }) {
            return None;
        }
        merged = Some(match merged {
            None => ty,
            Some(existing) => join_type(existing, ty),
        });
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::mir::{COUNTER_MAP_NAME, MapKind, MapRef, MirType, StackSlotKind};

    fn map_lookup_types(func: &MirFunction, vreg: VReg) -> HashMap<VReg, MirType> {
        let mut types = HashMap::new();
        for i in 0..func.vreg_count {
            types.insert(VReg(i), MirType::I64);
        }
        types.insert(
            vreg,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Map,
            },
        );
        types
    }

    #[test]
    fn test_map_lookup_requires_null_check() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::Const(0),
        });
        func.block_mut(entry).instructions.push(MirInst::MapLookup {
            dst,
            map: MapRef {
                name: "test".to_string(),
                kind: MapKind::Hash,
            },
            key,
        });
        let load_dst = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::Load {
            dst: load_dst,
            ptr: dst,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let types = map_lookup_types(&func, dst);
        let err = verify_mir(&func, &types).expect_err("expected null-check error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("may dereference null"))
        );
    }

    #[test]
    fn test_map_lookup_null_check_ok() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let ok = func.alloc_block();
        let bad = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let cond = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::Const(0),
        });
        func.block_mut(entry).instructions.push(MirInst::MapLookup {
            dst,
            map: MapRef {
                name: "test".to_string(),
                kind: MapKind::Hash,
            },
            key,
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(dst),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: ok,
            if_false: bad,
        };

        let ok_load = func.alloc_vreg();
        func.block_mut(ok).instructions.push(MirInst::Load {
            dst: ok_load,
            ptr: dst,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(ok).terminator = MirInst::Return { val: None };

        func.block_mut(bad).terminator = MirInst::Return { val: None };

        let types = map_lookup_types(&func, dst);
        verify_mir(&func, &types).expect("expected verifier pass");
    }

    #[test]
    fn test_typed_map_pointer_param_requires_null_check_before_load() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let map_ptr = func.alloc_vreg();
        func.param_count = 1;
        let dst = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::Load {
            dst,
            ptr: map_ptr,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            map_ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Map,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected null-check error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("may dereference null pointer")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_map_lookup_rejects_unsupported_map_kind() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        let dst = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::Const(0),
        });
        func.block_mut(entry).instructions.push(MirInst::MapLookup {
            dst,
            map: MapRef {
                name: "events".to_string(),
                kind: MapKind::RingBuf,
            },
            key,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            dst,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Map,
            },
        );
        let err = verify_mir(&func, &types).expect_err("expected unsupported map-kind error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("map operations do not support map kind")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_map_delete_rejects_array_map_kind() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::Const(0),
        });
        func.block_mut(entry).instructions.push(MirInst::MapDelete {
            map: MapRef {
                name: "arr".to_string(),
                kind: MapKind::Array,
            },
            key,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let err = verify_mir(&func, &HashMap::new()).expect_err("expected array delete error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("map delete is not supported for array map kind")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_pointer_arg_required() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: 16, // bpf_get_current_comm(buf, size)
                args: vec![MirValue::Const(0), MirValue::Const(16)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);
        let err = verify_mir(&func, &types).expect_err("expected helper pointer-arg error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("arg0 expects pointer")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_map_lookup_requires_null_check() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let map = func.alloc_vreg();
        let key = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let load_dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: map,
            src: MirValue::StackSlot(map_slot),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::StackSlot(key_slot),
        });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: 1, // bpf_map_lookup_elem(map, key)
                args: vec![MirValue::VReg(map), MirValue::VReg(key)],
            });
        func.block_mut(entry).instructions.push(MirInst::Load {
            dst: load_dst,
            ptr: dst,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            dst,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Map,
            },
        );
        types.insert(load_dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper null-check error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("may dereference null"))
        );
    }

    #[test]
    fn test_helper_map_lookup_rejects_out_of_bounds_key_pointer() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let map = func.alloc_vreg();
        let key_base = func.alloc_vreg();
        let key = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: map,
            src: MirValue::StackSlot(map_slot),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key_base,
            src: MirValue::StackSlot(key_slot),
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: key,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(key_base),
            rhs: MirValue::Const(8),
        });
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: 1, // bpf_map_lookup_elem(map, key)
                args: vec![MirValue::VReg(map), MirValue::VReg(key)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper key bounds error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("helper map_lookup key out of bounds")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_map_lookup_rejects_user_map_pointer() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let call = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let map = func.alloc_vreg();
        func.param_count = 1;
        let cond = func.alloc_vreg();
        let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(map),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: call,
            if_false: done,
        };

        func.block_mut(call).instructions.push(MirInst::CallHelper {
            dst,
            helper: 1, // bpf_map_lookup_elem(map, key)
            args: vec![MirValue::VReg(map), MirValue::StackSlot(key_slot)],
        });
        func.block_mut(call).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            map,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::User,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper map pointer-space error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("helper map_lookup map expects pointer in [Stack]")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_map_update_rejects_map_lookup_value_as_map_arg() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let call = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let key_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let lookup = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let update_ret = func.alloc_vreg();

        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: lookup,
                helper: 1, // bpf_map_lookup_elem(map, key)
                args: vec![MirValue::StackSlot(map_slot), MirValue::StackSlot(key_slot)],
            });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(lookup),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: call,
            if_false: done,
        };

        func.block_mut(call).instructions.push(MirInst::CallHelper {
            dst: update_ret,
            helper: 2, // bpf_map_update_elem(map, key, value, flags)
            args: vec![
                MirValue::VReg(lookup),
                MirValue::StackSlot(key_slot),
                MirValue::StackSlot(value_slot),
                MirValue::Const(0),
            ],
        });
        func.block_mut(call).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            lookup,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Map,
            },
        );
        types.insert(update_ret, MirType::I64);

        let err =
            verify_mir(&func, &types).expect_err("expected map-value pointer map-arg rejection");
        assert!(
            err.iter()
                .any(|e| e.message.contains("helper map_update map expects pointer in [Stack]")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_ringbuf_reserve_submit_releases_reference() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let submit = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let record = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let submit_ret = func.alloc_vreg();

        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: record,
                helper: 131, // bpf_ringbuf_reserve(map, size, flags)
                args: vec![
                    MirValue::StackSlot(map_slot),
                    MirValue::Const(8),
                    MirValue::Const(0),
                ],
            });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(record),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: submit,
            if_false: done,
        };

        func.block_mut(submit)
            .instructions
            .push(MirInst::CallHelper {
                dst: submit_ret,
                helper: 132, // bpf_ringbuf_submit(data, flags)
                args: vec![MirValue::VReg(record), MirValue::Const(0)],
            });
        func.block_mut(submit).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(submit_ret, MirType::I64);
        verify_mir(&func, &types).expect("expected ringbuf reference to be released");
    }

    #[test]
    fn test_helper_ringbuf_reserve_leak_is_rejected() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let leak = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let record = func.alloc_vreg();
        let cond = func.alloc_vreg();

        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: record,
                helper: 131, // bpf_ringbuf_reserve(map, size, flags)
                args: vec![
                    MirValue::StackSlot(map_slot),
                    MirValue::Const(8),
                    MirValue::Const(0),
                ],
            });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(record),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: leak,
            if_false: done,
        };

        func.block_mut(leak).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let err = verify_mir(&func, &HashMap::new()).expect_err("expected leak error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("unreleased ringbuf record reference")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_ringbuf_submit_requires_ringbuf_record_pointer() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: 132, // bpf_ringbuf_submit(data, flags)
                args: vec![MirValue::StackSlot(slot), MirValue::Const(0)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);
        let err = verify_mir(&func, &types).expect_err("expected ringbuf pointer-kind error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("helper 132 arg0 expects ringbuf record pointer")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_ringbuf_submit_rejects_double_release() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let submit = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let record = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let submit_ret0 = func.alloc_vreg();
        let submit_ret1 = func.alloc_vreg();

        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: record,
                helper: 131, // bpf_ringbuf_reserve(map, size, flags)
                args: vec![
                    MirValue::StackSlot(map_slot),
                    MirValue::Const(8),
                    MirValue::Const(0),
                ],
            });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(record),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: submit,
            if_false: done,
        };

        func.block_mut(submit)
            .instructions
            .push(MirInst::CallHelper {
                dst: submit_ret0,
                helper: 132, // bpf_ringbuf_submit(data, flags)
                args: vec![MirValue::VReg(record), MirValue::Const(0)],
            });
        func.block_mut(submit)
            .instructions
            .push(MirInst::CallHelper {
                dst: submit_ret1,
                helper: 132, // bpf_ringbuf_submit(data, flags)
                args: vec![MirValue::VReg(record), MirValue::Const(0)],
            });
        func.block_mut(submit).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(submit_ret0, MirType::I64);
        types.insert(submit_ret1, MirType::I64);
        let err = verify_mir(&func, &types).expect_err("expected double-release error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("helper 132 arg0 expects pointer")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_ringbuf_submit_invalidates_record_pointer() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let submit = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let record = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let submit_ret = func.alloc_vreg();
        let load_dst = func.alloc_vreg();

        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst: record,
                helper: 131, // bpf_ringbuf_reserve(map, size, flags)
                args: vec![
                    MirValue::StackSlot(map_slot),
                    MirValue::Const(8),
                    MirValue::Const(0),
                ],
            });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(record),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: submit,
            if_false: done,
        };

        func.block_mut(submit)
            .instructions
            .push(MirInst::CallHelper {
                dst: submit_ret,
                helper: 132, // bpf_ringbuf_submit(data, flags)
                args: vec![MirValue::VReg(record), MirValue::Const(0)],
            });
        func.block_mut(submit).instructions.push(MirInst::Load {
            dst: load_dst,
            ptr: record,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(submit).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(submit_ret, MirType::I64);
        types.insert(load_dst, MirType::I64);
        let err = verify_mir(&func, &types).expect_err("expected use-after-release error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("load requires pointer type")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_perf_event_output_rejects_user_ctx_pointer() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let call = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let ctx = func.alloc_vreg();
        func.param_count = 1;
        let cond = func.alloc_vreg();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(ctx),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: call,
            if_false: done,
        };

        func.block_mut(call).instructions.push(MirInst::CallHelper {
            dst,
            helper: 25, // bpf_perf_event_output(ctx, map, flags, data, size)
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::Const(0),
                MirValue::StackSlot(data_slot),
                MirValue::Const(8),
            ],
        });
        func.block_mut(call).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::User,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper ctx pointer-space error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("helper perf_event_output ctx expects pointer in [Kernel]")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_get_stackid_rejects_user_ctx_pointer() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let call = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let ctx = func.alloc_vreg();
        func.param_count = 1;
        let cond = func.alloc_vreg();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(ctx),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: call,
            if_false: done,
        };

        func.block_mut(call).instructions.push(MirInst::CallHelper {
            dst,
            helper: 27, // bpf_get_stackid(ctx, map, flags)
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::Const(0),
            ],
        });
        func.block_mut(call).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::User,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper ctx pointer-space error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("helper get_stackid ctx expects pointer in [Kernel]")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_tail_call_rejects_user_ctx_pointer() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let call = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let ctx = func.alloc_vreg();
        func.param_count = 1;
        let cond = func.alloc_vreg();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(ctx),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: call,
            if_false: done,
        };

        func.block_mut(call).instructions.push(MirInst::CallHelper {
            dst,
            helper: 12, // bpf_tail_call(ctx, prog_array_map, index)
            args: vec![
                MirValue::VReg(ctx),
                MirValue::StackSlot(map_slot),
                MirValue::Const(0),
            ],
        });
        func.block_mut(call).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ctx,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::User,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper ctx pointer-space error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("helper tail_call ctx expects pointer in [Kernel]")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_tail_call_rejects_pointer_index() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let index_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        func.block_mut(entry).terminator = MirInst::TailCall {
            prog_map: MapRef {
                name: "jumps".to_string(),
                kind: MapKind::ProgArray,
            },
            index: MirValue::StackSlot(index_slot),
        };

        let err = verify_mir(&func, &HashMap::new()).expect_err("expected tail-call index error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("tail_call index expects scalar")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_tail_call_rejects_non_prog_array_map_kind() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        func.block_mut(entry).terminator = MirInst::TailCall {
            prog_map: MapRef {
                name: "not_prog_array".to_string(),
                kind: MapKind::Hash,
            },
            index: MirValue::Const(0),
        };

        let err =
            verify_mir(&func, &HashMap::new()).expect_err("expected non-ProgArray tail_call error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("tail_call requires ProgArray map")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_get_current_comm_requires_positive_size() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let buf = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: 16, // bpf_get_current_comm(buf, size)
                args: vec![MirValue::StackSlot(buf), MirValue::Const(0)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected non-positive size error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("helper 16 arg1 must be > 0"))
        );
    }

    #[test]
    fn test_helper_get_current_comm_checks_dst_bounds() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let buf = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: 16, // bpf_get_current_comm(buf, size)
                args: vec![MirValue::StackSlot(buf), MirValue::Const(16)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper dst bounds error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("helper get_current_comm dst out of bounds")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_trace_printk_requires_positive_size() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let fmt = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: 6, // bpf_trace_printk(fmt, fmt_size, ...)
                args: vec![MirValue::StackSlot(fmt), MirValue::Const(0)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected non-positive size error");
        assert!(
            err.iter().any(|e| e.message.contains("helper 6 arg1 must be > 0")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_trace_printk_checks_fmt_bounds() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let fmt = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: 6, // bpf_trace_printk(fmt, fmt_size, ...)
                args: vec![MirValue::StackSlot(fmt), MirValue::Const(16)],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper fmt bounds error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("helper trace_printk fmt out of bounds")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_trace_printk_rejects_user_fmt_pointer() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let call = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let fmt = func.alloc_vreg();
        func.param_count = 1;
        let cond = func.alloc_vreg();
        let dst = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(fmt),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: call,
            if_false: done,
        };

        func.block_mut(call)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: 6, // bpf_trace_printk(fmt, fmt_size, ...)
                args: vec![MirValue::VReg(fmt), MirValue::Const(8)],
            });
        func.block_mut(call).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            fmt,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::User,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper fmt pointer-space error");
        assert!(
            err.iter().any(
                |e| e
                    .message
                    .contains("helper trace_printk fmt expects pointer in [Stack, Map]")
            ),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_get_current_comm_variable_size_range_checks_bounds() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let check_upper = func.alloc_block();
        let call = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let size = func.alloc_vreg();
        func.param_count = 1;
        let ge_one = func.alloc_vreg();
        let le_sixteen = func.alloc_vreg();
        let buf = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: ge_one,
            op: BinOpKind::Ge,
            lhs: MirValue::VReg(size),
            rhs: MirValue::Const(1),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond: ge_one,
            if_true: check_upper,
            if_false: done,
        };

        func.block_mut(check_upper)
            .instructions
            .push(MirInst::BinOp {
                dst: le_sixteen,
                op: BinOpKind::Le,
                lhs: MirValue::VReg(size),
                rhs: MirValue::Const(16),
            });
        func.block_mut(check_upper).terminator = MirInst::Branch {
            cond: le_sixteen,
            if_true: call,
            if_false: done,
        };

        func.block_mut(call).instructions.push(MirInst::CallHelper {
            dst,
            helper: 16, // bpf_get_current_comm(buf, size)
            args: vec![MirValue::StackSlot(buf), MirValue::VReg(size)],
        });
        func.block_mut(call).terminator = MirInst::Return { val: None };

        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(size, MirType::I64);
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper dst bounds error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("helper get_current_comm dst out of bounds")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_get_current_comm_variable_size_range_within_bounds() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let check_upper = func.alloc_block();
        let call = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let size = func.alloc_vreg();
        func.param_count = 1;
        let ge_one = func.alloc_vreg();
        let le_eight = func.alloc_vreg();
        let buf = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: ge_one,
            op: BinOpKind::Ge,
            lhs: MirValue::VReg(size),
            rhs: MirValue::Const(1),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond: ge_one,
            if_true: check_upper,
            if_false: done,
        };

        func.block_mut(check_upper)
            .instructions
            .push(MirInst::BinOp {
                dst: le_eight,
                op: BinOpKind::Le,
                lhs: MirValue::VReg(size),
                rhs: MirValue::Const(8),
            });
        func.block_mut(check_upper).terminator = MirInst::Branch {
            cond: le_eight,
            if_true: call,
            if_false: done,
        };

        func.block_mut(call).instructions.push(MirInst::CallHelper {
            dst,
            helper: 16, // bpf_get_current_comm(buf, size)
            args: vec![MirValue::StackSlot(buf), MirValue::VReg(size)],
        });
        func.block_mut(call).terminator = MirInst::Return { val: None };

        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(size, MirType::I64);
        types.insert(dst, MirType::I64);

        verify_mir(&func, &types).expect("expected bounded helper size range to pass");
    }

    #[test]
    fn test_helper_probe_read_user_str_rejects_stack_src() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let dst_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let src_slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: 114, // bpf_probe_read_user_str(dst, size, unsafe_ptr)
                args: vec![
                    MirValue::StackSlot(dst_slot),
                    MirValue::Const(8),
                    MirValue::StackSlot(src_slot),
                ],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected user source pointer error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("helper probe_read src expects pointer in [User]")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_ringbuf_output_checks_data_bounds() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let data_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();
        func.block_mut(entry)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: 130, // bpf_ringbuf_output(map, data, size, flags)
                args: vec![
                    MirValue::StackSlot(map_slot),
                    MirValue::StackSlot(data_slot),
                    MirValue::Const(16),
                    MirValue::Const(0),
                ],
            });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected helper data bounds error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("helper ringbuf_output data out of bounds")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_helper_map_update_rejects_user_key_pointer() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let call_block = func.alloc_block();
        let exit_block = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        func.param_count = 1;
        let cond = func.alloc_vreg();
        let map_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let value_slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(key),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: call_block,
            if_false: exit_block,
        };

        func.block_mut(call_block)
            .instructions
            .push(MirInst::CallHelper {
                dst,
                helper: 2, // bpf_map_update_elem(map, key, value, flags)
                args: vec![
                    MirValue::StackSlot(map_slot),
                    MirValue::VReg(key),
                    MirValue::StackSlot(value_slot),
                    MirValue::Const(0),
                ],
            });
        func.block_mut(call_block).terminator = MirInst::Return { val: None };

        func.block_mut(exit_block).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            key,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::User,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected map key pointer-space error");
        assert!(
            err.iter().any(|e| e
                .message
                .contains("helper map_update key expects pointer in [Stack, Map]")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_stack_pointer_non_null() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).instructions.push(MirInst::Load {
            dst,
            ptr,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(dst, MirType::I64);
        verify_mir(&func, &types).expect("stack pointer should be non-null");
    }

    #[test]
    fn test_stack_load_out_of_bounds() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(8, 8, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).instructions.push(MirInst::Load {
            dst,
            ptr,
            offset: 8,
            ty: MirType::I64,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected bounds error");
        assert!(err.iter().any(|e| e.message.contains("out of bounds")));
    }

    #[test]
    fn test_stack_pointer_offset_in_bounds() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let tmp = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: tmp,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::Const(8),
        });
        func.block_mut(entry).instructions.push(MirInst::Load {
            dst,
            ptr: tmp,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(
            tmp,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(dst, MirType::I64);

        verify_mir(&func, &types).expect("expected in-bounds access");
    }

    #[test]
    fn test_read_str_rejects_non_user_ptr_for_user_space() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ptr = func.alloc_vreg();
        func.param_count = 1;

        let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        func.block_mut(entry).instructions.push(MirInst::ReadStr {
            dst: slot,
            ptr,
            user_space: true,
            max_len: 16,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );

        let err = verify_mir(&func, &types).expect_err("expected user ptr error");
        assert!(err.iter().any(|e| e.message.contains("read_str")));
    }

    #[test]
    fn test_read_str_user_ptr_requires_null_check_for_user_space() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ptr = func.alloc_vreg();
        func.param_count = 1;
        let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        func.block_mut(entry).instructions.push(MirInst::ReadStr {
            dst: slot,
            ptr,
            user_space: true,
            max_len: 16,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::User,
            },
        );

        let err = verify_mir(&func, &types).expect_err("expected read_str null-check error");
        assert!(
            err.iter()
                .any(|e| e.message.contains("may dereference null pointer")),
            "unexpected errors: {:?}",
            err
        );
    }

    #[test]
    fn test_read_str_user_ptr_with_null_check_for_user_space() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let call = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let ptr = func.alloc_vreg();
        func.param_count = 1;
        let cond = func.alloc_vreg();
        let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);

        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: call,
            if_false: done,
        };

        func.block_mut(call).instructions.push(MirInst::ReadStr {
            dst: slot,
            ptr,
            user_space: true,
            max_len: 16,
        });
        func.block_mut(call).terminator = MirInst::Return { val: None };
        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::User,
            },
        );

        verify_mir(&func, &types).expect("expected null-checked read_str user pointer to pass");
    }

    #[test]
    fn test_load_rejects_user_ptr() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let ptr = func.alloc_vreg();
        func.param_count = 1;
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Load {
            dst,
            ptr,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::User,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected user ptr load error");
        assert!(err.iter().any(|e| e.message.contains("load")));
    }

    #[test]
    fn test_map_value_bounds() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let ok = func.alloc_block();
        let bad = func.alloc_block();
        let left = func.alloc_block();
        let right = func.alloc_block();
        let join = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        let ptr = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let dst = func.alloc_vreg();
        let off = func.alloc_vreg();
        let tmp_ptr = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::Const(0),
        });
        func.block_mut(entry).instructions.push(MirInst::MapLookup {
            dst: ptr,
            map: MapRef {
                name: COUNTER_MAP_NAME.to_string(),
                kind: MapKind::Hash,
            },
            key,
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: ok,
            if_false: bad,
        };

        func.block_mut(ok).terminator = MirInst::Branch {
            cond,
            if_true: left,
            if_false: right,
        };

        func.block_mut(left).instructions.push(MirInst::Copy {
            dst: off,
            src: MirValue::Const(0),
        });
        func.block_mut(left).terminator = MirInst::Jump { target: join };

        func.block_mut(right).instructions.push(MirInst::Copy {
            dst: off,
            src: MirValue::Const(4),
        });
        func.block_mut(right).terminator = MirInst::Jump { target: join };

        func.block_mut(join).instructions.push(MirInst::BinOp {
            dst: tmp_ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::VReg(off),
        });
        func.block_mut(join).instructions.push(MirInst::Load {
            dst,
            ptr: tmp_ptr,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(join).terminator = MirInst::Return { val: None };

        func.block_mut(bad).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Map,
            },
        );
        types.insert(
            tmp_ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Map,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected map bounds error");
        assert!(err.iter().any(|e| e.message.contains("out of bounds")));
    }

    #[test]
    fn test_unknown_map_uses_pointee_bounds_for_lookup_result() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let ok = func.alloc_block();
        let bad = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        let ptr = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::Const(0),
        });
        func.block_mut(entry).instructions.push(MirInst::MapLookup {
            dst: ptr,
            map: MapRef {
                name: "custom_map".to_string(),
                kind: MapKind::Hash,
            },
            key,
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: ok,
            if_false: bad,
        };

        func.block_mut(ok).instructions.push(MirInst::Load {
            dst,
            ptr,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(ok).terminator = MirInst::Return { val: None };
        func.block_mut(bad).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: 4,
                }),
                address_space: AddressSpace::Map,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected map bounds error");
        assert!(err.iter().any(|e| e.message.contains("out of bounds")));
    }

    #[test]
    fn test_unknown_map_pointee_bounds_allow_in_bounds_access() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let ok = func.alloc_block();
        let bad = func.alloc_block();
        func.entry = entry;

        let key = func.alloc_vreg();
        let ptr = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: key,
            src: MirValue::Const(0),
        });
        func.block_mut(entry).instructions.push(MirInst::MapLookup {
            dst: ptr,
            map: MapRef {
                name: "custom_map".to_string(),
                kind: MapKind::Hash,
            },
            key,
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::Const(0),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: ok,
            if_false: bad,
        };

        func.block_mut(ok).instructions.push(MirInst::Load {
            dst,
            ptr,
            offset: 0,
            ty: MirType::I32,
        });
        func.block_mut(ok).terminator = MirInst::Return { val: None };
        func.block_mut(bad).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: 8,
                }),
                address_space: AddressSpace::Map,
            },
        );
        types.insert(dst, MirType::I32);

        verify_mir(&func, &types).expect("expected in-bounds access");
    }

    #[test]
    fn test_stack_pointer_offset_via_shift_out_of_bounds() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let base = func.alloc_vreg();
        let offset = func.alloc_vreg();
        let tmp = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: base,
            src: MirValue::Const(3),
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: offset,
            op: BinOpKind::Shl,
            lhs: MirValue::VReg(base),
            rhs: MirValue::Const(2),
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: tmp,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::VReg(offset),
        });
        func.block_mut(entry).instructions.push(MirInst::Load {
            dst,
            ptr: tmp,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(
            tmp,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected bounds error");
        assert!(err.iter().any(|e| e.message.contains("out of bounds")));
    }

    #[test]
    fn test_stack_pointer_offset_via_mul_out_of_bounds() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let base = func.alloc_vreg();
        let scale = func.alloc_vreg();
        let offset = func.alloc_vreg();
        let tmp = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: base,
            src: MirValue::Const(3),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: scale,
            src: MirValue::Const(4),
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: offset,
            op: BinOpKind::Mul,
            lhs: MirValue::VReg(base),
            rhs: MirValue::VReg(scale),
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: tmp,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::VReg(offset),
        });
        func.block_mut(entry).instructions.push(MirInst::Load {
            dst,
            ptr: tmp,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(
            tmp,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected bounds error");
        assert!(err.iter().any(|e| e.message.contains("out of bounds")));
    }

    #[test]
    fn test_pointer_phi_preserves_bounds() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let left = func.alloc_block();
        let right = func.alloc_block();
        let join = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let tmp = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let phi_ptr = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: cond,
            src: MirValue::Const(1),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: left,
            if_false: right,
        };

        func.block_mut(left).instructions.push(MirInst::Copy {
            dst: tmp,
            src: MirValue::VReg(ptr),
        });
        func.block_mut(left).terminator = MirInst::Jump { target: join };

        func.block_mut(right).instructions.push(MirInst::Copy {
            dst: tmp,
            src: MirValue::VReg(ptr),
        });
        func.block_mut(right).terminator = MirInst::Jump { target: join };

        func.block_mut(join).instructions.push(MirInst::Phi {
            dst: phi_ptr,
            args: vec![(left, tmp), (right, tmp)],
        });
        func.block_mut(join).instructions.push(MirInst::Load {
            dst,
            ptr: phi_ptr,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(join).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(
            tmp,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(
            phi_ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(dst, MirType::I64);

        verify_mir(&func, &types).expect("expected bounds to propagate through phi");
    }

    #[test]
    fn test_div_range_with_non_zero_guard() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let left = func.alloc_block();
        let right = func.alloc_block();
        let join = func.alloc_block();
        let ok = func.alloc_block();
        let bad = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(16, 8, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let idx = func.alloc_vreg();
        let div = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let offset = func.alloc_vreg();
        let tmp_ptr = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond: ptr,
            if_true: left,
            if_false: right,
        };

        func.block_mut(left).instructions.push(MirInst::Copy {
            dst: idx,
            src: MirValue::Const(0),
        });
        func.block_mut(left).instructions.push(MirInst::Copy {
            dst: div,
            src: MirValue::Const(0),
        });
        func.block_mut(left).terminator = MirInst::Jump { target: join };

        func.block_mut(right).instructions.push(MirInst::Copy {
            dst: idx,
            src: MirValue::Const(31),
        });
        func.block_mut(right).instructions.push(MirInst::Copy {
            dst: div,
            src: MirValue::Const(4),
        });
        func.block_mut(right).terminator = MirInst::Jump { target: join };

        func.block_mut(join).instructions.push(MirInst::BinOp {
            dst: cond,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(div),
            rhs: MirValue::Const(0),
        });
        func.block_mut(join).terminator = MirInst::Branch {
            cond,
            if_true: ok,
            if_false: bad,
        };

        func.block_mut(ok).instructions.push(MirInst::BinOp {
            dst: offset,
            op: BinOpKind::Div,
            lhs: MirValue::VReg(idx),
            rhs: MirValue::VReg(div),
        });
        func.block_mut(ok).instructions.push(MirInst::BinOp {
            dst: tmp_ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::VReg(offset),
        });
        func.block_mut(ok).instructions.push(MirInst::Load {
            dst,
            ptr: tmp_ptr,
            offset: 0,
            ty: MirType::I64,
        });
        func.block_mut(ok).terminator = MirInst::Return { val: None };

        func.block_mut(bad).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(
            tmp_ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::I64),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected bounds error");
        assert!(err.iter().any(|e| e.message.contains("out of bounds")));
    }

    #[test]
    fn test_mod_range_bounds() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(2, 1, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let idx = func.alloc_vreg();
        let div = func.alloc_vreg();
        let offset = func.alloc_vreg();
        let tmp_ptr = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: idx,
            src: MirValue::Const(31),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: div,
            src: MirValue::Const(4),
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: offset,
            op: BinOpKind::Mod,
            lhs: MirValue::VReg(idx),
            rhs: MirValue::VReg(div),
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: tmp_ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::VReg(offset),
        });
        func.block_mut(entry).instructions.push(MirInst::Load {
            dst,
            ptr: tmp_ptr,
            offset: 0,
            ty: MirType::I8,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(
            tmp_ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(dst, MirType::I8);

        let err = verify_mir(&func, &types).expect_err("expected bounds error");
        assert!(err.iter().any(|e| e.message.contains("out of bounds")));
    }

    #[test]
    fn test_and_or_xor_range_bounds() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(8, 1, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let left = func.alloc_vreg();
        let right = func.alloc_vreg();
        let tmp_and = func.alloc_vreg();
        let tmp_or = func.alloc_vreg();
        let tmp_xor = func.alloc_vreg();
        let ptr_and = func.alloc_vreg();
        let ptr_or = func.alloc_vreg();
        let ptr_xor = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: left,
            src: MirValue::Const(15),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: right,
            src: MirValue::Const(1),
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: tmp_and,
            op: BinOpKind::And,
            lhs: MirValue::VReg(left),
            rhs: MirValue::VReg(right),
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: tmp_or,
            op: BinOpKind::Or,
            lhs: MirValue::VReg(left),
            rhs: MirValue::VReg(right),
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: tmp_xor,
            op: BinOpKind::Xor,
            lhs: MirValue::VReg(left),
            rhs: MirValue::VReg(right),
        });

        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: ptr_and,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::VReg(tmp_and),
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: ptr_or,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::VReg(tmp_or),
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: ptr_xor,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::VReg(tmp_xor),
        });
        func.block_mut(entry).instructions.push(MirInst::Load {
            dst,
            ptr: ptr_xor,
            offset: 0,
            ty: MirType::I8,
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(
            ptr_and,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(
            ptr_or,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(
            ptr_xor,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(dst, MirType::I8);

        let err = verify_mir(&func, &types).expect_err("expected bounds error");
        assert!(err.iter().any(|e| e.message.contains("out of bounds")));
    }

    #[test]
    fn test_prune_impossible_const_compare_branch() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let impossible = func.alloc_block();
        let done = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let idx = func.alloc_vreg();
        let cmp = func.alloc_vreg();
        let tmp_ptr = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: idx,
            src: MirValue::Const(5),
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst: cmp,
            op: BinOpKind::Lt,
            lhs: MirValue::VReg(idx),
            rhs: MirValue::Const(4),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond: cmp,
            if_true: impossible,
            if_false: done,
        };

        func.block_mut(impossible)
            .instructions
            .push(MirInst::BinOp {
                dst: tmp_ptr,
                op: BinOpKind::Add,
                lhs: MirValue::VReg(ptr),
                rhs: MirValue::VReg(idx),
            });
        func.block_mut(impossible).instructions.push(MirInst::Load {
            dst,
            ptr: tmp_ptr,
            offset: 0,
            ty: MirType::I8,
        });
        func.block_mut(impossible).terminator = MirInst::Return { val: None };

        func.block_mut(done).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(
            tmp_ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(dst, MirType::I8);

        verify_mir(&func, &types).expect("expected impossible branch to be pruned");
    }

    #[test]
    fn test_not_equal_fact_prunes_followup_eq_branch() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let left = func.alloc_block();
        let right = func.alloc_block();
        let join = func.alloc_block();
        let guarded = func.alloc_block();
        let skip = func.alloc_block();
        let bad = func.alloc_block();
        let ok = func.alloc_block();
        func.entry = entry;

        let cond = func.alloc_vreg();
        func.param_count = 1;

        let slot = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let left_idx = func.alloc_vreg();
        let right_idx = func.alloc_vreg();
        let idx = func.alloc_vreg();
        let neq = func.alloc_vreg();
        let eq = func.alloc_vreg();
        let tmp_ptr = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: left,
            if_false: right,
        };

        func.block_mut(left).instructions.push(MirInst::Copy {
            dst: left_idx,
            src: MirValue::Const(0),
        });
        func.block_mut(left).terminator = MirInst::Jump { target: join };

        func.block_mut(right).instructions.push(MirInst::Copy {
            dst: right_idx,
            src: MirValue::Const(2),
        });
        func.block_mut(right).terminator = MirInst::Jump { target: join };

        func.block_mut(join).instructions.push(MirInst::Phi {
            dst: idx,
            args: vec![(left, left_idx), (right, right_idx)],
        });
        func.block_mut(join).instructions.push(MirInst::BinOp {
            dst: neq,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(idx),
            rhs: MirValue::Const(1),
        });
        func.block_mut(join).terminator = MirInst::Branch {
            cond: neq,
            if_true: guarded,
            if_false: skip,
        };

        func.block_mut(guarded).instructions.push(MirInst::BinOp {
            dst: eq,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(idx),
            rhs: MirValue::Const(1),
        });
        func.block_mut(guarded).terminator = MirInst::Branch {
            cond: eq,
            if_true: bad,
            if_false: ok,
        };

        func.block_mut(skip).terminator = MirInst::Return { val: None };

        func.block_mut(bad).instructions.push(MirInst::BinOp {
            dst: tmp_ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::Const(9),
        });
        func.block_mut(bad).instructions.push(MirInst::Load {
            dst,
            ptr: tmp_ptr,
            offset: 0,
            ty: MirType::I8,
        });
        func.block_mut(bad).terminator = MirInst::Return { val: None };

        func.block_mut(ok).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(cond, MirType::Bool);
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(
            tmp_ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(dst, MirType::I8);

        verify_mir(&func, &types).expect("expected impossible == branch to be pruned");
    }

    #[test]
    fn test_multiple_not_equal_facts_prune_followup_eq() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let left = func.alloc_block();
        let right = func.alloc_block();
        let join = func.alloc_block();
        let after_first = func.alloc_block();
        let after_second = func.alloc_block();
        let skip_first = func.alloc_block();
        let skip_second = func.alloc_block();
        let bad = func.alloc_block();
        let ok = func.alloc_block();
        func.entry = entry;

        let cond = func.alloc_vreg();
        func.param_count = 1;

        let slot = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let left_idx = func.alloc_vreg();
        let right_idx = func.alloc_vreg();
        let idx = func.alloc_vreg();
        let neq1 = func.alloc_vreg();
        let neq3 = func.alloc_vreg();
        let eq1 = func.alloc_vreg();
        let tmp_ptr = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: left,
            if_false: right,
        };

        func.block_mut(left).instructions.push(MirInst::Copy {
            dst: left_idx,
            src: MirValue::Const(0),
        });
        func.block_mut(left).terminator = MirInst::Jump { target: join };

        func.block_mut(right).instructions.push(MirInst::Copy {
            dst: right_idx,
            src: MirValue::Const(4),
        });
        func.block_mut(right).terminator = MirInst::Jump { target: join };

        func.block_mut(join).instructions.push(MirInst::Phi {
            dst: idx,
            args: vec![(left, left_idx), (right, right_idx)],
        });
        func.block_mut(join).instructions.push(MirInst::BinOp {
            dst: neq1,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(idx),
            rhs: MirValue::Const(1),
        });
        func.block_mut(join).terminator = MirInst::Branch {
            cond: neq1,
            if_true: after_first,
            if_false: skip_first,
        };

        func.block_mut(after_first)
            .instructions
            .push(MirInst::BinOp {
                dst: neq3,
                op: BinOpKind::Ne,
                lhs: MirValue::VReg(idx),
                rhs: MirValue::Const(3),
            });
        func.block_mut(after_first).terminator = MirInst::Branch {
            cond: neq3,
            if_true: after_second,
            if_false: skip_second,
        };

        func.block_mut(after_second)
            .instructions
            .push(MirInst::BinOp {
                dst: eq1,
                op: BinOpKind::Eq,
                lhs: MirValue::VReg(idx),
                rhs: MirValue::Const(1),
            });
        func.block_mut(after_second).terminator = MirInst::Branch {
            cond: eq1,
            if_true: bad,
            if_false: ok,
        };

        func.block_mut(skip_first).terminator = MirInst::Return { val: None };
        func.block_mut(skip_second).terminator = MirInst::Return { val: None };

        func.block_mut(bad).instructions.push(MirInst::BinOp {
            dst: tmp_ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::Const(9),
        });
        func.block_mut(bad).instructions.push(MirInst::Load {
            dst,
            ptr: tmp_ptr,
            offset: 0,
            ty: MirType::I8,
        });
        func.block_mut(bad).terminator = MirInst::Return { val: None };

        func.block_mut(ok).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(cond, MirType::Bool);
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(
            tmp_ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(dst, MirType::I8);

        verify_mir(&func, &types).expect("expected impossible == branch to be pruned");
    }

    #[test]
    fn test_compare_refines_true_branch_lt() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let left = func.alloc_block();
        let right = func.alloc_block();
        let join = func.alloc_block();
        let ok = func.alloc_block();
        let bad = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let idx = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let cmp = func.alloc_vreg();
        let tmp_ptr = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: cond,
            src: MirValue::Const(1),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: left,
            if_false: right,
        };

        func.block_mut(left).instructions.push(MirInst::Copy {
            dst: idx,
            src: MirValue::Const(0),
        });
        func.block_mut(left).terminator = MirInst::Jump { target: join };

        func.block_mut(right).instructions.push(MirInst::Copy {
            dst: idx,
            src: MirValue::Const(7),
        });
        func.block_mut(right).terminator = MirInst::Jump { target: join };

        func.block_mut(join).instructions.push(MirInst::BinOp {
            dst: cmp,
            op: BinOpKind::Lt,
            lhs: MirValue::VReg(idx),
            rhs: MirValue::Const(4),
        });
        func.block_mut(join).terminator = MirInst::Branch {
            cond: cmp,
            if_true: ok,
            if_false: bad,
        };

        func.block_mut(ok).instructions.push(MirInst::BinOp {
            dst: tmp_ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::VReg(idx),
        });
        func.block_mut(ok).instructions.push(MirInst::Load {
            dst,
            ptr: tmp_ptr,
            offset: 0,
            ty: MirType::I8,
        });
        func.block_mut(ok).terminator = MirInst::Return { val: None };

        func.block_mut(bad).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(
            tmp_ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(dst, MirType::I8);

        verify_mir(&func, &types).expect("expected compare to refine range");
    }

    #[test]
    fn test_compare_refines_true_branch_ge() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let left = func.alloc_block();
        let right = func.alloc_block();
        let join = func.alloc_block();
        let ok = func.alloc_block();
        let bad = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let idx = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let cmp = func.alloc_vreg();
        let offset = func.alloc_vreg();
        let tmp_ptr = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: cond,
            src: MirValue::Const(1),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: left,
            if_false: right,
        };

        func.block_mut(left).instructions.push(MirInst::Copy {
            dst: idx,
            src: MirValue::Const(0),
        });
        func.block_mut(left).terminator = MirInst::Jump { target: join };

        func.block_mut(right).instructions.push(MirInst::Copy {
            dst: idx,
            src: MirValue::Const(7),
        });
        func.block_mut(right).terminator = MirInst::Jump { target: join };

        func.block_mut(join).instructions.push(MirInst::BinOp {
            dst: cmp,
            op: BinOpKind::Ge,
            lhs: MirValue::VReg(idx),
            rhs: MirValue::Const(4),
        });
        func.block_mut(join).terminator = MirInst::Branch {
            cond: cmp,
            if_true: ok,
            if_false: bad,
        };

        func.block_mut(ok).instructions.push(MirInst::BinOp {
            dst: offset,
            op: BinOpKind::Sub,
            lhs: MirValue::VReg(idx),
            rhs: MirValue::Const(4),
        });
        func.block_mut(ok).instructions.push(MirInst::BinOp {
            dst: tmp_ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::VReg(offset),
        });
        func.block_mut(ok).instructions.push(MirInst::Load {
            dst,
            ptr: tmp_ptr,
            offset: 0,
            ty: MirType::I8,
        });
        func.block_mut(ok).terminator = MirInst::Return { val: None };

        func.block_mut(bad).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(
            tmp_ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(dst, MirType::I8);

        verify_mir(&func, &types).expect("expected compare to refine range");
    }

    #[test]
    fn test_compare_refines_vreg_bound() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let left = func.alloc_block();
        let right = func.alloc_block();
        let join = func.alloc_block();
        let ok = func.alloc_block();
        let bad = func.alloc_block();
        func.entry = entry;

        let slot = func.alloc_stack_slot(4, 1, StackSlotKind::StringBuffer);
        let ptr = func.alloc_vreg();
        let idx = func.alloc_vreg();
        let bound = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let cmp = func.alloc_vreg();
        let tmp_ptr = func.alloc_vreg();
        let dst = func.alloc_vreg();

        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: ptr,
            src: MirValue::StackSlot(slot),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: bound,
            src: MirValue::Const(4),
        });
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: cond,
            src: MirValue::Const(1),
        });
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: left,
            if_false: right,
        };

        func.block_mut(left).instructions.push(MirInst::Copy {
            dst: idx,
            src: MirValue::Const(0),
        });
        func.block_mut(left).terminator = MirInst::Jump { target: join };

        func.block_mut(right).instructions.push(MirInst::Copy {
            dst: idx,
            src: MirValue::Const(7),
        });
        func.block_mut(right).terminator = MirInst::Jump { target: join };

        func.block_mut(join).instructions.push(MirInst::BinOp {
            dst: cmp,
            op: BinOpKind::Lt,
            lhs: MirValue::VReg(idx),
            rhs: MirValue::VReg(bound),
        });
        func.block_mut(join).terminator = MirInst::Branch {
            cond: cmp,
            if_true: ok,
            if_false: bad,
        };

        func.block_mut(ok).instructions.push(MirInst::BinOp {
            dst: tmp_ptr,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(ptr),
            rhs: MirValue::VReg(idx),
        });
        func.block_mut(ok).instructions.push(MirInst::Load {
            dst,
            ptr: tmp_ptr,
            offset: 0,
            ty: MirType::I8,
        });
        func.block_mut(ok).terminator = MirInst::Return { val: None };

        func.block_mut(bad).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(
            ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(
            tmp_ptr,
            MirType::Ptr {
                pointee: Box::new(MirType::U8),
                address_space: AddressSpace::Stack,
            },
        );
        types.insert(dst, MirType::I8);

        verify_mir(&func, &types).expect("expected vreg compare to refine range");
    }

    #[test]
    fn test_uninitialized_scalar_use_rejected() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        func.entry = entry;

        let lhs = func.alloc_vreg();
        let rhs = func.alloc_vreg();
        let dst = func.alloc_vreg();
        func.block_mut(entry).instructions.push(MirInst::Copy {
            dst: rhs,
            src: MirValue::Const(1),
        });
        func.block_mut(entry).instructions.push(MirInst::BinOp {
            dst,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(lhs),
            rhs: MirValue::VReg(rhs),
        });
        func.block_mut(entry).terminator = MirInst::Return { val: None };

        let mut types = HashMap::new();
        types.insert(dst, MirType::I64);

        let err = verify_mir(&func, &types).expect_err("expected uninitialized-use error");
        assert!(err.iter().any(|e| e.message.contains("uninitialized v")));
    }

    #[test]
    fn test_uninitialized_branch_cond_rejected() {
        let mut func = MirFunction::new();
        let entry = func.alloc_block();
        let left = func.alloc_block();
        let right = func.alloc_block();
        func.entry = entry;

        let cond = func.alloc_vreg();
        func.block_mut(entry).terminator = MirInst::Branch {
            cond,
            if_true: left,
            if_false: right,
        };
        func.block_mut(left).terminator = MirInst::Return { val: None };
        func.block_mut(right).terminator = MirInst::Return { val: None };

        let types = HashMap::new();
        let err = verify_mir(&func, &types).expect_err("expected uninitialized branch cond error");
        assert!(err.iter().any(|e| e.message.contains("uninitialized v")));
    }
}
