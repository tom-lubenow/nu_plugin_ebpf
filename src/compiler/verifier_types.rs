//! Flow-sensitive verifier-type analysis over MIR.
//!
//! This pass models a subset of the kernel verifier's type system, focusing on
//! pointer kinds and nullability. It is intended to reject uses that are known
//! to fail the verifier (e.g. dereferencing a map lookup result without a null check).

use std::collections::{HashMap, VecDeque};

use super::mir::{
    AddressSpace, BinOpKind, BlockId, MapRef, MirFunction, MirInst, MirType, MirValue, StackSlotId,
    VReg, COUNTER_MAP_NAME, HISTOGRAM_MAP_NAME, KSTACK_MAP_NAME, STRING_COUNTER_MAP_NAME,
    TIMESTAMP_MAP_NAME, USTACK_MAP_NAME,
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
}

#[derive(Debug, Clone)]
struct VerifierState {
    regs: Vec<VerifierType>,
    ranges: Vec<ValueRange>,
    non_zero: Vec<bool>,
    guards: HashMap<VReg, Guard>,
}

impl VerifierState {
    fn new(total_vregs: usize) -> Self {
        Self {
            regs: vec![VerifierType::Uninit; total_vregs],
            ranges: vec![ValueRange::Unknown; total_vregs],
            non_zero: vec![false; total_vregs],
            guards: HashMap::new(),
        }
    }

    fn with_cleared_guards(&self) -> Self {
        Self {
            regs: self.regs.clone(),
            ranges: self.ranges.clone(),
            non_zero: self.non_zero.clone(),
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
        self.non_zero
            .get(vreg.0 as usize)
            .copied()
            .unwrap_or(false)
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
        self.guards.remove(&vreg);
    }

    fn join(&self, other: &VerifierState) -> VerifierState {
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
        VerifierState {
            regs,
            ranges,
            non_zero,
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
    let total_vregs = func
        .vreg_count
        .max(func.param_count as u32) as usize;
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
        let mut state = state_in.with_cleared_guards();
        let block = func.block(block_id);

        for inst in &block.instructions {
            apply_inst(inst, types, &slot_sizes, &mut state, &mut errors);
        }

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
            MirInst::Return { .. } | MirInst::TailCall { .. } => {}
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
    let updated = match in_states.get(&block) {
        None => {
            in_states.insert(block, state.clone());
            true
        }
        Some(existing) => {
            let merged = existing.join(state);
            if merged.regs != existing.regs || merged.ranges != existing.ranges {
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
                if let VerifierType::Ptr { space, bounds, .. } = current {
                    let nullability = if wants_non_null {
                        Nullability::NonNull
                    } else {
                        Nullability::Null
                    };
                    next.set(
                        ptr,
                        VerifierType::Ptr {
                            space,
                            nullability,
                            bounds,
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
                    if let Some(slot) = next.non_zero.get_mut(reg.0 as usize) {
                        *slot = true;
                    }
                } else {
                    if let Some(slot) = next.ranges.get_mut(reg.0 as usize) {
                        *slot = ValueRange::Known { min: 0, max: 0 };
                    }
                    if let Some(slot) = next.non_zero.get_mut(reg.0 as usize) {
                        *slot = false;
                    }
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
            state.set_with_range(*dst, ty, range);
        }
        MirInst::Load { dst, ptr, offset, .. } => {
            let access_size = types
                .get(dst)
                .map(|ty| ty.size())
                .unwrap_or(8);
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
        MirInst::Store { ptr, offset, ty, .. } => {
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
            if let MirInst::LoadSlot { slot, offset, ty, .. } = inst {
                check_slot_access(*slot, *offset, ty.size(), slot_sizes, "load slot", errors);
            }
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            state.set(*dst, ty);
        }
        MirInst::StoreSlot { .. } => {
            if let MirInst::StoreSlot { slot, offset, ty, .. } = inst {
                check_slot_access(*slot, *offset, ty.size(), slot_sizes, "store slot", errors);
            }
        }
        MirInst::BinOp { dst, op, lhs, rhs } => {
            if matches!(op, BinOpKind::Eq | BinOpKind::Ne) {
                state.set_with_range(*dst, VerifierType::Bool, ValueRange::Known { min: 0, max: 1 });
                if let Some(guard) = guard_from_compare(*op, lhs, rhs, state) {
                    state.guards.insert(*dst, guard);
                }
            } else if matches!(op, BinOpKind::Lt | BinOpKind::Le | BinOpKind::Gt | BinOpKind::Ge) {
                state.set_with_range(*dst, VerifierType::Bool, ValueRange::Known { min: 0, max: 1 });
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
        MirInst::CallHelper { dst, .. }
        | MirInst::CallSubfn { dst, .. }
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
            let bounds = map_value_limit(map).map(|limit| PtrBounds {
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
            if let (VerifierType::Ptr { space: AddressSpace::Stack, nullability, .. }, Some(slot)) =
                (ty, slot)
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
        MirInst::MapUpdate { key, .. } | MirInst::MapDelete { key, .. } => {
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
            require_ptr_with_space(
                *list,
                "list",
                &[AddressSpace::Stack],
                state,
                errors,
            );
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
    let (ptr, other) = match (lhs, rhs) {
        (MirValue::VReg(v), other) => (Some(*v), other),
        (other, MirValue::VReg(v)) => (Some(*v), other),
        _ => (None, rhs),
    };

    let reg = ptr?;
    match other {
        MirValue::Const(c) if *c == 0 => {
            let true_is_non_zero = matches!(op, BinOpKind::Ne);
            let ty = state.get(reg);
            if matches!(ty, VerifierType::Ptr { .. }) {
                Some(Guard::Ptr {
                    ptr: reg,
                    true_is_non_null: true_is_non_zero,
                })
            } else {
                Some(Guard::NonZero {
                    reg,
                    true_is_non_zero,
                })
            }
        }
        _ => None,
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
            ..
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
        },
        MirType::Ptr { address_space, .. } => VerifierType::Ptr {
            space: *address_space,
            nullability: match address_space {
                AddressSpace::Stack => Nullability::NonNull,
                AddressSpace::Map => Nullability::MaybeNull,
                AddressSpace::Kernel | AddressSpace::User => Nullability::MaybeNull,
            },
            bounds: None,
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
            },
            Ptr {
                space: sb,
                nullability: nb,
                bounds: bb,
            },
        ) => {
            if sa != sb {
                return Unknown;
            }
            let nullability = join_nullability(na, nb);
            let bounds = join_bounds(ba, bb);
            Ptr {
                space: sa,
                nullability,
                bounds,
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

fn map_value_limit(map: &MapRef) -> Option<i64> {
    match map.name.as_str() {
        COUNTER_MAP_NAME
        | STRING_COUNTER_MAP_NAME
        | HISTOGRAM_MAP_NAME
        | TIMESTAMP_MAP_NAME => Some(8 - 1),
        KSTACK_MAP_NAME | USTACK_MAP_NAME => Some((127 * 8) - 1),
        _ => None,
    }
}

fn join_range(a: ValueRange, b: ValueRange) -> ValueRange {
    match (a, b) {
        (ValueRange::Known { min: a_min, max: a_max }, ValueRange::Known { min: b_min, max: b_max }) => {
            ValueRange::Known {
                min: a_min.min(b_min),
                max: a_max.max(b_max),
            }
        }
        _ => ValueRange::Unknown,
    }
}

fn range_add(a: ValueRange, b: ValueRange) -> ValueRange {
    match (a, b) {
        (ValueRange::Known { min: a_min, max: a_max }, ValueRange::Known { min: b_min, max: b_max }) => {
            ValueRange::Known {
                min: a_min.saturating_add(b_min),
                max: a_max.saturating_add(b_max),
            }
        }
        _ => ValueRange::Unknown,
    }
}

fn range_sub(a: ValueRange, b: ValueRange) -> ValueRange {
    match (a, b) {
        (ValueRange::Known { min: a_min, max: a_max }, ValueRange::Known { min: b_min, max: b_max }) => {
            ValueRange::Known {
                min: a_min.saturating_sub(b_max),
                max: a_max.saturating_sub(b_min),
            }
        }
        _ => ValueRange::Unknown,
    }
}

fn range_for_binop(op: BinOpKind, lhs: &MirValue, rhs: &MirValue, state: &VerifierState) -> ValueRange {
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
        (ValueRange::Known { min: a_min, max: a_max }, ValueRange::Known { min: b_min, max: b_max }) => {
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
            ValueRange::Known { min: lhs_min, max: lhs_max },
            ValueRange::Known { min: rhs_min, max: rhs_max },
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
        (ValueRange::Known { min: lhs_min, max: lhs_max }, ValueRange::Known { min: rhs_min, max: rhs_max }) => {
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
        (ValueRange::Known { min: lhs_min, max: _lhs_max }, ValueRange::Known { min: rhs_min, max: rhs_max }) => {
            if rhs_min <= 0 || rhs_max <= 0 {
                return ValueRange::Unknown;
            }
            if lhs_min < 0 {
                return ValueRange::Unknown;
            }
            let max_mod = rhs_max.saturating_sub(1);
            ValueRange::Known { min: 0, max: max_mod }
        }
        _ => ValueRange::Unknown,
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
    use crate::compiler::mir::{
        MapKind, MapRef, MirType, StackSlotKind, COUNTER_MAP_NAME,
    };

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
        assert!(err
            .iter()
            .any(|e| e.message.contains("may dereference null")));
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
}
