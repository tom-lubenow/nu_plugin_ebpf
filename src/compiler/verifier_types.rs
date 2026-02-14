//! Flow-sensitive verifier-type analysis over MIR.
//!
//! This pass models a subset of the kernel verifier's type system, focusing on
//! pointer kinds and nullability. It is intended to reject uses that are known
//! to fail the verifier (e.g. dereferencing a map lookup result without a null check).

use std::collections::{HashMap, VecDeque};

use super::instruction::{
    BpfHelper, HelperArgKind, HelperRetKind, HelperSignature, KfuncArgKind, KfuncRefKind,
    KfuncRetKind, KfuncSignature, helper_acquire_ref_kind, helper_release_ref_kind,
    kfunc_acquire_ref_kind, kfunc_pointer_arg_ref_kind,
    kfunc_pointer_arg_requires_kernel as kfunc_pointer_arg_requires_kernel_shared,
    kfunc_release_ref_kind,
};
use super::mir::{
    AddressSpace, BinOpKind, BlockId, COUNTER_MAP_NAME, CtxField, HISTOGRAM_MAP_NAME,
    KSTACK_MAP_NAME, MapKind, MapRef, MirFunction, MirInst, MirType, MirValue, RINGBUF_MAP_NAME,
    STRING_COUNTER_MAP_NAME, StackSlotId, TIMESTAMP_MAP_NAME, USTACK_MAP_NAME, VReg,
};

mod state;
use state::*;

mod apply;
mod calls;
mod map_layout;
mod ranges;
mod refinement;

use apply::{apply_inst, check_uses_initialized};
use calls::*;
use map_layout::*;
use ranges::*;
use refinement::*;

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
    if func.param_count > 5 {
        errors.push(VerifierTypeError::new(format!(
            "BPF subfunctions support at most 5 arguments, got {}",
            func.param_count
        )));
        return Err(errors);
    }
    errors.extend(check_generic_map_layout_constraints(func, types));
    if !errors.is_empty() {
        return Err(errors);
    }

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
        let mut state = state_in.clone();
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
                if state.has_live_kfunc_refs() {
                    errors.push(VerifierTypeError::new(
                        "unreleased kfunc reference at function exit",
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
                if state.has_live_kfunc_refs() {
                    errors.push(VerifierTypeError::new(
                        "unreleased kfunc reference at function exit",
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
                || merged.ctx_field_sources != existing.ctx_field_sources
                || merged.live_ringbuf_refs != existing.live_ringbuf_refs
                || merged.live_kfunc_refs != existing.live_kfunc_refs
                || merged.kfunc_ref_kinds != existing.kfunc_ref_kinds
                || merged.guards != existing.guards
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
            kfunc_ref,
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
                kfunc_ref,
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
                kfunc_ref: None,
            }
        }
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
            kfunc_ref: None,
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
            kfunc_ref: None,
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
                kfunc_ref: ka,
            },
            Ptr {
                space: sb,
                nullability: nb,
                bounds: bb,
                ringbuf_ref: rb,
                kfunc_ref: kb,
            },
        ) => {
            if sa != sb {
                return Unknown;
            }
            let nullability = join_nullability(na, nb);
            let bounds = join_bounds(ba, bb);
            let ringbuf_ref = join_ringbuf_ref(ra, rb);
            let kfunc_ref = join_kfunc_ref(ka, kb);
            Ptr {
                space: sa,
                nullability,
                bounds,
                ringbuf_ref,
                kfunc_ref,
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

fn join_kfunc_ref(a: Option<VReg>, b: Option<VReg>) -> Option<VReg> {
    match (a, b) {
        (Some(a), Some(b)) if a == b => Some(a),
        (Some(_), Some(_)) => None,
        (None, None) => None,
        _ => None,
    }
}

#[cfg(test)]
mod tests;
