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
    AddressSpace, BinOpKind, BlockId, COUNTER_MAP_NAME, HISTOGRAM_MAP_NAME, KSTACK_MAP_NAME,
    MapKind, MapRef, MirFunction, MirInst, MirType, MirValue, RINGBUF_MAP_NAME,
    STRING_COUNTER_MAP_NAME, StackSlotId, TIMESTAMP_MAP_NAME, USTACK_MAP_NAME, VReg,
};

include!("verifier_types/state.rs");

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

include!("verifier_types/refinement.rs");

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
            let src_guard = match src {
                MirValue::VReg(vreg) => state.guards.get(vreg).copied(),
                _ => None,
            };
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
            if let Some(guard) = src_guard {
                state.guards.insert(*dst, guard);
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
                let guard = if matches!(op, super::mir::UnaryOpKind::Not) {
                    if let MirInst::UnaryOp { src, .. } = inst {
                        if let MirValue::VReg(src_reg) = src {
                            state.guards.get(src_reg).copied().and_then(invert_guard)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                let range = if matches!(op, super::mir::UnaryOpKind::Not) {
                    ValueRange::Known { min: 0, max: 1 }
                } else {
                    ValueRange::Unknown
                };
                state.set_with_range(dst, ty, range);
                if let Some(guard) = guard {
                    state.guards.insert(dst, guard);
                }
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
                let helper_kfunc_acquire_kind =
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
                                kfunc_ref: None,
                            }
                        }
                        Some(BpfHelper::KptrXchg) => VerifierType::Ptr {
                            space: AddressSpace::Kernel,
                            nullability: Nullability::MaybeNull,
                            bounds: None,
                            ringbuf_ref: None,
                            kfunc_ref: helper_kfunc_acquire_kind.map(|kind| {
                                state.set_live_kfunc_ref(*dst, true, Some(kind));
                                *dst
                            }),
                        },
                        Some(BpfHelper::SkLookupTcp | BpfHelper::SkLookupUdp) => {
                            VerifierType::Ptr {
                                space: AddressSpace::Kernel,
                                nullability: Nullability::MaybeNull,
                                bounds: None,
                                ringbuf_ref: None,
                                kfunc_ref: helper_kfunc_acquire_kind.map(|kind| {
                                    state.set_live_kfunc_ref(*dst, true, Some(kind));
                                    *dst
                                }),
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
                                kfunc_ref: None,
                            }
                        }
                    },
                };
                state.set_with_range(*dst, ty, ValueRange::Unknown);
            } else {
                if args.len() > 5 {
                    errors.push(VerifierTypeError::new(
                        "BPF helpers support at most 5 arguments",
                    ));
                }
                let ty = types
                    .get(dst)
                    .map(verifier_type_from_mir)
                    .unwrap_or(VerifierType::Scalar);
                state.set_with_range(*dst, ty, ValueRange::Unknown);
            }
        }
        MirInst::CallKfunc {
            dst, kfunc, args, ..
        } => {
            let Some(sig) = KfuncSignature::for_name(kfunc) else {
                errors.push(VerifierTypeError::new(format!(
                    "unknown kfunc '{}' (typed signature required)",
                    kfunc
                )));
                return;
            };
            if args.len() < sig.min_args || args.len() > sig.max_args {
                errors.push(VerifierTypeError::new(format!(
                    "kfunc '{}' expects {}..={} args, got {}",
                    kfunc,
                    sig.min_args,
                    sig.max_args,
                    args.len()
                )));
            }
            if args.len() > 5 {
                errors.push(VerifierTypeError::new(
                    "BPF kfunc calls support at most 5 arguments",
                ));
            }
            for (idx, arg) in args.iter().take(sig.max_args.min(5)).enumerate() {
                check_kfunc_arg(kfunc, idx, *arg, sig.arg_kind(idx), state, errors);
            }
            apply_kfunc_semantics(kfunc, args, state, errors);

            let ty = match sig.ret_kind {
                KfuncRetKind::Scalar | KfuncRetKind::Void => types
                    .get(dst)
                    .map(verifier_type_from_mir)
                    .unwrap_or(VerifierType::Scalar),
                KfuncRetKind::PointerMaybeNull => {
                    let acquire_kind = kfunc_acquire_kind(kfunc);
                    if let Some(kind) = acquire_kind {
                        state.set_live_kfunc_ref(*dst, true, Some(kind));
                    }
                    VerifierType::Ptr {
                        space: AddressSpace::Kernel,
                        nullability: Nullability::MaybeNull,
                        bounds: None,
                        ringbuf_ref: None,
                        kfunc_ref: if acquire_kind.is_some() {
                            Some(*dst)
                        } else {
                            None
                        },
                    }
                }
            };
            state.set_with_range(*dst, ty, ValueRange::Unknown);
        }
        MirInst::CallSubfn { dst, args, .. } => {
            if args.len() > 5 {
                errors.push(VerifierTypeError::new(format!(
                    "BPF subfunctions support at most 5 arguments, got {}",
                    args.len()
                )));
            }
            let ty = types
                .get(dst)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Scalar);
            state.set_with_range(*dst, ty, ValueRange::Unknown);
        }
        MirInst::StrCmp { dst, .. }
        | MirInst::StopTimer { dst, .. }
        | MirInst::LoopHeader { counter: dst, .. }
        | MirInst::Phi { dst, .. } => {
            let phi_guard = if let MirInst::Phi { args, .. } = inst {
                let mut merged: Option<Option<Guard>> = None;
                for (_, reg) in args {
                    let next = state.guards.get(reg).copied();
                    merged = Some(match merged {
                        None => next,
                        Some(existing) if existing == next => existing,
                        _ => None,
                    });
                    if matches!(merged, Some(None)) {
                        break;
                    }
                }
                merged.flatten()
            } else {
                None
            };
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
            if let Some(guard) = phi_guard {
                state.guards.insert(*dst, guard);
            }
        }
        MirInst::MapLookup { dst, map, key } => {
            if !supports_generic_map_kind(map.kind) {
                errors.push(VerifierTypeError::new(format!(
                    "map operations do not support map kind {:?} for '{}'",
                    map.kind, map.name
                )));
            }
            check_map_operand_scalar_size(*key, "map key", types, errors);
            if map.name == STRING_COUNTER_MAP_NAME {
                check_ptr_access(
                    *key,
                    "map key",
                    &[AddressSpace::Stack, AddressSpace::Map],
                    0,
                    16,
                    state,
                    errors,
                );
            } else if let VerifierType::Ptr { .. } = state.get(*key) {
                require_ptr_with_space(
                    *key,
                    "map key",
                    &[AddressSpace::Stack, AddressSpace::Map],
                    state,
                    errors,
                );
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
                    kfunc_ref: None,
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
                    kfunc_ref: None,
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
                    kfunc_ref: None,
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
        MirInst::MapUpdate {
            map,
            key,
            val,
            flags,
        } => {
            if !supports_generic_map_kind(map.kind) {
                errors.push(VerifierTypeError::new(format!(
                    "map operations do not support map kind {:?} for '{}'",
                    map.kind, map.name
                )));
            }
            if *flags > i32::MAX as u64 {
                errors.push(VerifierTypeError::new(format!(
                    "map update flags {} exceed supported 32-bit immediate range",
                    flags
                )));
            }
            check_map_operand_scalar_size(*key, "map key", types, errors);
            check_map_operand_scalar_size(*val, "map value", types, errors);
            if map.name == STRING_COUNTER_MAP_NAME {
                check_ptr_access(
                    *key,
                    "map key",
                    &[AddressSpace::Stack, AddressSpace::Map],
                    0,
                    16,
                    state,
                    errors,
                );
            } else if let VerifierType::Ptr { .. } = state.get(*key) {
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
            check_map_operand_scalar_size(*key, "map key", types, errors);
            if map.name == STRING_COUNTER_MAP_NAME {
                check_ptr_access(
                    *key,
                    "map key",
                    &[AddressSpace::Stack, AddressSpace::Map],
                    0,
                    16,
                    state,
                    errors,
                );
            } else if let VerifierType::Ptr { .. } = state.get(*key) {
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
        kfunc_ref,
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
            kfunc_ref,
        });
    }

    None
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

include!("verifier_types/calls.rs");

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

include!("verifier_types/ranges.rs");

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

include!("verifier_types/map_layout.rs");

#[cfg(test)]
mod tests;
