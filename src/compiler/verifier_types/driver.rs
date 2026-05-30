use super::*;
use crate::compiler::mir::SubfunctionId;
use crate::compiler::subfn_summaries::SubfunctionSummary;
use crate::compiler::type_infer::validate_program_capabilities_for_info;
use crate::compiler::{ProbeContext, ProgramTypeInfo};
use std::collections::{HashMap, VecDeque};

pub fn verify_mir(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
) -> Result<(), Vec<VerifierTypeError>> {
    verify_mir_with_subfunction_summaries_impl(func, types, &HashMap::new(), None, None, None, None)
}

pub fn verify_mir_for_program(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
    program: &ProgramTypeInfo,
) -> Result<(), Vec<VerifierTypeError>> {
    verify_mir_with_subfunction_summaries_impl(
        func,
        types,
        &HashMap::new(),
        None,
        Some(program),
        None,
        None,
    )
}

#[cfg(test)]
pub(crate) fn verify_mir_for_probe_context(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
    probe_ctx: &ProbeContext,
) -> Result<(), Vec<VerifierTypeError>> {
    verify_mir_with_subfunction_summaries_impl(
        func,
        types,
        &HashMap::new(),
        None,
        Some(probe_ctx.program_info()),
        Some(probe_ctx),
        None,
    )
}

#[allow(dead_code)]
pub(crate) fn verify_mir_with_subfunction_summaries(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
    subfn_summaries: &HashMap<SubfunctionId, SubfunctionSummary>,
) -> Result<(), Vec<VerifierTypeError>> {
    verify_mir_with_subfunction_summaries_impl(func, types, subfn_summaries, None, None, None, None)
}

#[allow(dead_code)]
pub(crate) fn verify_mir_with_subfunction_summaries_for_probe_context(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
    subfn_summaries: &HashMap<SubfunctionId, SubfunctionSummary>,
    probe_ctx: Option<&ProbeContext>,
    generic_map_value_types: Option<&HashMap<MapRef, MirType>>,
) -> Result<(), Vec<VerifierTypeError>> {
    verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
        func,
        types,
        subfn_summaries,
        None,
        probe_ctx,
        generic_map_value_types,
    )
}

pub(crate) fn verify_mir_with_subfunction_summaries_for_probe_context_with_current_summary(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
    subfn_summaries: &HashMap<SubfunctionId, SubfunctionSummary>,
    current_summary: Option<SubfunctionSummary>,
    probe_ctx: Option<&ProbeContext>,
    generic_map_value_types: Option<&HashMap<MapRef, MirType>>,
) -> Result<(), Vec<VerifierTypeError>> {
    verify_mir_with_subfunction_summaries_impl(
        func,
        types,
        subfn_summaries,
        current_summary,
        probe_ctx.map(|ctx| ctx.program_info()),
        probe_ctx,
        generic_map_value_types,
    )
}

fn verify_mir_with_subfunction_summaries_impl(
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
    subfn_summaries: &HashMap<SubfunctionId, SubfunctionSummary>,
    current_summary: Option<SubfunctionSummary>,
    program: Option<&ProgramTypeInfo>,
    probe_ctx: Option<&ProbeContext>,
    generic_map_value_types: Option<&HashMap<MapRef, MirType>>,
) -> Result<(), Vec<VerifierTypeError>> {
    let effective_program = probe_ctx.map(|ctx| ctx.program_info()).or(program);

    if let Some(program) = effective_program {
        if let Err(errors) = validate_program_capabilities_for_info(func, program) {
            return Err(errors
                .into_iter()
                .map(|err| VerifierTypeError::new(err.message))
                .collect());
        }
    }

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
    let empty_map_value_types = HashMap::new();
    errors.extend(check_generic_map_layout_constraints(
        func,
        types,
        generic_map_value_types.unwrap_or(&empty_map_value_types),
    ));
    if !errors.is_empty() {
        return Err(errors);
    }

    let mut entry_state = VerifierState::new(total_vregs);
    for i in 0..func.param_count {
        let vreg = VReg(i as u32);
        let mut ty = if let Some(slot) = func.param_stack_slots.get(&i).copied() {
            let bounds = slot_sizes
                .get(&slot)
                .copied()
                .map(|limit| PtrBounds::new(PtrOrigin::Stack(slot), 0, 0, limit));
            VerifierType::Ptr {
                space: AddressSpace::Stack,
                nullability: Nullability::NonNull,
                bounds,
                ringbuf_ref: None,
                kfunc_ref: None,
            }
        } else {
            types
                .get(&vreg)
                .map(verifier_type_from_mir)
                .unwrap_or(VerifierType::Unknown)
        };
        if func.param_trusted_btf.contains(&i)
            && let VerifierType::Ptr {
                space: AddressSpace::Kernel,
                bounds,
                ..
            } = &mut ty
        {
            *bounds = Some(PtrBounds::new(
                PtrOrigin::KernelBtf(vreg),
                0,
                0,
                UNKNOWN_KERNEL_BTF_LIMIT,
            ));
        }
        if func.param_non_null.contains(&i)
            && let VerifierType::Ptr { nullability, .. } = &mut ty
        {
            *nullability = Nullability::NonNull;
        }
        if current_summary.is_some_and(|summary| summary.releases_ringbuf_record_arg(i)) {
            ty = VerifierType::Ptr {
                space: AddressSpace::Map,
                nullability: Nullability::NonNull,
                bounds: None,
                ringbuf_ref: Some(vreg),
                kfunc_ref: None,
            };
            entry_state.set_live_ringbuf_ref(vreg, true);
        }
        if let Some(kind) =
            current_summary.and_then(|summary| summary.kfunc_ref_release_arg_kind(i))
        {
            match &mut ty {
                VerifierType::Ptr {
                    space,
                    nullability,
                    kfunc_ref,
                    ..
                } => {
                    *space = AddressSpace::Kernel;
                    *nullability = Nullability::NonNull;
                    *kfunc_ref = Some(vreg);
                }
                _ => {
                    ty = VerifierType::Ptr {
                        space: AddressSpace::Kernel,
                        nullability: Nullability::NonNull,
                        bounds: None,
                        ringbuf_ref: None,
                        kfunc_ref: Some(vreg),
                    };
                }
            }
            entry_state.set_live_kfunc_ref(vreg, true, Some(kind));
        }
        entry_state.set(vreg, ty);
    }
    for slot in &func.entry_initialized_dynptr_slots {
        entry_state.initialize_dynptr_slot(*slot);
    }
    if let Some(summary) = current_summary {
        seed_entry_critical_section_state(&mut entry_state, func, summary);
        for i in 0..func.param_count {
            if !summary.releases_ringbuf_dynptr_arg(i) {
                continue;
            }
            if let Some(slot) = func.param_stack_slots.get(&i).copied() {
                entry_state.initialize_dynptr_slot(slot);
                entry_state.acquire_ringbuf_dynptr_slot(slot);
            }
        }
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
            apply_inst(
                inst,
                types,
                &slot_sizes,
                subfn_summaries,
                effective_program,
                probe_ctx,
                &mut state,
                &mut errors,
            );
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
                let cond_ty = state.get(*cond);
                if !matches!(
                    cond_ty,
                    VerifierType::Scalar | VerifierType::Bool | VerifierType::Ptr { .. }
                ) {
                    errors.push(VerifierTypeError::new(format!(
                        "branch condition expects scalar or pointer, got {:?}",
                        cond_ty
                    )));
                }
                let guard = state
                    .guard(*cond)
                    .or_else(|| direct_branch_guard(*cond, cond_ty));
                let true_state = refine_on_branch(&state, guard, true);
                let false_state = refine_on_branch(&state, guard, false);
                propagate_state(*if_true, &true_state, &mut in_states, &mut worklist);
                propagate_state(*if_false, &false_state, &mut in_states, &mut worklist);
            }
            MirInst::LoopHeader { body, exit, .. } => {
                let mut body_state = state.clone();
                apply_inst(
                    &block.terminator,
                    types,
                    &slot_sizes,
                    subfn_summaries,
                    effective_program,
                    probe_ctx,
                    &mut body_state,
                    &mut errors,
                );
                propagate_state(*body, &body_state, &mut in_states, &mut worklist);
                propagate_state(*exit, &state, &mut in_states, &mut worklist);
            }
            MirInst::LoopBack { header, .. } => {
                propagate_state(*header, &state, &mut in_states, &mut worklist);
            }
            MirInst::Return { val } => {
                let returned_ringbuf_ref =
                    allowed_returned_ringbuf_ref(current_summary, val.as_ref(), &state);
                if state.has_live_ringbuf_refs_except(returned_ringbuf_ref) {
                    errors.push(VerifierTypeError::new(
                        "unreleased ringbuf record reference at function exit",
                    ));
                }
                let returned_kfunc_ref =
                    allowed_returned_kfunc_ref(current_summary, val.as_ref(), &state);
                if state.has_live_kfunc_refs_except(returned_kfunc_ref) {
                    errors.push(VerifierTypeError::new(
                        "unreleased kfunc reference at function exit",
                    ));
                }
                if state.has_live_rcu_read_lock_except(allowed_rcu_depth(current_summary)) {
                    errors.push(VerifierTypeError::new(
                        "unreleased RCU read lock at function exit",
                    ));
                }
                if state.has_live_preempt_disable_except(allowed_preempt_depth(current_summary)) {
                    errors.push(VerifierTypeError::new(
                        "unreleased preempt disable at function exit",
                    ));
                }
                let allowed_local_irq_slots = allowed_local_irq_slots(current_summary, func);
                if state.has_live_local_irq_disable_except_slots(&allowed_local_irq_slots) {
                    errors.push(VerifierTypeError::new(
                        "unreleased local irq disable at function exit",
                    ));
                }
                if state.has_live_res_spin_lock() {
                    errors.push(VerifierTypeError::new(
                        "unreleased res spin lock at function exit",
                    ));
                }
                if state.has_live_bpf_spin_lock() {
                    errors.push(VerifierTypeError::new(
                        "unreleased bpf spin lock at function exit",
                    ));
                }
                if state.has_live_res_spin_lock_irqsave() {
                    errors.push(VerifierTypeError::new(
                        "unreleased res spin lock irqsave at function exit",
                    ));
                }
                if state.has_live_iter_task_vma() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_task_vma iterator at function exit",
                    ));
                }
                if state.has_live_iter_task() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_task iterator at function exit",
                    ));
                }
                if state.has_live_iter_scx_dsq() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_scx_dsq iterator at function exit",
                    ));
                }
                if state.has_live_iter_num() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_num iterator at function exit",
                    ));
                }
                if state.has_live_iter_bits() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_bits iterator at function exit",
                    ));
                }
                if state.has_live_iter_css() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_css iterator at function exit",
                    ));
                }
                if state.has_live_iter_css_task() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_css_task iterator at function exit",
                    ));
                }
                if state.has_live_iter_dmabuf() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_dmabuf iterator at function exit",
                    ));
                }
                if state.has_live_iter_kmem_cache() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_kmem_cache iterator at function exit",
                    ));
                }
                if let Some(slot) = state.first_live_ringbuf_dynptr_slot() {
                    errors.push(VerifierTypeError::new(format!(
                        "unreleased ringbuf dynptr reservation at function exit: stack slot {}",
                        slot.0
                    )));
                }
                if let Some((slot, type_name)) = state.first_live_unknown_stack_object() {
                    errors.push(VerifierTypeError::new(format!(
                        "unreleased unknown stack object at function exit: {} in stack slot {}",
                        type_name, slot.0
                    )));
                }
            }
            MirInst::TailCall { prog_map, index } => {
                if prog_map.kind != MapKind::ProgArray {
                    errors.push(VerifierTypeError::new(format!(
                        "tail_call requires prog-array map, got {}",
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
                if state.has_live_rcu_read_lock() {
                    errors.push(VerifierTypeError::new(
                        "unreleased RCU read lock at function exit",
                    ));
                }
                if state.has_live_preempt_disable() {
                    errors.push(VerifierTypeError::new(
                        "unreleased preempt disable at function exit",
                    ));
                }
                if state.has_live_local_irq_disable() {
                    errors.push(VerifierTypeError::new(
                        "unreleased local irq disable at function exit",
                    ));
                }
                if state.has_live_res_spin_lock() {
                    errors.push(VerifierTypeError::new(
                        "unreleased res spin lock at function exit",
                    ));
                }
                if state.has_live_bpf_spin_lock() {
                    errors.push(VerifierTypeError::new(
                        "unreleased bpf spin lock at function exit",
                    ));
                }
                if state.has_live_res_spin_lock_irqsave() {
                    errors.push(VerifierTypeError::new(
                        "unreleased res spin lock irqsave at function exit",
                    ));
                }
                if state.has_live_iter_task_vma() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_task_vma iterator at function exit",
                    ));
                }
                if state.has_live_iter_task() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_task iterator at function exit",
                    ));
                }
                if state.has_live_iter_scx_dsq() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_scx_dsq iterator at function exit",
                    ));
                }
                if state.has_live_iter_num() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_num iterator at function exit",
                    ));
                }
                if state.has_live_iter_bits() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_bits iterator at function exit",
                    ));
                }
                if state.has_live_iter_css() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_css iterator at function exit",
                    ));
                }
                if state.has_live_iter_css_task() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_css_task iterator at function exit",
                    ));
                }
                if state.has_live_iter_dmabuf() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_dmabuf iterator at function exit",
                    ));
                }
                if state.has_live_iter_kmem_cache() {
                    errors.push(VerifierTypeError::new(
                        "unreleased iter_kmem_cache iterator at function exit",
                    ));
                }
                if let Some(slot) = state.first_live_ringbuf_dynptr_slot() {
                    errors.push(VerifierTypeError::new(format!(
                        "unreleased ringbuf dynptr reservation at function exit: stack slot {}",
                        slot.0
                    )));
                }
                if let Some((slot, type_name)) = state.first_live_unknown_stack_object() {
                    errors.push(VerifierTypeError::new(format!(
                        "unreleased unknown stack object at function exit: {} in stack slot {}",
                        type_name, slot.0
                    )));
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

fn seed_entry_critical_section_state(
    state: &mut VerifierState,
    func: &MirFunction,
    summary: SubfunctionSummary,
) {
    for _ in 0..summary.rcu_read_lock_delta().saturating_neg() {
        state.acquire_rcu_read_lock();
    }
    for _ in 0..summary.preempt_disable_delta().saturating_neg() {
        state.acquire_preempt_disable();
    }
    for idx in 0..func.param_count {
        let Some(slot) = func.param_stack_slots.get(&idx).copied() else {
            continue;
        };
        for _ in 0..summary.local_irq_delta_arg(idx).saturating_neg() {
            state.acquire_local_irq_disable_slot(slot);
        }
    }
}

fn allowed_rcu_depth(current_summary: Option<SubfunctionSummary>) -> u32 {
    current_summary
        .map(|summary| summary.rcu_read_lock_delta().max(0) as u32)
        .unwrap_or(0)
}

fn allowed_preempt_depth(current_summary: Option<SubfunctionSummary>) -> u32 {
    current_summary
        .map(|summary| summary.preempt_disable_delta().max(0) as u32)
        .unwrap_or(0)
}

fn allowed_local_irq_slots(
    current_summary: Option<SubfunctionSummary>,
    func: &MirFunction,
) -> HashMap<StackSlotId, u32> {
    let mut allowed = HashMap::new();
    let Some(summary) = current_summary else {
        return allowed;
    };
    for idx in 0..func.param_count {
        let delta = summary.local_irq_delta_arg(idx).max(0) as u32;
        if delta == 0 {
            continue;
        }
        if let Some(slot) = func.param_stack_slots.get(&idx).copied() {
            let entry = allowed.entry(slot).or_insert(0u32);
            *entry = entry.saturating_add(delta);
        }
    }
    allowed
}

fn allowed_returned_ringbuf_ref(
    current_summary: Option<SubfunctionSummary>,
    val: Option<&MirValue>,
    state: &VerifierState,
) -> Option<VReg> {
    if !current_summary.is_some_and(|summary| summary.returns_ringbuf_record()) {
        return None;
    }
    let Some(MirValue::VReg(vreg)) = val else {
        return None;
    };
    let VerifierType::Ptr {
        space: AddressSpace::Map,
        ringbuf_ref: Some(ref_id),
        ..
    } = state.get(*vreg)
    else {
        return None;
    };
    state.is_live_ringbuf_ref(ref_id).then_some(ref_id)
}

fn allowed_returned_kfunc_ref(
    current_summary: Option<SubfunctionSummary>,
    val: Option<&MirValue>,
    state: &VerifierState,
) -> Option<VReg> {
    let expected_kind = current_summary.and_then(|summary| summary.kfunc_ref_return_kind())?;
    let Some(MirValue::VReg(vreg)) = val else {
        return None;
    };
    let VerifierType::Ptr {
        space: AddressSpace::Kernel,
        kfunc_ref: Some(ref_id),
        ..
    } = state.get(*vreg)
    else {
        return None;
    };
    if state.is_live_kfunc_ref(ref_id) && state.kfunc_ref_kind(ref_id) == Some(expected_kind) {
        Some(ref_id)
    } else {
        None
    }
}

fn direct_branch_guard(cond: VReg, cond_ty: VerifierType) -> Option<Guard> {
    match cond_ty {
        VerifierType::Scalar | VerifierType::Bool => Some(Guard::NonZero {
            reg: cond,
            true_is_non_zero: true,
        }),
        VerifierType::Ptr { .. } => Some(Guard::Ptr {
            ptr: cond,
            true_is_non_null: true,
        }),
        VerifierType::Uninit | VerifierType::Unknown | VerifierType::StalePacketPtr => None,
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
            if !merged.equivalent(existing) {
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
