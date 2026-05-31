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

    let current_summary = current_summary.as_ref();
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
        seed_entry_iter_state(&mut entry_state, func, summary);
        seed_entry_unknown_stack_object_state(&mut entry_state, func, summary);
        for i in 0..func.param_count {
            if let Some(slot) = func.param_stack_slots.get(&i).copied() {
                let ringbuf_seeded = summary.ringbuf_dynptr_delta_arg(i) < 0;
                if !ringbuf_seeded
                    && (summary.requires_initialized_dynptr_arg(i)
                        || summary.dynptr_delta_arg(i) < 0)
                {
                    entry_state.initialize_dynptr_slot(slot);
                }
                for _ in 0..summary.ringbuf_dynptr_delta_arg(i).saturating_neg() {
                    entry_state.initialize_dynptr_slot(slot);
                    entry_state.acquire_ringbuf_dynptr_slot(slot);
                }
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
            if matches!(inst, MirInst::Phi { .. }) {
                continue;
            }
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
                propagate_state(
                    block_id,
                    *target,
                    func,
                    types,
                    &state,
                    &mut errors,
                    &mut in_states,
                    &mut worklist,
                );
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
                propagate_state(
                    block_id,
                    *if_true,
                    func,
                    types,
                    &true_state,
                    &mut errors,
                    &mut in_states,
                    &mut worklist,
                );
                propagate_state(
                    block_id,
                    *if_false,
                    func,
                    types,
                    &false_state,
                    &mut errors,
                    &mut in_states,
                    &mut worklist,
                );
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
                propagate_state(
                    block_id,
                    *body,
                    func,
                    types,
                    &body_state,
                    &mut errors,
                    &mut in_states,
                    &mut worklist,
                );
                propagate_state(
                    block_id,
                    *exit,
                    func,
                    types,
                    &state,
                    &mut errors,
                    &mut in_states,
                    &mut worklist,
                );
            }
            MirInst::LoopBack { header, .. } => {
                propagate_state(
                    block_id,
                    *header,
                    func,
                    types,
                    &state,
                    &mut errors,
                    &mut in_states,
                    &mut worklist,
                );
            }
            MirInst::Return { val } => {
                check_required_return_range(
                    current_summary,
                    func,
                    types,
                    val.as_ref(),
                    &state,
                    &slot_sizes,
                    &mut errors,
                );
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
                check_live_iter_families_at_return(current_summary, func, &state, &mut errors);
                let allowed_ringbuf_dynptr_slots =
                    allowed_ringbuf_dynptr_slots(current_summary, func);
                if let Some(slot) =
                    state.first_live_ringbuf_dynptr_slot_except_slots(&allowed_ringbuf_dynptr_slots)
                {
                    errors.push(VerifierTypeError::new(format!(
                        "unreleased ringbuf dynptr reservation at function exit: stack slot {}",
                        slot.0
                    )));
                }
                let allowed_unknown_stack_object_slots =
                    allowed_unknown_stack_object_slots(current_summary, func);
                if let Some((slot, type_name)) = state.first_live_unknown_stack_object_except_slots(
                    &allowed_unknown_stack_object_slots,
                ) {
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
    summary: &SubfunctionSummary,
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

fn seed_entry_iter_state(
    state: &mut VerifierState,
    func: &MirFunction,
    summary: &SubfunctionSummary,
) {
    for idx in 0..func.param_count {
        let Some(delta) = summary.iter_delta_arg(idx) else {
            continue;
        };
        if delta.delta >= 0 {
            continue;
        }
        let Some(slot) = func.param_stack_slots.get(&idx).copied() else {
            continue;
        };
        for _ in 0..delta.delta.unsigned_abs() {
            let _ = apply_iter_lifecycle_op(state, delta.family, KfuncIterLifecycleOp::New, slot);
        }
    }
}

fn seed_entry_unknown_stack_object_state(
    state: &mut VerifierState,
    func: &MirFunction,
    summary: &SubfunctionSummary,
) {
    for idx in 0..func.param_count {
        let Some(slot) = func.param_stack_slots.get(&idx).copied() else {
            continue;
        };
        if let Some(object_type) = summary.unknown_stack_object_required_arg(idx) {
            seed_unknown_stack_object_slot(state, slot, object_type);
        } else if let Some(delta) = summary.unknown_stack_object_delta_arg(idx)
            && delta.delta < 0
        {
            seed_unknown_stack_object_slot(state, slot, &delta.object_type);
        }
    }
}

fn seed_unknown_stack_object_slot(
    state: &mut VerifierState,
    slot: StackSlotId,
    object_type: &crate::compiler::subfn_summaries::SubfunctionUnknownStackObjectType,
) {
    if !state.has_unknown_stack_object_slot(slot, &object_type.type_name, object_type.type_id) {
        state.initialize_unknown_stack_object_slot(
            slot,
            &object_type.type_name,
            object_type.type_id,
        );
    }
}

fn allowed_rcu_depth(current_summary: Option<&SubfunctionSummary>) -> u32 {
    current_summary
        .map(|summary| summary.rcu_read_lock_delta().max(0) as u32)
        .unwrap_or(0)
}

fn allowed_preempt_depth(current_summary: Option<&SubfunctionSummary>) -> u32 {
    current_summary
        .map(|summary| summary.preempt_disable_delta().max(0) as u32)
        .unwrap_or(0)
}

fn allowed_local_irq_slots(
    current_summary: Option<&SubfunctionSummary>,
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

fn check_live_iter_families_at_return(
    current_summary: Option<&SubfunctionSummary>,
    func: &MirFunction,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    for family in [
        KfuncIterFamily::TaskVma,
        KfuncIterFamily::Task,
        KfuncIterFamily::ScxDsq,
        KfuncIterFamily::Num,
        KfuncIterFamily::Bits,
        KfuncIterFamily::Css,
        KfuncIterFamily::CssTask,
        KfuncIterFamily::Dmabuf,
        KfuncIterFamily::KmemCache,
    ] {
        let allowed_slots = allowed_iter_slots(current_summary, func, family);
        if state.has_live_iter_family_except_slots(family, &allowed_slots) {
            errors.push(VerifierTypeError::new(format!(
                "unreleased {} iterator at function exit",
                iter_exit_label(family)
            )));
        }
    }
}

fn iter_exit_label(family: KfuncIterFamily) -> &'static str {
    match family {
        KfuncIterFamily::TaskVma => "iter_task_vma",
        KfuncIterFamily::Task => "iter_task",
        KfuncIterFamily::ScxDsq => "iter_scx_dsq",
        KfuncIterFamily::Num => "iter_num",
        KfuncIterFamily::Bits => "iter_bits",
        KfuncIterFamily::Css => "iter_css",
        KfuncIterFamily::CssTask => "iter_css_task",
        KfuncIterFamily::Dmabuf => "iter_dmabuf",
        KfuncIterFamily::KmemCache => "iter_kmem_cache",
    }
}

fn allowed_iter_slots(
    current_summary: Option<&SubfunctionSummary>,
    func: &MirFunction,
    family: KfuncIterFamily,
) -> HashMap<StackSlotId, u32> {
    let mut allowed = HashMap::new();
    let Some(summary) = current_summary else {
        return allowed;
    };
    for idx in 0..func.param_count {
        let Some(delta) = summary.iter_delta_arg(idx) else {
            continue;
        };
        if delta.family != family || delta.delta <= 0 {
            continue;
        }
        if let Some(slot) = func.param_stack_slots.get(&idx).copied() {
            let entry = allowed.entry(slot).or_insert(0u32);
            *entry = entry.saturating_add(delta.delta as u32);
        }
    }
    allowed
}

fn allowed_ringbuf_dynptr_slots(
    current_summary: Option<&SubfunctionSummary>,
    func: &MirFunction,
) -> HashMap<StackSlotId, u32> {
    let mut allowed = HashMap::new();
    let Some(summary) = current_summary else {
        return allowed;
    };
    for idx in 0..func.param_count {
        let delta = summary.ringbuf_dynptr_delta_arg(idx).max(0) as u32;
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

fn allowed_unknown_stack_object_slots(
    current_summary: Option<&SubfunctionSummary>,
    func: &MirFunction,
) -> HashMap<StackSlotId, u32> {
    let mut allowed = HashMap::new();
    let Some(summary) = current_summary else {
        return allowed;
    };
    for idx in 0..func.param_count {
        let mut delta = summary
            .unknown_stack_object_delta_arg(idx)
            .map(|delta| delta.delta.max(0) as u32)
            .unwrap_or(0);
        if summary.unknown_stack_object_required_arg(idx).is_some() {
            delta = delta.saturating_add(1);
        }
        if summary
            .unknown_stack_object_maybe_initialized_arg(idx)
            .is_some()
        {
            delta = delta.saturating_add(1);
        }
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
    current_summary: Option<&SubfunctionSummary>,
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
    current_summary: Option<&SubfunctionSummary>,
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

fn return_range_message(func: &MirFunction, required: ScalarValueRange) -> String {
    let name = func.name.as_deref().unwrap_or("subfunction");
    if required.min == required.max {
        format!("callback return for '{}' must be {}", name, required.min)
    } else {
        format!(
            "callback return for '{}' must be in range {}..={}",
            name, required.min, required.max
        )
    }
}

fn mir_value_type_range(
    value: Option<&MirValue>,
    types: &HashMap<VReg, MirType>,
) -> Option<ValueRange> {
    match value? {
        MirValue::Const(value) => Some(ValueRange::Known {
            min: *value,
            max: *value,
        }),
        MirValue::VReg(vreg) => types
            .get(vreg)
            .and_then(MirType::scalar_value_range)
            .map(|(min, max)| ValueRange::Known { min, max }),
        MirValue::StackSlot(_) => None,
    }
}

fn check_required_return_range(
    current_summary: Option<&SubfunctionSummary>,
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
    value: Option<&MirValue>,
    state: &VerifierState,
    slot_sizes: &HashMap<StackSlotId, i64>,
    errors: &mut Vec<VerifierTypeError>,
) {
    let Some(required) = current_summary.and_then(SubfunctionSummary::required_return_range) else {
        return;
    };
    let message = return_range_message(func, required);
    let Some(value) = value else {
        errors.push(VerifierTypeError::new(format!(
            "{}; missing callback return value",
            message
        )));
        return;
    };
    let ty = value_type(value, state, slot_sizes);
    if !matches!(ty, VerifierType::Scalar | VerifierType::Bool) {
        errors.push(VerifierTypeError::new(format!(
            "{}; got non-scalar return",
            message
        )));
        return;
    }
    let range = match value_range(value, state) {
        known @ ValueRange::Known { .. } => known,
        ValueRange::Unknown => {
            mir_value_type_range(Some(value), types).unwrap_or(ValueRange::Unknown)
        }
    };
    match range {
        ValueRange::Known { min, max } if required.contains(min, max) => {}
        ValueRange::Known { .. } | ValueRange::Unknown => {
            errors.push(VerifierTypeError::new(message));
        }
    }
}

fn propagate_state(
    pred: BlockId,
    block: BlockId,
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
    state: &VerifierState,
    errors: &mut Vec<VerifierTypeError>,
    in_states: &mut HashMap<BlockId, VerifierState>,
    worklist: &mut VecDeque<BlockId>,
) {
    if !state.is_reachable() {
        return;
    }
    let mut state = state.clone();
    apply_incoming_phi_edges(pred, block, func, types, &mut state, errors);

    let updated = match in_states.get(&block) {
        None => {
            in_states.insert(block, state);
            true
        }
        Some(existing) => {
            let merged = existing.join(&state);
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

fn apply_incoming_phi_edges(
    pred: BlockId,
    block: BlockId,
    func: &MirFunction,
    types: &HashMap<VReg, MirType>,
    state: &mut VerifierState,
    errors: &mut Vec<VerifierTypeError>,
) {
    for inst in &func.block(block).instructions {
        let MirInst::Phi { dst, args } = inst else {
            continue;
        };
        let Some((_, src)) = args.iter().find(|(arg_block, _)| *arg_block == pred) else {
            errors.push(VerifierTypeError::new(format!(
                "phi for v{} in block {} has no incoming value from predecessor {}",
                dst.0, block.0, pred.0
            )));
            continue;
        };
        if matches!(state.get(*src), VerifierType::Uninit) {
            errors.push(VerifierTypeError::new(format!(
                "use of uninitialized v{} in phi for v{}",
                src.0, dst.0
            )));
            continue;
        }
        apply_phi_edge_inst(*dst, *src, types, state);
    }
}
