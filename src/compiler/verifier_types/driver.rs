use super::*;
use std::collections::{HashMap, VecDeque};

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
            .map(verifier_type_from_mir)
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
                let guard = state.guard(*cond);
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
