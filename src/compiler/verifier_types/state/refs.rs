use super::*;

fn unknown_stack_object_type_key(
    type_name: &str,
    type_id: Option<u32>,
) -> UnknownStackObjectTypeKey {
    (type_name.to_string(), type_id)
}

impl VerifierState {
    pub(in crate::compiler::verifier_types) fn initialize_dynptr_slot(
        &mut self,
        slot: StackSlotId,
    ) {
        self.released_ringbuf_dynptr_slots.remove(&slot);
        self.ringbuf_dynptr_alias_roots.remove(&slot);
        self.dynptr_initialized_slots.insert(slot);
        self.maybe_initialized_dynptr_slots.insert(slot);
    }

    pub(in crate::compiler::verifier_types) fn is_dynptr_slot_initialized(
        &self,
        slot: StackSlotId,
    ) -> bool {
        self.dynptr_initialized_slots.contains(&slot)
    }

    pub(in crate::compiler::verifier_types) fn is_dynptr_slot_maybe_initialized(
        &self,
        slot: StackSlotId,
    ) -> bool {
        self.maybe_initialized_dynptr_slots.contains(&slot)
    }

    pub(in crate::compiler::verifier_types) fn deinitialize_dynptr_slot(
        &mut self,
        slot: StackSlotId,
    ) {
        self.dynptr_initialized_slots.remove(&slot);
        self.maybe_initialized_dynptr_slots.remove(&slot);
    }

    pub(in crate::compiler::verifier_types) fn mark_dynptr_slot_maybe_initialized(
        &mut self,
        slot: StackSlotId,
    ) {
        self.released_ringbuf_dynptr_slots.remove(&slot);
        self.ringbuf_dynptr_alias_roots.remove(&slot);
        self.dynptr_initialized_slots.remove(&slot);
        self.maybe_initialized_dynptr_slots.insert(slot);
    }

    pub(in crate::compiler::verifier_types) fn acquire_ringbuf_dynptr_slot(
        &mut self,
        slot: StackSlotId,
    ) {
        self.released_ringbuf_dynptr_slots.remove(&slot);
        self.ringbuf_dynptr_alias_roots.insert(slot, slot);
        increment_slot_depth(&mut self.ringbuf_dynptr_slots, slot);
    }

    pub(in crate::compiler::verifier_types) fn release_ringbuf_dynptr_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        let Some(root) = self.ringbuf_dynptr_root(slot) else {
            return false;
        };
        let released = decrement_slot_depth(&mut self.ringbuf_dynptr_slots, root);
        if released {
            for member in self.ringbuf_dynptr_alias_members(root) {
                self.released_ringbuf_dynptr_slots.insert(member);
                self.dynptr_initialized_slots.remove(&member);
                self.maybe_initialized_dynptr_slots.remove(&member);
                self.ringbuf_dynptr_alias_roots.remove(&member);
            }
        }
        released
    }

    pub(in crate::compiler::verifier_types) fn copy_ringbuf_dynptr_slot(
        &mut self,
        src: StackSlotId,
        dst: StackSlotId,
        move_semantics: bool,
    ) {
        let Some(root) = self.ringbuf_dynptr_root(src) else {
            return;
        };
        if !self
            .ringbuf_dynptr_slots
            .get(&root)
            .is_some_and(|(_, max_depth)| *max_depth > 0)
        {
            return;
        }
        self.released_ringbuf_dynptr_slots.remove(&dst);
        if move_semantics && src == root {
            if let Some(depth) = self.ringbuf_dynptr_slots.remove(&root) {
                self.ringbuf_dynptr_slots.insert(dst, depth);
                for alias_root in self.ringbuf_dynptr_alias_roots.values_mut() {
                    if *alias_root == root {
                        *alias_root = dst;
                    }
                }
            }
            self.ringbuf_dynptr_alias_roots.remove(&src);
            self.ringbuf_dynptr_alias_roots.insert(dst, dst);
            return;
        }
        self.ringbuf_dynptr_alias_roots.insert(dst, root);
        if move_semantics {
            self.ringbuf_dynptr_alias_roots.remove(&src);
        }
    }

    pub(in crate::compiler::verifier_types) fn is_released_ringbuf_dynptr_slot(
        &self,
        slot: StackSlotId,
    ) -> bool {
        self.released_ringbuf_dynptr_slots.contains(&slot)
    }

    pub(in crate::compiler::verifier_types) fn has_ringbuf_dynptr_slot(
        &self,
        slot: StackSlotId,
    ) -> bool {
        let Some(root) = self.ringbuf_dynptr_root(slot) else {
            return false;
        };
        self.ringbuf_dynptr_slots
            .get(&root)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    pub(in crate::compiler::verifier_types) fn has_live_ringbuf_dynptr_slot(
        &self,
        slot: StackSlotId,
    ) -> bool {
        let Some(root) = self.ringbuf_dynptr_root(slot) else {
            return false;
        };
        self.ringbuf_dynptr_slots
            .get(&root)
            .is_some_and(|(_, max_depth)| *max_depth > 0)
    }

    pub(in crate::compiler::verifier_types) fn first_live_ringbuf_dynptr_slot(
        &self,
    ) -> Option<StackSlotId> {
        self.ringbuf_dynptr_alias_roots
            .iter()
            .find(|(_, root)| {
                self.ringbuf_dynptr_slots
                    .get(root)
                    .is_some_and(|(_, max_depth)| *max_depth > 0)
            })
            .map(|(slot, _)| *slot)
            .or_else(|| {
                self.ringbuf_dynptr_slots
                    .iter()
                    .find_map(|(slot, (_, max_depth))| (*max_depth > 0).then_some(*slot))
            })
    }

    pub(in crate::compiler::verifier_types) fn first_live_ringbuf_dynptr_slot_except_slots(
        &self,
        allowed_slots: &HashMap<StackSlotId, u32>,
    ) -> Option<StackSlotId> {
        self.ringbuf_dynptr_slots
            .iter()
            .find_map(|(slot, (_, max_depth))| {
                (*max_depth > allowed_slots.get(slot).copied().unwrap_or(0)).then_some(*slot)
            })
    }

    fn ringbuf_dynptr_root(&self, slot: StackSlotId) -> Option<StackSlotId> {
        self.ringbuf_dynptr_alias_roots.get(&slot).copied()
    }

    fn ringbuf_dynptr_alias_members(&self, root: StackSlotId) -> Vec<StackSlotId> {
        self.ringbuf_dynptr_alias_roots
            .iter()
            .filter_map(|(slot, alias_root)| (*alias_root == root).then_some(*slot))
            .collect()
    }

    pub(in crate::compiler::verifier_types) fn initialize_unknown_stack_object_slot(
        &mut self,
        slot: StackSlotId,
        type_name: &str,
        type_id: Option<u32>,
    ) {
        increment_typed_slot_depth(
            &mut self.unknown_stack_object_slots,
            (slot, unknown_stack_object_type_key(type_name, type_id)),
        );
    }

    pub(in crate::compiler::verifier_types) fn has_unknown_stack_object_slot(
        &self,
        slot: StackSlotId,
        type_name: &str,
        type_id: Option<u32>,
    ) -> bool {
        self.unknown_stack_object_slots
            .get(&(slot, unknown_stack_object_type_key(type_name, type_id)))
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    pub(in crate::compiler::verifier_types) fn release_unknown_stack_object_slot(
        &mut self,
        slot: StackSlotId,
        type_name: &str,
        type_id: Option<u32>,
    ) -> bool {
        decrement_typed_slot_depth(
            &mut self.unknown_stack_object_slots,
            (slot, unknown_stack_object_type_key(type_name, type_id)),
        )
    }

    pub(in crate::compiler::verifier_types) fn first_live_unknown_stack_object(
        &self,
    ) -> Option<(StackSlotId, String)> {
        self.unknown_stack_object_slots
            .iter()
            .find(|(_, (_, max_depth))| *max_depth > 0)
            .map(|((slot, (type_name, _)), _)| (*slot, type_name.clone()))
    }

    pub(in crate::compiler::verifier_types) fn has_live_unknown_stack_object_slot(
        &self,
        slot: StackSlotId,
    ) -> bool {
        self.unknown_stack_object_slots
            .iter()
            .any(|((candidate_slot, _), (_, max_depth))| *candidate_slot == slot && *max_depth > 0)
    }

    pub(in crate::compiler::verifier_types) fn set_live_ringbuf_ref(
        &mut self,
        id: VReg,
        live: bool,
    ) {
        if let Some(slot) = self.live_ringbuf_refs.get_mut(id.0 as usize) {
            *slot = live;
        }
    }

    pub(in crate::compiler::verifier_types) fn set_live_kfunc_ref(
        &mut self,
        id: VReg,
        live: bool,
        kind: Option<KfuncRefKind>,
    ) {
        if let Some(slot) = self.live_kfunc_refs.get_mut(id.0 as usize) {
            *slot = live;
        }
        if live && let Some(slot) = self.released_kfunc_ref_regs.get_mut(id.0 as usize) {
            *slot = false;
        }
        if let Some(slot) = self.kfunc_ref_kinds.get_mut(id.0 as usize) {
            *slot = if live { kind } else { None };
        }
    }

    pub(in crate::compiler::verifier_types) fn invalidate_ringbuf_ref(&mut self, id: VReg) {
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
                self.released_ringbuf_record_regs[idx] = true;
                self.guards.remove(&reg);
            }
        }
    }

    pub(in crate::compiler::verifier_types) fn invalidate_kfunc_ref(&mut self, id: VReg) {
        self.set_live_kfunc_ref(id, false, None);
        for idx in 0..self.regs.len() {
            let reg = VReg(idx as u32);
            let is_ref = matches!(
                self.regs[idx],
                VerifierType::Ptr {
                    kfunc_ref: Some(ref_id),
                    ..
                } if ref_id == id
            );
            if is_ref {
                self.mark_released_kfunc_ref(reg);
            }
        }
    }

    pub(in crate::compiler::verifier_types) fn has_live_ringbuf_refs(&self) -> bool {
        self.live_ringbuf_refs
            .iter()
            .copied()
            .any(std::convert::identity)
    }

    pub(in crate::compiler::verifier_types) fn has_live_ringbuf_refs_except(
        &self,
        allowed: Option<VReg>,
    ) -> bool {
        self.live_ringbuf_refs
            .iter()
            .enumerate()
            .any(|(idx, live)| *live && Some(VReg(idx as u32)) != allowed)
    }

    pub(in crate::compiler::verifier_types) fn is_live_ringbuf_ref(&self, id: VReg) -> bool {
        self.live_ringbuf_refs
            .get(id.0 as usize)
            .copied()
            .unwrap_or(false)
    }

    pub(in crate::compiler::verifier_types) fn is_released_ringbuf_record(
        &self,
        vreg: VReg,
    ) -> bool {
        self.released_ringbuf_record_regs
            .get(vreg.0 as usize)
            .copied()
            .unwrap_or(false)
    }

    pub(in crate::compiler::verifier_types) fn has_live_kfunc_refs(&self) -> bool {
        self.live_kfunc_refs
            .iter()
            .copied()
            .any(std::convert::identity)
    }

    pub(in crate::compiler::verifier_types) fn has_live_kfunc_refs_except(
        &self,
        allowed: Option<VReg>,
    ) -> bool {
        self.live_kfunc_refs
            .iter()
            .enumerate()
            .any(|(idx, live)| *live && Some(VReg(idx as u32)) != allowed)
    }

    pub(in crate::compiler::verifier_types) fn is_live_kfunc_ref(&self, id: VReg) -> bool {
        self.live_kfunc_refs
            .get(id.0 as usize)
            .copied()
            .unwrap_or(false)
    }

    pub(in crate::compiler::verifier_types) fn is_released_kfunc_ref(&self, vreg: VReg) -> bool {
        self.released_kfunc_ref_regs
            .get(vreg.0 as usize)
            .copied()
            .unwrap_or(false)
    }

    pub(in crate::compiler::verifier_types) fn mark_released_kfunc_ref(&mut self, vreg: VReg) {
        self.set_with_range(vreg, VerifierType::Unknown, ValueRange::Unknown);
        if let Some(slot) = self.released_kfunc_ref_regs.get_mut(vreg.0 as usize) {
            *slot = true;
        }
    }

    pub(in crate::compiler::verifier_types) fn kfunc_ref_kind(
        &self,
        id: VReg,
    ) -> Option<KfuncRefKind> {
        self.kfunc_ref_kinds.get(id.0 as usize).copied().flatten()
    }

    pub(in crate::compiler::verifier_types) fn acquire_rcu_read_lock(&mut self) {
        self.rcu_read_lock_min_depth = self.rcu_read_lock_min_depth.saturating_add(1);
        self.rcu_read_lock_max_depth = self.rcu_read_lock_max_depth.saturating_add(1);
    }

    pub(in crate::compiler::verifier_types) fn release_rcu_read_lock(&mut self) -> bool {
        if self.rcu_read_lock_min_depth == 0 {
            return false;
        }
        self.rcu_read_lock_min_depth -= 1;
        self.rcu_read_lock_max_depth -= 1;
        true
    }

    pub(in crate::compiler::verifier_types) fn has_live_rcu_read_lock(&self) -> bool {
        self.rcu_read_lock_max_depth > 0
    }

    pub(in crate::compiler::verifier_types) fn has_live_rcu_read_lock_except(
        &self,
        allowed_depth: u32,
    ) -> bool {
        self.rcu_read_lock_max_depth > allowed_depth
    }

    pub(in crate::compiler::verifier_types) fn acquire_preempt_disable(&mut self) {
        self.preempt_disable_min_depth = self.preempt_disable_min_depth.saturating_add(1);
        self.preempt_disable_max_depth = self.preempt_disable_max_depth.saturating_add(1);
    }

    pub(in crate::compiler::verifier_types) fn release_preempt_disable(&mut self) -> bool {
        if self.preempt_disable_min_depth == 0 {
            return false;
        }
        self.preempt_disable_min_depth -= 1;
        self.preempt_disable_max_depth -= 1;
        true
    }

    pub(in crate::compiler::verifier_types) fn has_live_preempt_disable(&self) -> bool {
        self.preempt_disable_max_depth > 0
    }

    pub(in crate::compiler::verifier_types) fn has_live_preempt_disable_except(
        &self,
        allowed_depth: u32,
    ) -> bool {
        self.preempt_disable_max_depth > allowed_depth
    }

    pub(in crate::compiler::verifier_types) fn acquire_local_irq_disable(&mut self) {
        self.local_irq_disable_min_depth = self.local_irq_disable_min_depth.saturating_add(1);
        self.local_irq_disable_max_depth = self.local_irq_disable_max_depth.saturating_add(1);
    }

    pub(in crate::compiler::verifier_types) fn acquire_local_irq_disable_slot(
        &mut self,
        slot: StackSlotId,
    ) {
        self.acquire_local_irq_disable();
        increment_slot_depth(&mut self.local_irq_disable_slots, slot);
    }

    pub(in crate::compiler::verifier_types) fn release_local_irq_disable(&mut self) -> bool {
        if self.local_irq_disable_min_depth == 0 {
            return false;
        }
        self.local_irq_disable_min_depth -= 1;
        self.local_irq_disable_max_depth -= 1;
        true
    }

    pub(in crate::compiler::verifier_types) fn release_local_irq_disable_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        if self.local_irq_disable_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.local_irq_disable_slots, slot) {
            return false;
        }
        self.release_local_irq_disable()
    }

    pub(in crate::compiler::verifier_types) fn has_live_local_irq_disable(&self) -> bool {
        self.local_irq_disable_max_depth > 0
    }

    pub(in crate::compiler::verifier_types) fn has_live_local_irq_disable_except_slots(
        &self,
        allowed_slots: &HashMap<StackSlotId, u32>,
    ) -> bool {
        let allowed_total = allowed_slots.values().copied().sum();
        let tracked_total: u32 = self
            .local_irq_disable_slots
            .values()
            .map(|(_, max_depth)| *max_depth)
            .sum();
        if self.local_irq_disable_max_depth > tracked_total {
            return true;
        }
        if self.local_irq_disable_max_depth > allowed_total {
            return true;
        }
        self.local_irq_disable_slots
            .iter()
            .any(|(slot, (_, max_depth))| {
                *max_depth > allowed_slots.get(slot).copied().unwrap_or(0)
            })
    }

    pub(in crate::compiler::verifier_types) fn acquire_iter_task_vma_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        acquire_slot_depth(
            &mut self.iter_task_vma_slots,
            &mut self.iter_task_vma_min_depth,
            &mut self.iter_task_vma_max_depth,
            slot,
        )
    }

    pub(in crate::compiler::verifier_types) fn use_iter_task_vma_slot(
        &self,
        slot: StackSlotId,
    ) -> bool {
        self.iter_task_vma_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    pub(in crate::compiler::verifier_types) fn release_iter_task_vma_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        if self.iter_task_vma_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_task_vma_slots, slot) {
            return false;
        }
        self.iter_task_vma_min_depth -= 1;
        self.iter_task_vma_max_depth -= 1;
        true
    }

    pub(in crate::compiler::verifier_types) fn has_live_iter_task_vma(&self) -> bool {
        self.iter_task_vma_max_depth > 0
    }

    pub(in crate::compiler::verifier_types) fn acquire_iter_task_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        acquire_slot_depth(
            &mut self.iter_task_slots,
            &mut self.iter_task_min_depth,
            &mut self.iter_task_max_depth,
            slot,
        )
    }

    pub(in crate::compiler::verifier_types) fn use_iter_task_slot(
        &self,
        slot: StackSlotId,
    ) -> bool {
        self.iter_task_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    pub(in crate::compiler::verifier_types) fn release_iter_task_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        if self.iter_task_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_task_slots, slot) {
            return false;
        }
        self.iter_task_min_depth -= 1;
        self.iter_task_max_depth -= 1;
        true
    }

    pub(in crate::compiler::verifier_types) fn has_live_iter_task(&self) -> bool {
        self.iter_task_max_depth > 0
    }

    pub(in crate::compiler::verifier_types) fn acquire_iter_scx_dsq_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        acquire_slot_depth(
            &mut self.iter_scx_dsq_slots,
            &mut self.iter_scx_dsq_min_depth,
            &mut self.iter_scx_dsq_max_depth,
            slot,
        )
    }

    pub(in crate::compiler::verifier_types) fn use_iter_scx_dsq_slot(
        &self,
        slot: StackSlotId,
    ) -> bool {
        self.iter_scx_dsq_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    pub(in crate::compiler::verifier_types) fn release_iter_scx_dsq_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        if self.iter_scx_dsq_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_scx_dsq_slots, slot) {
            return false;
        }
        self.iter_scx_dsq_min_depth -= 1;
        self.iter_scx_dsq_max_depth -= 1;
        true
    }

    pub(in crate::compiler::verifier_types) fn has_live_iter_scx_dsq(&self) -> bool {
        self.iter_scx_dsq_max_depth > 0
    }

    pub(in crate::compiler::verifier_types) fn acquire_iter_num_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        acquire_slot_depth(
            &mut self.iter_num_slots,
            &mut self.iter_num_min_depth,
            &mut self.iter_num_max_depth,
            slot,
        )
    }

    pub(in crate::compiler::verifier_types) fn use_iter_num_slot(&self, slot: StackSlotId) -> bool {
        self.iter_num_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    pub(in crate::compiler::verifier_types) fn release_iter_num_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        if self.iter_num_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_num_slots, slot) {
            return false;
        }
        self.iter_num_min_depth -= 1;
        self.iter_num_max_depth -= 1;
        true
    }

    pub(in crate::compiler::verifier_types) fn has_live_iter_num(&self) -> bool {
        self.iter_num_max_depth > 0
    }

    pub(in crate::compiler::verifier_types) fn acquire_iter_bits_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        acquire_slot_depth(
            &mut self.iter_bits_slots,
            &mut self.iter_bits_min_depth,
            &mut self.iter_bits_max_depth,
            slot,
        )
    }

    pub(in crate::compiler::verifier_types) fn use_iter_bits_slot(
        &self,
        slot: StackSlotId,
    ) -> bool {
        self.iter_bits_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    pub(in crate::compiler::verifier_types) fn release_iter_bits_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        if self.iter_bits_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_bits_slots, slot) {
            return false;
        }
        self.iter_bits_min_depth -= 1;
        self.iter_bits_max_depth -= 1;
        true
    }

    pub(in crate::compiler::verifier_types) fn has_live_iter_bits(&self) -> bool {
        self.iter_bits_max_depth > 0
    }

    pub(in crate::compiler::verifier_types) fn acquire_iter_css_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        acquire_slot_depth(
            &mut self.iter_css_slots,
            &mut self.iter_css_min_depth,
            &mut self.iter_css_max_depth,
            slot,
        )
    }

    pub(in crate::compiler::verifier_types) fn use_iter_css_slot(&self, slot: StackSlotId) -> bool {
        self.iter_css_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    pub(in crate::compiler::verifier_types) fn release_iter_css_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        if self.iter_css_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_css_slots, slot) {
            return false;
        }
        self.iter_css_min_depth -= 1;
        self.iter_css_max_depth -= 1;
        true
    }

    pub(in crate::compiler::verifier_types) fn has_live_iter_css(&self) -> bool {
        self.iter_css_max_depth > 0
    }

    pub(in crate::compiler::verifier_types) fn acquire_iter_css_task_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        acquire_slot_depth(
            &mut self.iter_css_task_slots,
            &mut self.iter_css_task_min_depth,
            &mut self.iter_css_task_max_depth,
            slot,
        )
    }

    pub(in crate::compiler::verifier_types) fn use_iter_css_task_slot(
        &self,
        slot: StackSlotId,
    ) -> bool {
        self.iter_css_task_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    pub(in crate::compiler::verifier_types) fn release_iter_css_task_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        if self.iter_css_task_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_css_task_slots, slot) {
            return false;
        }
        self.iter_css_task_min_depth -= 1;
        self.iter_css_task_max_depth -= 1;
        true
    }

    pub(in crate::compiler::verifier_types) fn has_live_iter_css_task(&self) -> bool {
        self.iter_css_task_max_depth > 0
    }

    pub(in crate::compiler::verifier_types) fn acquire_iter_dmabuf_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        acquire_slot_depth(
            &mut self.iter_dmabuf_slots,
            &mut self.iter_dmabuf_min_depth,
            &mut self.iter_dmabuf_max_depth,
            slot,
        )
    }

    pub(in crate::compiler::verifier_types) fn use_iter_dmabuf_slot(
        &self,
        slot: StackSlotId,
    ) -> bool {
        self.iter_dmabuf_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    pub(in crate::compiler::verifier_types) fn release_iter_dmabuf_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        if self.iter_dmabuf_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_dmabuf_slots, slot) {
            return false;
        }
        self.iter_dmabuf_min_depth -= 1;
        self.iter_dmabuf_max_depth -= 1;
        true
    }

    pub(in crate::compiler::verifier_types) fn has_live_iter_dmabuf(&self) -> bool {
        self.iter_dmabuf_max_depth > 0
    }

    pub(in crate::compiler::verifier_types) fn acquire_iter_kmem_cache_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        acquire_slot_depth(
            &mut self.iter_kmem_cache_slots,
            &mut self.iter_kmem_cache_min_depth,
            &mut self.iter_kmem_cache_max_depth,
            slot,
        )
    }

    pub(in crate::compiler::verifier_types) fn use_iter_kmem_cache_slot(
        &self,
        slot: StackSlotId,
    ) -> bool {
        self.iter_kmem_cache_slots
            .get(&slot)
            .is_some_and(|(min_depth, _)| *min_depth > 0)
    }

    pub(in crate::compiler::verifier_types) fn release_iter_kmem_cache_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        if self.iter_kmem_cache_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.iter_kmem_cache_slots, slot) {
            return false;
        }
        self.iter_kmem_cache_min_depth -= 1;
        self.iter_kmem_cache_max_depth -= 1;
        true
    }

    pub(in crate::compiler::verifier_types) fn has_live_iter_kmem_cache(&self) -> bool {
        self.iter_kmem_cache_max_depth > 0
    }

    pub(in crate::compiler::verifier_types) fn has_live_iter_family_except_slots(
        &self,
        family: KfuncIterFamily,
        allowed_slots: &HashMap<StackSlotId, u32>,
    ) -> bool {
        match family {
            KfuncIterFamily::TaskVma => has_live_slot_depth_except(
                &self.iter_task_vma_slots,
                self.iter_task_vma_max_depth,
                allowed_slots,
            ),
            KfuncIterFamily::Task => has_live_slot_depth_except(
                &self.iter_task_slots,
                self.iter_task_max_depth,
                allowed_slots,
            ),
            KfuncIterFamily::ScxDsq => has_live_slot_depth_except(
                &self.iter_scx_dsq_slots,
                self.iter_scx_dsq_max_depth,
                allowed_slots,
            ),
            KfuncIterFamily::Num => has_live_slot_depth_except(
                &self.iter_num_slots,
                self.iter_num_max_depth,
                allowed_slots,
            ),
            KfuncIterFamily::Bits => has_live_slot_depth_except(
                &self.iter_bits_slots,
                self.iter_bits_max_depth,
                allowed_slots,
            ),
            KfuncIterFamily::Css => has_live_slot_depth_except(
                &self.iter_css_slots,
                self.iter_css_max_depth,
                allowed_slots,
            ),
            KfuncIterFamily::CssTask => has_live_slot_depth_except(
                &self.iter_css_task_slots,
                self.iter_css_task_max_depth,
                allowed_slots,
            ),
            KfuncIterFamily::Dmabuf => has_live_slot_depth_except(
                &self.iter_dmabuf_slots,
                self.iter_dmabuf_max_depth,
                allowed_slots,
            ),
            KfuncIterFamily::KmemCache => has_live_slot_depth_except(
                &self.iter_kmem_cache_slots,
                self.iter_kmem_cache_max_depth,
                allowed_slots,
            ),
        }
    }

    pub(in crate::compiler::verifier_types) fn res_spin_lock_identity(
        &self,
        reg: VReg,
    ) -> ResSpinLockIdentity {
        self.ctx_field_source(reg)
            .cloned()
            .map(ResSpinLockIdentity::CtxField)
            .unwrap_or(ResSpinLockIdentity::Reg(reg))
    }

    pub(in crate::compiler::verifier_types) fn acquire_res_spin_lock(
        &mut self,
        identity: ResSpinLockIdentity,
    ) -> bool {
        let Some(stack) = &mut self.res_spin_lock_stack else {
            return false;
        };
        if stack.iter().any(|frame| frame.identity == identity) {
            return false;
        }
        self.res_spin_lock_min_depth = self.res_spin_lock_min_depth.saturating_add(1);
        self.res_spin_lock_max_depth = self.res_spin_lock_max_depth.saturating_add(1);
        stack.push(ResSpinLockFrame {
            identity,
            irqsave_slot: None,
        });
        true
    }

    pub(in crate::compiler::verifier_types) fn release_res_spin_lock(
        &mut self,
        identity: ResSpinLockIdentity,
    ) -> bool {
        if self.res_spin_lock_min_depth == 0 {
            return false;
        }
        let Some(stack) = &mut self.res_spin_lock_stack else {
            return false;
        };
        let Some(frame) = stack.last() else {
            return false;
        };
        if frame.identity != identity || frame.irqsave_slot.is_some() {
            return false;
        }
        self.res_spin_lock_min_depth -= 1;
        self.res_spin_lock_max_depth -= 1;
        stack.pop();
        true
    }

    pub(in crate::compiler::verifier_types) fn has_live_res_spin_lock(&self) -> bool {
        self.res_spin_lock_max_depth > 0
    }

    pub(in crate::compiler::verifier_types) fn bpf_spin_lock_identity(
        &self,
        reg: VReg,
    ) -> BpfSpinLockIdentity {
        if let Some((root, bounds)) = self.map_value_root_and_bounds(reg) {
            return BpfSpinLockIdentity::MapBounds {
                root,
                min: bounds.min(),
                max: bounds.max(),
                limit: bounds.limit(),
            };
        }
        BpfSpinLockIdentity::Reg(reg)
    }

    fn map_value_root_and_bounds(&self, reg: VReg) -> Option<(VReg, PtrBounds)> {
        match self.get(reg) {
            VerifierType::Ptr {
                space: AddressSpace::Map,
                bounds: Some(bounds),
                ..
            } => match bounds.origin() {
                PtrOrigin::Map(root) => Some((root, bounds)),
                _ => None,
            },
            _ => None,
        }
    }

    pub(in crate::compiler::verifier_types) fn map_value_source(
        &self,
        reg: VReg,
    ) -> Option<&MapLookupSource> {
        if let Some(source) = self.map_lookup_source(reg) {
            return Some(source);
        }
        let (root, _) = self.map_value_root_and_bounds(reg)?;
        self.map_lookup_source(root)
    }

    pub(in crate::compiler::verifier_types) fn map_value_source_is_ambiguous(
        &self,
        reg: VReg,
    ) -> bool {
        if self.map_lookup_source_is_ambiguous(reg) {
            return true;
        }
        let Some((root, _)) = self.map_value_root_and_bounds(reg) else {
            return false;
        };
        self.map_lookup_source_is_ambiguous(root)
    }

    pub(in crate::compiler::verifier_types) fn has_bpf_spin_lock_for_map_root(
        &self,
        reg: VReg,
    ) -> bool {
        if !self.has_live_bpf_spin_lock() {
            return false;
        }
        let Some((root, _)) = self.map_value_root_and_bounds(reg) else {
            return true;
        };
        match &self.bpf_spin_lock_identity {
            Some(BpfSpinLockIdentity::MapBounds {
                root: lock_root, ..
            }) => self.map_roots_may_alias_same_lookup(*lock_root, root),
            Some(BpfSpinLockIdentity::Reg(_)) => true,
            None => false,
        }
    }

    pub(in crate::compiler::verifier_types) fn acquire_bpf_spin_lock(
        &mut self,
        identity: BpfSpinLockIdentity,
    ) -> bool {
        if self.bpf_spin_lock_max_depth > 0 {
            return false;
        }
        self.bpf_spin_lock_min_depth = 1;
        self.bpf_spin_lock_max_depth = 1;
        self.bpf_spin_lock_identity = Some(identity);
        true
    }

    pub(in crate::compiler::verifier_types) fn release_bpf_spin_lock(
        &mut self,
        identity: BpfSpinLockIdentity,
    ) -> bool {
        if self.bpf_spin_lock_min_depth == 0 {
            return false;
        }
        if !self.bpf_spin_lock_identity_matches(&identity) {
            return false;
        }
        self.bpf_spin_lock_min_depth = 0;
        self.bpf_spin_lock_max_depth = 0;
        self.bpf_spin_lock_identity = None;
        true
    }

    pub(in crate::compiler::verifier_types) fn has_live_bpf_spin_lock(&self) -> bool {
        self.bpf_spin_lock_max_depth > 0
    }

    fn bpf_spin_lock_identity_matches(&self, unlock: &BpfSpinLockIdentity) -> bool {
        match (self.bpf_spin_lock_identity.as_ref(), unlock) {
            (Some(lhs), rhs) if lhs == rhs => true,
            (
                Some(BpfSpinLockIdentity::MapBounds {
                    root: lhs_root,
                    min: lhs_min,
                    max: lhs_max,
                    limit: lhs_limit,
                }),
                BpfSpinLockIdentity::MapBounds {
                    root: rhs_root,
                    min: rhs_min,
                    max: rhs_max,
                    limit: rhs_limit,
                },
            ) => {
                lhs_min == rhs_min
                    && lhs_max == rhs_max
                    && lhs_limit == rhs_limit
                    && self.map_roots_may_alias_same_lookup(*lhs_root, *rhs_root)
            }
            _ => false,
        }
    }

    pub(in crate::compiler::verifier_types) fn live_kernel_lock_description(
        &self,
    ) -> Option<&'static str> {
        if self.has_live_bpf_spin_lock() {
            Some("bpf_spin_lock")
        } else if self.has_live_res_spin_lock() {
            Some("resource spin lock")
        } else if self.has_live_res_spin_lock_irqsave() {
            Some("resource spin lock irqsave")
        } else {
            None
        }
    }

    pub(in crate::compiler::verifier_types) fn acquire_res_spin_lock_irqsave(
        &mut self,
        identity: ResSpinLockIdentity,
        slot: StackSlotId,
    ) -> bool {
        let Some(stack) = &mut self.res_spin_lock_stack else {
            return false;
        };
        if stack.iter().any(|frame| frame.identity == identity) {
            return false;
        }
        self.res_spin_lock_irqsave_min_depth =
            self.res_spin_lock_irqsave_min_depth.saturating_add(1);
        self.res_spin_lock_irqsave_max_depth =
            self.res_spin_lock_irqsave_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.res_spin_lock_irqsave_slots, slot);
        stack.push(ResSpinLockFrame {
            identity,
            irqsave_slot: Some(slot),
        });
        true
    }

    pub(in crate::compiler::verifier_types) fn release_res_spin_lock_irqsave(
        &mut self,
        identity: ResSpinLockIdentity,
        slot: StackSlotId,
    ) -> bool {
        if self.res_spin_lock_irqsave_min_depth == 0 {
            return false;
        }
        let Some(stack) = &mut self.res_spin_lock_stack else {
            return false;
        };
        let Some(frame) = stack.last() else {
            return false;
        };
        if frame.identity != identity || frame.irqsave_slot != Some(slot) {
            return false;
        }
        if !decrement_slot_depth(&mut self.res_spin_lock_irqsave_slots, slot) {
            return false;
        }
        self.res_spin_lock_irqsave_min_depth -= 1;
        self.res_spin_lock_irqsave_max_depth -= 1;
        stack.pop();
        true
    }

    pub(in crate::compiler::verifier_types) fn has_live_res_spin_lock_irqsave(&self) -> bool {
        self.res_spin_lock_irqsave_max_depth > 0
    }
}

fn increment_slot_depth(depths: &mut HashMap<StackSlotId, (u32, u32)>, slot: StackSlotId) {
    let entry = depths.entry(slot).or_insert((0, 0));
    entry.0 = entry.0.saturating_add(1);
    entry.1 = entry.1.saturating_add(1);
}

fn has_live_slot_depth_except(
    depths: &HashMap<StackSlotId, (u32, u32)>,
    max_depth: u32,
    allowed_slots: &HashMap<StackSlotId, u32>,
) -> bool {
    let tracked_total: u32 = depths.values().map(|(_, max_depth)| *max_depth).sum();
    if max_depth > tracked_total {
        return true;
    }
    let allowed_total = allowed_slots.values().copied().sum();
    if max_depth > allowed_total {
        return true;
    }
    depths
        .iter()
        .any(|(slot, (_, slot_max))| *slot_max > allowed_slots.get(slot).copied().unwrap_or(0))
}

fn acquire_slot_depth(
    depths: &mut HashMap<StackSlotId, (u32, u32)>,
    min_depth: &mut u32,
    max_depth: &mut u32,
    slot: StackSlotId,
) -> bool {
    if depths
        .get(&slot)
        .is_some_and(|(_, max_depth)| *max_depth > 0)
    {
        return false;
    }
    *min_depth = (*min_depth).saturating_add(1);
    *max_depth = (*max_depth).saturating_add(1);
    increment_slot_depth(depths, slot);
    true
}

fn decrement_slot_depth(depths: &mut HashMap<StackSlotId, (u32, u32)>, slot: StackSlotId) -> bool {
    let Some((min_depth, max_depth)) = depths.get_mut(&slot) else {
        return false;
    };
    if *min_depth == 0 {
        return false;
    }
    *min_depth -= 1;
    *max_depth -= 1;
    if *max_depth == 0 {
        depths.remove(&slot);
    }
    true
}

fn increment_typed_slot_depth(
    depths: &mut HashMap<(StackSlotId, UnknownStackObjectTypeKey), (u32, u32)>,
    slot: (StackSlotId, UnknownStackObjectTypeKey),
) {
    let entry = depths.entry(slot).or_insert((0, 0));
    entry.0 = entry.0.saturating_add(1);
    entry.1 = entry.1.saturating_add(1);
}

fn decrement_typed_slot_depth(
    depths: &mut HashMap<(StackSlotId, UnknownStackObjectTypeKey), (u32, u32)>,
    slot: (StackSlotId, UnknownStackObjectTypeKey),
) -> bool {
    let Some((min_depth, max_depth)) = depths.get_mut(&slot) else {
        return false;
    };
    if *min_depth == 0 {
        return false;
    }
    *min_depth -= 1;
    *max_depth -= 1;
    if *max_depth == 0 {
        depths.remove(&slot);
    }
    true
}
