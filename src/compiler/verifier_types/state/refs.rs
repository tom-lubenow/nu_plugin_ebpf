use super::*;

impl VerifierState {
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
                self.regs[idx] = VerifierType::Unknown;
                self.ranges[idx] = ValueRange::Unknown;
                self.non_zero[idx] = false;
                self.not_equal[idx].clear();
                self.guards.remove(&reg);
            }
        }
    }

    pub(in crate::compiler::verifier_types) fn has_live_ringbuf_refs(&self) -> bool {
        self.live_ringbuf_refs
            .iter()
            .copied()
            .any(std::convert::identity)
    }

    pub(in crate::compiler::verifier_types) fn has_live_kfunc_refs(&self) -> bool {
        self.live_kfunc_refs
            .iter()
            .copied()
            .any(std::convert::identity)
    }

    pub(in crate::compiler::verifier_types) fn is_live_kfunc_ref(&self, id: VReg) -> bool {
        self.live_kfunc_refs
            .get(id.0 as usize)
            .copied()
            .unwrap_or(false)
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

    pub(in crate::compiler::verifier_types) fn acquire_iter_task_vma_slot(
        &mut self,
        slot: StackSlotId,
    ) {
        self.iter_task_vma_min_depth = self.iter_task_vma_min_depth.saturating_add(1);
        self.iter_task_vma_max_depth = self.iter_task_vma_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_task_vma_slots, slot);
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
    ) {
        self.iter_task_min_depth = self.iter_task_min_depth.saturating_add(1);
        self.iter_task_max_depth = self.iter_task_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_task_slots, slot);
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
    ) {
        self.iter_scx_dsq_min_depth = self.iter_scx_dsq_min_depth.saturating_add(1);
        self.iter_scx_dsq_max_depth = self.iter_scx_dsq_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_scx_dsq_slots, slot);
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

    pub(in crate::compiler::verifier_types) fn acquire_iter_num_slot(&mut self, slot: StackSlotId) {
        self.iter_num_min_depth = self.iter_num_min_depth.saturating_add(1);
        self.iter_num_max_depth = self.iter_num_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_num_slots, slot);
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
    ) {
        self.iter_bits_min_depth = self.iter_bits_min_depth.saturating_add(1);
        self.iter_bits_max_depth = self.iter_bits_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_bits_slots, slot);
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

    pub(in crate::compiler::verifier_types) fn acquire_iter_css_slot(&mut self, slot: StackSlotId) {
        self.iter_css_min_depth = self.iter_css_min_depth.saturating_add(1);
        self.iter_css_max_depth = self.iter_css_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_css_slots, slot);
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

    pub(in crate::compiler::verifier_types) fn acquire_iter_dmabuf_slot(
        &mut self,
        slot: StackSlotId,
    ) {
        self.iter_dmabuf_min_depth = self.iter_dmabuf_min_depth.saturating_add(1);
        self.iter_dmabuf_max_depth = self.iter_dmabuf_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_dmabuf_slots, slot);
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
    ) {
        self.iter_kmem_cache_min_depth = self.iter_kmem_cache_min_depth.saturating_add(1);
        self.iter_kmem_cache_max_depth = self.iter_kmem_cache_max_depth.saturating_add(1);
        increment_slot_depth(&mut self.iter_kmem_cache_slots, slot);
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

    pub(in crate::compiler::verifier_types) fn acquire_res_spin_lock(&mut self) {
        self.res_spin_lock_min_depth = self.res_spin_lock_min_depth.saturating_add(1);
        self.res_spin_lock_max_depth = self.res_spin_lock_max_depth.saturating_add(1);
    }

    pub(in crate::compiler::verifier_types) fn release_res_spin_lock(&mut self) -> bool {
        if self.res_spin_lock_min_depth == 0 {
            return false;
        }
        self.res_spin_lock_min_depth -= 1;
        self.res_spin_lock_max_depth -= 1;
        true
    }

    pub(in crate::compiler::verifier_types) fn has_live_res_spin_lock(&self) -> bool {
        self.res_spin_lock_max_depth > 0
    }

    pub(in crate::compiler::verifier_types) fn acquire_res_spin_lock_irqsave(&mut self) {
        self.res_spin_lock_irqsave_min_depth =
            self.res_spin_lock_irqsave_min_depth.saturating_add(1);
        self.res_spin_lock_irqsave_max_depth =
            self.res_spin_lock_irqsave_max_depth.saturating_add(1);
    }

    pub(in crate::compiler::verifier_types) fn acquire_res_spin_lock_irqsave_slot(
        &mut self,
        slot: StackSlotId,
    ) {
        self.acquire_res_spin_lock_irqsave();
        increment_slot_depth(&mut self.res_spin_lock_irqsave_slots, slot);
    }

    pub(in crate::compiler::verifier_types) fn release_res_spin_lock_irqsave(&mut self) -> bool {
        if self.res_spin_lock_irqsave_min_depth == 0 {
            return false;
        }
        self.res_spin_lock_irqsave_min_depth -= 1;
        self.res_spin_lock_irqsave_max_depth -= 1;
        true
    }

    pub(in crate::compiler::verifier_types) fn release_res_spin_lock_irqsave_slot(
        &mut self,
        slot: StackSlotId,
    ) -> bool {
        if self.res_spin_lock_irqsave_min_depth == 0 {
            return false;
        }
        if !decrement_slot_depth(&mut self.res_spin_lock_irqsave_slots, slot) {
            return false;
        }
        self.release_res_spin_lock_irqsave()
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
