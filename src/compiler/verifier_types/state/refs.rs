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
}
