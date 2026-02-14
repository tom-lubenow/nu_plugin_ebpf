use super::*;

impl GraphColoringAllocator {
    pub(super) fn is_precolored(&self, vreg: VReg) -> bool {
        matches!(self.node_state.get(&vreg), Some(NodeState::Precolored))
    }

    pub(super) fn is_forbidden(&self, vreg: VReg, reg: EbpfReg) -> bool {
        self.forbidden_regs
            .get(&vreg)
            .map(|set| set.contains(&reg))
            .unwrap_or(false)
    }

    pub(super) fn effective_k(&self, vreg: VReg) -> usize {
        if self.is_precolored(vreg) {
            return 1;
        }
        self.available_regs
            .iter()
            .filter(|reg| !self.is_forbidden(vreg, **reg))
            .count()
    }

    pub(super) fn forbid_regs_for_live(&mut self, live: &HashSet<VReg>, regs: &[EbpfReg]) {
        if regs.is_empty() {
            return;
        }
        for vreg in live {
            let entry = self.forbidden_regs.entry(*vreg).or_default();
            entry.extend(regs.iter().copied());
        }
    }
}
