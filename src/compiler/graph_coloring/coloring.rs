use super::*;

impl GraphColoringAllocator {
    /// Freeze: give up coalescing on a move-related node
    pub(super) fn freeze(&mut self) {
        // Pick lowest-numbered node for deterministic behavior.
        let vreg = match self.freeze_worklist.iter().copied().min_by_key(|v| v.0) {
            Some(v) => v,
            None => return,
        };

        self.freeze_worklist.remove(&vreg);
        self.simplify_worklist.push_back(vreg);
        self.node_state.insert(vreg, NodeState::Simplify);
        self.freeze_moves(vreg);
    }

    /// Freeze all moves involving a node
    pub(super) fn freeze_moves(&mut self, vreg: VReg) {
        for mv in self.node_moves(vreg) {
            self.active_moves.remove(&mv);
            self.move_state.insert(mv, MoveState::Frozen);

            let other = if self.get_alias(mv.src) == self.get_alias(vreg) {
                self.get_alias(mv.dst)
            } else {
                self.get_alias(mv.src)
            };

            // If other is now non-move-related and low-degree, move to simplify
            if !self.is_move_related(other) && self.graph.degree(other) < self.k {
                if self.freeze_worklist.remove(&other) {
                    self.simplify_worklist.push_back(other);
                    self.node_state.insert(other, NodeState::Simplify);
                }
            }
        }
    }

    /// Select a node to spill
    pub(super) fn select_spill(&mut self) {
        // Use spill cost heuristic: spill the node with lowest cost/degree ratio
        let mut best: Option<(VReg, f64)> = None;

        for &vreg in &self.spill_worklist {
            let cost = self.spill_cost.get(&vreg).copied().unwrap_or(1.0);
            let degree = self.graph.degree(vreg).max(1) as f64;
            let priority = cost / degree; // Lower is better to spill

            match best {
                None => best = Some((vreg, priority)),
                Some((_, best_priority)) if priority < best_priority => {
                    best = Some((vreg, priority));
                }
                Some((best_vreg, best_priority))
                    if (priority - best_priority).abs() < f64::EPSILON && vreg.0 < best_vreg.0 =>
                {
                    best = Some((vreg, priority));
                }
                _ => {}
            }
        }

        if let Some((vreg, _)) = best {
            self.spill_worklist.remove(&vreg);
            self.simplify_worklist.push_back(vreg);
            self.node_state.insert(vreg, NodeState::Simplify);
            self.freeze_moves(vreg);
        }
    }

    /// Assign colors (registers) to nodes
    pub(super) fn assign_colors(&mut self) {
        while let Some(vreg) = self.select_stack.pop() {
            if self.is_precolored(vreg) {
                continue;
            }
            // Find colors used by neighbors
            let mut used_colors: HashSet<EbpfReg> = HashSet::new();

            for neighbor in self.graph.adjacent(vreg) {
                let alias = self.get_alias(neighbor);
                if let Some(&color) = self.color.get(&alias) {
                    used_colors.insert(color);
                }
            }

            // Find an available color
            let available = self
                .available_regs
                .iter()
                .find(|r| !used_colors.contains(r) && !self.is_forbidden(vreg, **r));

            if let Some(&reg) = available {
                self.color.insert(vreg, reg);
                self.node_state.insert(vreg, NodeState::Colored);
            } else {
                // Actual spill
                self.spilled_nodes.insert(vreg);
            }
        }

        // Assign colors to coalesced nodes
        for i in 0..self.graph.nodes.len() as u32 {
            let vreg = VReg(i);
            if self.node_state.get(&vreg) == Some(&NodeState::Coalesced) {
                let alias = self.get_alias(vreg);
                if let Some(&color) = self.color.get(&alias) {
                    self.color.insert(vreg, color);
                }
            }
        }
    }
}
