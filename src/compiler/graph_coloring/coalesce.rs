use super::*;

impl GraphColoringAllocator {
    /// Coalesce: attempt to merge move-related nodes
    pub(super) fn coalesce(&mut self) {
        let Some(mv) = self.move_worklist.pop_front() else {
            return;
        };

        let x = self.get_alias(mv.dst);
        let y = self.get_alias(mv.src);

        // Order so that if one is precolored, it's u (George criterion)
        let (u, v) = if self.is_precolored(x) {
            (x, y)
        } else if self.is_precolored(y) {
            (y, x)
        } else {
            (x, y)
        };

        if u == v {
            // Already coalesced
            self.move_state.insert(mv, MoveState::Coalesced);
            self.add_worklist(u);
        } else if self.graph.interferes(u, v) {
            // Constrained: can't coalesce interfering nodes
            self.move_state.insert(mv, MoveState::Constrained);
            self.add_worklist(u);
            self.add_worklist(v);
        } else if self.is_precolored(u) {
            if self.george(u, v) {
                self.move_state.insert(mv, MoveState::Coalesced);
                self.combine(u, v);
                self.add_worklist(u);
            } else {
                self.active_moves.insert(mv);
                self.move_state.insert(mv, MoveState::Active);
            }
        } else if self.can_coalesce(u, v) {
            // Safe to coalesce using Briggs or George criterion
            self.move_state.insert(mv, MoveState::Coalesced);
            self.combine(u, v);
            self.add_worklist(u);
        } else {
            // Not safe yet, keep as active
            self.active_moves.insert(mv);
            self.move_state.insert(mv, MoveState::Active);
        }
    }

    /// Check if coalescing u and v is safe (Briggs criterion)
    pub(super) fn can_coalesce(&self, u: VReg, v: VReg) -> bool {
        // Briggs: coalesce if resulting node has fewer than K high-degree neighbors
        let k = self.effective_k(u).min(self.effective_k(v));
        if k == 0 {
            return false;
        }
        let mut high_degree_neighbors = HashSet::new();

        for neighbor in self.graph.adjacent(u) {
            if self.graph.degree(neighbor) >= k {
                high_degree_neighbors.insert(neighbor);
            }
        }
        for neighbor in self.graph.adjacent(v) {
            if self.graph.degree(neighbor) >= k {
                high_degree_neighbors.insert(neighbor);
            }
        }

        high_degree_neighbors.len() < k
    }

    /// George criterion for coalescing with a precolored node
    pub(super) fn george(&self, u: VReg, v: VReg) -> bool {
        for t in self.graph.adjacent(v) {
            if self.graph.degree(t) >= self.k && !self.graph.interferes(t, u) {
                return false;
            }
        }
        true
    }

    /// Add node to simplify worklist if appropriate
    pub(super) fn add_worklist(&mut self, vreg: VReg) {
        if self.is_precolored(vreg) {
            return;
        }
        if self.node_state.get(&vreg) == Some(&NodeState::Freeze)
            && !self.is_move_related(vreg)
            && self.graph.degree(vreg) < self.k
        {
            self.freeze_worklist.remove(&vreg);
            self.simplify_worklist.push_back(vreg);
            self.node_state.insert(vreg, NodeState::Simplify);
        }
    }

    /// Combine two nodes (coalesce v into u)
    pub(super) fn combine(&mut self, u: VReg, v: VReg) {
        // Remove v from its worklist
        if self.freeze_worklist.remove(&v) {
            // was in freeze
        } else {
            self.spill_worklist.remove(&v);
        }

        self.node_state.insert(v, NodeState::Coalesced);
        self.alias.insert(v, u);

        // Merge move lists
        let v_moves: Vec<Move> = self.graph.moves_for(v).collect();
        for mv in v_moves {
            self.graph.move_list.entry(u).or_default().insert(mv);
        }

        // Add edges from u to v's neighbors
        let mut v_neighbors: Vec<VReg> = self.graph.adjacent(v).collect();
        v_neighbors.sort_by_key(|n| n.0);
        for neighbor in v_neighbors {
            self.graph.add_edge(u, neighbor);
            self.decrement_degree(neighbor);
        }

        // If u now has high degree, move to spill worklist
        if self.graph.degree(u) >= self.k && self.freeze_worklist.remove(&u) {
            self.spill_worklist.insert(u);
            self.node_state.insert(u, NodeState::Spill);
        }
    }

    /// Get the representative (alias) for a node
    pub(super) fn get_alias(&self, vreg: VReg) -> VReg {
        if self.node_state.get(&vreg) == Some(&NodeState::Coalesced) {
            if let Some(&alias) = self.alias.get(&vreg) {
                return self.get_alias(alias);
            }
        }
        vreg
    }
}
