use super::*;

impl GraphColoringAllocator {
    pub(super) fn make_worklist(&mut self) {
        let mut nodes: Vec<VReg> = self.graph.nodes.iter().copied().collect();
        nodes.sort_by_key(|v| v.0);

        for vreg in nodes {
            if self.node_state.get(&vreg) != Some(&NodeState::Initial) {
                continue;
            }

            let degree = self.graph.degree(vreg);
            let move_related = self.is_move_related(vreg);
            let k = self.effective_k(vreg);

            if k == 0 || degree >= k {
                self.spill_worklist.insert(vreg);
                self.node_state.insert(vreg, NodeState::Spill);
            } else if move_related {
                self.freeze_worklist.insert(vreg);
                self.node_state.insert(vreg, NodeState::Freeze);
            } else {
                self.simplify_worklist.push_back(vreg);
                self.node_state.insert(vreg, NodeState::Simplify);
            }
        }

        // Initialize move worklist with all moves
        let mut all_moves: Vec<Move> = self.graph.all_moves.iter().copied().collect();
        all_moves.sort_by_key(|mv| (mv.src.0, mv.dst.0));
        for mv in all_moves {
            self.move_worklist.push_back(mv);
            self.move_state.insert(mv, MoveState::Worklist);
        }
    }

    /// Check if a node is involved in any active move
    pub(super) fn is_move_related(&self, vreg: VReg) -> bool {
        for mv in self.graph.moves_for(vreg) {
            match self.move_state.get(&mv) {
                Some(MoveState::Worklist) | Some(MoveState::Active) | None => return true,
                _ => {}
            }
        }
        false
    }

    /// Get active moves for a node
    pub(super) fn node_moves(&self, vreg: VReg) -> Vec<Move> {
        let mut moves: Vec<Move> = self
            .graph
            .moves_for(vreg)
            .filter(|mv| {
                matches!(
                    self.move_state.get(mv),
                    Some(MoveState::Worklist) | Some(MoveState::Active) | None
                )
            })
            .collect();
        moves.sort_by_key(|mv| (mv.src.0, mv.dst.0));
        moves
    }

    /// Simplify: remove a low-degree non-move-related node
    pub(super) fn simplify(&mut self) {
        if let Some(vreg) = self.simplify_worklist.pop_front() {
            self.select_stack.push(vreg);
            self.node_state.insert(vreg, NodeState::OnStack);

            // Decrement degree of neighbors
            let mut neighbors: Vec<VReg> = self.graph.adjacent(vreg).collect();
            neighbors.sort_by_key(|n| n.0);
            for neighbor in neighbors {
                self.decrement_degree(neighbor);
            }
        }
    }

    /// Decrement degree when a neighbor is removed
    pub(super) fn decrement_degree(&mut self, vreg: VReg) {
        if self.is_precolored(vreg) {
            return;
        }
        let old_degree = self.graph.degree.get(&vreg).copied().unwrap_or(0);
        if old_degree == 0 {
            return;
        }

        let new_degree = old_degree - 1;
        self.graph.degree.insert(vreg, new_degree);

        // If degree dropped below K, move from spill to freeze/simplify
        if old_degree == self.effective_k(vreg) {
            // Enable moves for this node and its neighbors
            let mut neighbors: Vec<VReg> = self.graph.adjacent(vreg).collect();
            neighbors.sort_by_key(|n| n.0);
            self.enable_moves(vreg);
            for neighbor in neighbors {
                self.enable_moves(neighbor);
            }

            self.spill_worklist.remove(&vreg);

            if self.is_move_related(vreg) {
                self.freeze_worklist.insert(vreg);
                self.node_state.insert(vreg, NodeState::Freeze);
            } else {
                self.simplify_worklist.push_back(vreg);
                self.node_state.insert(vreg, NodeState::Simplify);
            }
        }
    }

    /// Enable moves involving a node
    pub(super) fn enable_moves(&mut self, vreg: VReg) {
        for mv in self.node_moves(vreg) {
            if self.move_state.get(&mv) == Some(&MoveState::Active) {
                self.active_moves.remove(&mv);
                self.move_worklist.push_back(mv);
                self.move_state.insert(mv, MoveState::Worklist);
            }
        }
    }
}
