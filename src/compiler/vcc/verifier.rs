#[path = "verifier/comparison_helpers.rs"]
mod comparison_helpers;
#[path = "verifier/execution.rs"]
mod execution;
#[path = "verifier/refinement.rs"]
mod refinement;

impl VccVerifier {
    const MAX_STATE_UPDATES_PER_BLOCK: usize = 64;

    pub fn verify_function(self, func: &VccFunction) -> Result<(), Vec<VccError>> {
        self.verify_function_with_seed(func, HashMap::new())
    }

    pub fn verify_function_with_seed(
        mut self,
        func: &VccFunction,
        seed: HashMap<VccReg, VccValueType>,
    ) -> Result<(), Vec<VccError>> {
        let mut in_states: HashMap<VccBlockId, VccState> = HashMap::new();
        let mut worklist: VecDeque<VccBlockId> = VecDeque::new();
        let mut update_counts: HashMap<VccBlockId, usize> = HashMap::new();

        in_states.insert(func.entry, VccState::with_seed(seed));
        worklist.push_back(func.entry);

        while let Some(block_id) = worklist.pop_front() {
            let Some(mut state) = in_states.get(&block_id).cloned() else {
                continue;
            };
            if !state.is_reachable() {
                continue;
            }
            let block = func.block(block_id);
            for inst in &block.instructions {
                self.verify_inst(inst, &mut state);
            }
            self.verify_terminator(&block.terminator, &mut state);

            match &block.terminator {
                VccTerminator::Jump { target } => {
                    self.propagate_state(
                        *target,
                        &state,
                        &mut in_states,
                        &mut worklist,
                        &mut update_counts,
                    );
                }
                VccTerminator::Branch {
                    cond,
                    if_true,
                    if_false,
                } => {
                    let (true_state, false_state) = self.refine_branch_states(*cond, &state);
                    self.propagate_state(
                        *if_true,
                        &true_state,
                        &mut in_states,
                        &mut worklist,
                        &mut update_counts,
                    );
                    self.propagate_state(
                        *if_false,
                        &false_state,
                        &mut in_states,
                        &mut worklist,
                        &mut update_counts,
                    );
                }
                VccTerminator::Return { .. } => {}
            }
        }

        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors)
        }
    }

    fn propagate_state(
        &mut self,
        block: VccBlockId,
        state: &VccState,
        in_states: &mut HashMap<VccBlockId, VccState>,
        worklist: &mut VecDeque<VccBlockId>,
        update_counts: &mut HashMap<VccBlockId, usize>,
    ) {
        if !state.is_reachable() {
            return;
        }
        let existing = in_states.get(&block).cloned();
        let mut next_state = match existing.as_ref() {
            None => state.clone(),
            Some(existing) => existing.merge_with(state),
        };

        let updates = update_counts.get(&block).copied().unwrap_or(0);
        if updates >= Self::MAX_STATE_UPDATES_PER_BLOCK {
            next_state = next_state.widened();
        }

        let changed = match existing {
            None => true,
            Some(existing) => existing != next_state,
        };

        if changed {
            in_states.insert(block, next_state);
            *update_counts.entry(block).or_insert(0) += 1;
            worklist.push_back(block);
        }
    }

}
