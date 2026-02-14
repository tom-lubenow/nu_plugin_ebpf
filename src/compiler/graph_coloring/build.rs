use super::*;

impl GraphColoringAllocator {
    /// Build the interference graph from liveness information
    pub(super) fn build<F: RegAllocFunction>(
        &mut self,
        func: &F,
        cfg: &AnalysisCfg,
        liveness: &BlockLiveness,
    ) where
        F::Inst: RegAllocInst,
    {
        // Add all vregs as nodes
        let total_vregs = func.vreg_count().max(func.param_count() as u32);
        for i in 0..total_vregs {
            let vreg = VReg(i);
            self.graph.add_node(vreg);
            if let Some(&reg) = self.precolored.get(&vreg) {
                self.node_state.insert(vreg, NodeState::Precolored);
                self.color.insert(vreg, reg);
            } else {
                self.node_state.insert(vreg, NodeState::Initial);
            }
        }

        // Build interference edges: two vregs interfere if they're both live at the same point
        // We iterate through each instruction and add edges between all simultaneously live vregs
        let block_order = &cfg.rpo;
        let mut inst_idx = 0;

        for &block_id in block_order {
            let block = func.block(block_id);

            // Get live-out set for this block
            let mut live: HashSet<VReg> = liveness
                .live_out
                .get(&block_id)
                .cloned()
                .unwrap_or_default();

            // Process terminator first (backward analysis)
            self.process_instruction_liveness(block.terminator(), &mut live, inst_idx);
            inst_idx += 1;

            // Process instructions in reverse
            for inst in block.instructions().iter().rev() {
                self.process_instruction_liveness(inst, &mut live, inst_idx);

                // Check for move instructions that could be coalesced
                for (dst, src) in inst.move_pairs() {
                    self.graph.add_move(src, dst);
                }

                inst_idx += 1;
            }
        }

        // Add interference edges between all simultaneously live vregs
        self.build_interference_from_liveness(func, cfg, liveness);
    }

    /// Build interference edges from liveness analysis
    pub(super) fn build_interference_from_liveness<F: RegAllocFunction>(
        &mut self,
        func: &F,
        cfg: &AnalysisCfg,
        liveness: &BlockLiveness,
    ) where
        F::Inst: RegAllocInst,
    {
        let block_order = &cfg.rpo;

        for &block_id in block_order {
            let block = func.block(block_id);

            // Start with live-out
            let mut live: HashSet<VReg> = liveness
                .live_out
                .get(&block_id)
                .cloned()
                .unwrap_or_default();

            // Process terminator
            self.apply_call_clobbers(block.terminator(), &live);
            self.add_interference_for_inst(block.terminator(), &live);
            self.update_live_for_inst(block.terminator(), &mut live);
            self.apply_scratch_clobbers(block.terminator(), &live);

            // Process instructions in reverse
            for inst in block.instructions().iter().rev() {
                self.apply_call_clobbers(inst, &live);
                self.add_interference_for_inst(inst, &live);
                self.update_live_for_inst(inst, &mut live);
                self.apply_scratch_clobbers(inst, &live);
            }
        }
    }

    /// Add interference edges for an instruction
    pub(super) fn add_interference_for_inst<I: RegAllocInst>(
        &mut self,
        inst: &I,
        live: &HashSet<VReg>,
    ) {
        let defs = inst.defs();
        let mut move_src: HashMap<VReg, VReg> = HashMap::new();
        for (dst, src) in inst.move_pairs() {
            move_src.insert(dst, src);
        }

        for def in &defs {
            for &live_vreg in live {
                if live_vreg == *def {
                    continue;
                }
                if move_src.get(def).copied() == Some(live_vreg) {
                    continue;
                }
                self.graph.add_edge(*def, live_vreg);
            }
        }

        // Defs in the same instruction cannot alias
        for i in 0..defs.len() {
            for j in (i + 1)..defs.len() {
                if defs[i] != defs[j] {
                    self.graph.add_edge(defs[i], defs[j]);
                }
            }
        }

        // Operands used by the same instruction must not alias registers
        let uses = inst.uses();
        for i in 0..uses.len() {
            for j in (i + 1)..uses.len() {
                if uses[i] != uses[j] {
                    self.graph.add_edge(uses[i], uses[j]);
                }
            }
        }
    }

    pub(super) fn apply_call_clobbers<I: RegAllocInst>(&mut self, inst: &I, live: &HashSet<VReg>) {
        let regs = inst.call_clobbers();
        if regs.is_empty() {
            return;
        }
        let mut live_across: HashSet<VReg> = live.iter().copied().collect();
        for def in inst.defs() {
            live_across.remove(&def);
        }
        self.forbid_regs_for_live(&live_across, regs);
    }

    pub(super) fn apply_scratch_clobbers<I: RegAllocInst>(
        &mut self,
        inst: &I,
        live: &HashSet<VReg>,
    ) {
        let regs = inst.scratch_clobbers();
        if regs.is_empty() {
            return;
        }
        self.forbid_regs_for_live(live, regs);
    }

    /// Update live set for an instruction (backward)
    pub(super) fn update_live_for_inst<I: RegAllocInst>(
        &mut self,
        inst: &I,
        live: &mut HashSet<VReg>,
    ) {
        for def in inst.defs() {
            live.remove(&def);
        }

        for use_vreg in inst.uses() {
            live.insert(use_vreg);
        }
    }

    /// Process instruction for liveness (used during initial build)
    pub(super) fn process_instruction_liveness<I: RegAllocInst>(
        &mut self,
        inst: &I,
        live: &mut HashSet<VReg>,
        _inst_idx: usize,
    ) {
        // Add interference between all live vregs
        let live_vec: Vec<VReg> = live.iter().copied().collect();
        for i in 0..live_vec.len() {
            for j in (i + 1)..live_vec.len() {
                self.graph.add_edge(live_vec[i], live_vec[j]);
            }
        }

        for def in inst.defs() {
            live.remove(&def);
        }
        for use_vreg in inst.uses() {
            live.insert(use_vreg);
        }
    }

    /// Compute spill costs for each vreg
    pub(super) fn compute_spill_costs<F: RegAllocFunction>(
        &mut self,
        func: &F,
        cfg: &AnalysisCfg,
        loop_depths: Option<&HashMap<BlockId, usize>>,
    ) where
        F::Inst: RegAllocInst,
    {
        let total_vregs = func.vreg_count().max(func.param_count() as u32);
        for i in 0..total_vregs {
            let vreg = VReg(i);
            self.spill_cost.insert(vreg, 0.0);
        }

        for &block_id in cfg.rpo.iter() {
            let block = func.block(block_id);
            let depth = loop_depths
                .and_then(|d| d.get(&block_id).copied())
                .unwrap_or(0);
            let weight = 10.0_f64.powi(depth as i32);

            for inst in block.instructions() {
                for def in inst.defs() {
                    *self.spill_cost.entry(def).or_insert(0.0) += weight;
                }
                for use_vreg in inst.uses() {
                    *self.spill_cost.entry(use_vreg).or_insert(0.0) += weight;
                }
            }

            for def in block.terminator().defs() {
                *self.spill_cost.entry(def).or_insert(0.0) += weight;
            }
            for use_vreg in block.terminator().uses() {
                *self.spill_cost.entry(use_vreg).or_insert(0.0) += weight;
            }
        }
    }
}
