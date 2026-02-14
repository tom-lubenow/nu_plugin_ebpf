use super::*;

impl CFG {
    /// Build a CFG from a MIR function
    pub fn build(func: &MirFunction) -> Self {
        let analysis = AnalysisCfg::build(func);

        let mut cfg = CFG {
            entry: analysis.entry,
            predecessors: analysis.predecessors,
            successors: analysis.successors,
            idom: analysis.idom,
            rpo: analysis.rpo,
            post_order: analysis.post_order,
            dominance_frontiers: HashMap::new(),
        };

        // Compute dominance frontiers (needed for SSA construction)
        cfg.compute_dominance_frontiers(func);

        cfg
    }

    /// Compute dominance frontiers using the Cooper-Harvey-Kennedy algorithm
    ///
    /// The dominance frontier of a block N is the set of all blocks M where:
    /// - N dominates a predecessor of M, but
    /// - N does not strictly dominate M
    ///
    /// In other words, it's where N's dominance "ends" - the points where
    /// control flow from paths not dominated by N can join.
    fn compute_dominance_frontiers(&mut self, func: &MirFunction) {
        // Initialize empty frontiers for all blocks
        for block in &func.blocks {
            self.dominance_frontiers.insert(block.id, HashSet::new());
        }

        // For each block with multiple predecessors (join points)
        for block in &func.blocks {
            let preds = self
                .predecessors
                .get(&block.id)
                .cloned()
                .unwrap_or_default();

            if preds.len() >= 2 {
                // For each predecessor, walk up the dominator tree
                for pred in &preds {
                    let mut runner = *pred;

                    // Walk up until we reach the immediate dominator of the join point
                    // The immediate dominator strictly dominates the join point,
                    // so it's not in the frontier
                    //
                    // For entry block, idom is not set (or is itself), so we also check
                    // if we've reached the entry
                    let idom_of_block = self.idom.get(&block.id).copied();

                    while Some(runner) != idom_of_block {
                        // This block is in the dominance frontier of runner
                        self.dominance_frontiers
                            .entry(runner)
                            .or_default()
                            .insert(block.id);

                        // Move up to the immediate dominator
                        match self.idom.get(&runner) {
                            Some(&idom) if idom != runner => runner = idom,
                            _ => break, // Reached entry or cycle
                        }
                    }
                }
            }
        }
    }

    /// Get the dominance frontier of a block
    pub fn dominance_frontier(&self, block: BlockId) -> HashSet<BlockId> {
        self.dominance_frontiers
            .get(&block)
            .cloned()
            .unwrap_or_default()
    }

    /// Check if block A dominates block B
    pub fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        super::analysis::dominates_in_idom(a, b, &self.idom)
    }

    /// Get all blocks reachable from entry
    pub fn reachable_blocks(&self) -> HashSet<BlockId> {
        self.rpo.iter().copied().collect()
    }
}

impl LivenessInfo {
    /// Compute liveness information for a MIR function
    pub fn compute(func: &MirFunction, cfg: &CFG) -> Self {
        let analysis_cfg = AnalysisCfg {
            entry: cfg.entry,
            predecessors: cfg.predecessors.clone(),
            successors: cfg.successors.clone(),
            idom: cfg.idom.clone(),
            rpo: cfg.rpo.clone(),
            post_order: cfg.post_order.clone(),
        };
        let block_liveness = BlockLiveness::compute(func, &analysis_cfg);

        let mut info = LivenessInfo {
            live_in: block_liveness.live_in,
            live_out: block_liveness.live_out,
            defs: HashMap::new(),
            uses: HashMap::new(),
        };

        // First pass: collect defs and uses
        for block in &func.blocks {
            for (idx, inst) in block.instructions.iter().enumerate() {
                if let Some(def) = inst.def() {
                    info.defs.entry(def).or_default().push((block.id, idx));
                }
                for use_vreg in inst.uses() {
                    info.uses.entry(use_vreg).or_default().push((block.id, idx));
                }
            }
            // Also check terminator
            let term_idx = block.instructions.len();
            if let Some(def) = block.terminator.def() {
                info.defs.entry(def).or_default().push((block.id, term_idx));
            }
            for use_vreg in block.terminator.uses() {
                info.uses
                    .entry(use_vreg)
                    .or_default()
                    .push((block.id, term_idx));
            }
        }

        info
    }

    /// Check if a virtual register is live at a specific point
    pub fn is_live_at(
        &self,
        vreg: VReg,
        block: BlockId,
        inst_idx: usize,
        func: &MirFunction,
    ) -> bool {
        // A vreg is live at a point if:
        // 1. It's used after this point in the same block, OR
        // 2. It's in live_out of this block

        let blk = func.block(block);

        // Check if used later in this block
        for (idx, inst) in blk.instructions.iter().enumerate() {
            if idx > inst_idx && inst.uses().contains(&vreg) {
                return true;
            }
        }
        // Check terminator
        if blk.terminator.uses().contains(&vreg) {
            return true;
        }

        // Check if in live_out
        self.live_out
            .get(&block)
            .map(|s| s.contains(&vreg))
            .unwrap_or(false)
    }
}

impl LiveInterval {
    /// Check if two intervals overlap
    pub fn overlaps(&self, other: &LiveInterval) -> bool {
        self.start < other.end && other.start < self.end
    }
}

pub fn compute_live_intervals(
    func: &MirFunction,
    cfg: &CFG,
    liveness: &LivenessInfo,
) -> Vec<LiveInterval> {
    // Linearize the program: assign a global index to each instruction
    let mut inst_index: HashMap<(BlockId, usize), usize> = HashMap::new();
    let mut current_idx = 0;

    for &block_id in &cfg.rpo {
        let block = func.block(block_id);
        for i in 0..block.instructions.len() {
            inst_index.insert((block_id, i), current_idx);
            current_idx += 1;
        }
        // Terminator
        inst_index.insert((block_id, block.instructions.len()), current_idx);
        current_idx += 1;
    }

    // Compute intervals for each vreg
    let mut intervals: HashMap<VReg, LiveInterval> = HashMap::new();

    // Process definitions
    for (vreg, defs) in &liveness.defs {
        for &(block, idx) in defs {
            if let Some(&global_idx) = inst_index.get(&(block, idx)) {
                let interval = intervals.entry(*vreg).or_insert_with(|| LiveInterval {
                    vreg: *vreg,
                    start: global_idx,
                    end: global_idx + 1,
                    use_points: Vec::new(),
                });
                interval.start = interval.start.min(global_idx);
                interval.end = interval.end.max(global_idx + 1);
            }
        }
    }

    // Process uses
    for (vreg, uses) in &liveness.uses {
        for &(block, idx) in uses {
            if let Some(&global_idx) = inst_index.get(&(block, idx)) {
                let interval = intervals.entry(*vreg).or_insert_with(|| LiveInterval {
                    vreg: *vreg,
                    start: global_idx,
                    end: global_idx + 1,
                    use_points: Vec::new(),
                });
                interval.start = interval.start.min(global_idx);
                interval.end = interval.end.max(global_idx + 1);
                interval.use_points.push(global_idx);
            }
        }
    }

    // Extend intervals for live-out
    for &block_id in &cfg.rpo {
        if let Some(live_out) = liveness.live_out.get(&block_id) {
            let block = func.block(block_id);
            let term_idx = block.instructions.len();
            if let Some(&global_idx) = inst_index.get(&(block_id, term_idx)) {
                for &vreg in live_out {
                    if let Some(interval) = intervals.get_mut(&vreg) {
                        interval.end = interval.end.max(global_idx + 1);
                    }
                }
            }
        }
    }

    // Sort intervals by start point
    let mut result: Vec<_> = intervals.into_values().collect();
    result.sort_by_key(|i| i.start);
    result
}

impl LoopInfo {
    /// Detect natural loops in the CFG
    pub fn compute(func: &MirFunction, cfg: &CFG) -> Self {
        let analysis_cfg = AnalysisCfg {
            entry: cfg.entry,
            predecessors: cfg.predecessors.clone(),
            successors: cfg.successors.clone(),
            idom: cfg.idom.clone(),
            rpo: cfg.rpo.clone(),
            post_order: cfg.post_order.clone(),
        };
        let generic = GenericLoopInfo::compute(func, &analysis_cfg);
        LoopInfo {
            loops: generic.loops,
            loop_depth: generic.loop_depth,
        }
    }

    /// Check if a block is a loop header
    pub fn is_loop_header(&self, block: BlockId) -> bool {
        self.loops.contains_key(&block)
    }

    /// Get the loop depth of a block
    pub fn depth(&self, block: BlockId) -> usize {
        self.loop_depth.get(&block).copied().unwrap_or(0)
    }
}
