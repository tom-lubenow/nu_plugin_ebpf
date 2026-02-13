//! Control Flow Graph construction and analysis
//!
//! This module builds a CFG from MIR and provides analysis capabilities:
//! - Predecessor/successor relationships
//! - Dominator tree
//! - Liveness analysis for register allocation
//! - Loop detection

use std::collections::{HashMap, HashSet, VecDeque};

use super::mir::{BasicBlock, BlockId, MirFunction, MirInst, VReg};

/// Instruction adapter for generic CFG/liveness analysis.
pub trait CfgInst {
    fn defs(&self) -> Vec<VReg>;
    fn uses(&self) -> Vec<VReg>;
}

/// Basic block adapter for generic CFG/liveness analysis.
pub trait CfgBlock {
    type Inst: CfgInst;
    fn id(&self) -> BlockId;
    fn instructions(&self) -> &[Self::Inst];
    fn terminator(&self) -> &Self::Inst;
    fn successors(&self) -> Vec<BlockId>;
}

/// Function adapter for generic CFG/liveness analysis.
pub trait CfgFunction {
    type Inst: CfgInst;
    type Block: CfgBlock<Inst = Self::Inst>;
    fn entry(&self) -> BlockId;
    fn blocks(&self) -> &[Self::Block];
    fn block(&self, id: BlockId) -> &Self::Block;
    fn has_block(&self, id: BlockId) -> bool;
}

impl CfgInst for MirInst {
    fn defs(&self) -> Vec<VReg> {
        self.def().into_iter().collect()
    }

    fn uses(&self) -> Vec<VReg> {
        self.uses()
    }
}

impl CfgBlock for BasicBlock {
    type Inst = MirInst;

    fn id(&self) -> BlockId {
        self.id
    }

    fn instructions(&self) -> &[Self::Inst] {
        &self.instructions
    }

    fn terminator(&self) -> &Self::Inst {
        &self.terminator
    }

    fn successors(&self) -> Vec<BlockId> {
        self.successors()
    }
}

impl CfgFunction for MirFunction {
    type Inst = MirInst;
    type Block = BasicBlock;

    fn entry(&self) -> BlockId {
        self.entry
    }

    fn blocks(&self) -> &[Self::Block] {
        &self.blocks
    }

    fn block(&self, id: BlockId) -> &Self::Block {
        MirFunction::block(self, id)
    }

    fn has_block(&self, id: BlockId) -> bool {
        MirFunction::has_block(self, id)
    }
}

#[derive(Debug, Clone)]
pub struct AnalysisCfg {
    pub entry: BlockId,
    pub predecessors: HashMap<BlockId, Vec<BlockId>>,
    pub successors: HashMap<BlockId, Vec<BlockId>>,
    pub idom: HashMap<BlockId, BlockId>,
    pub rpo: Vec<BlockId>,
    pub post_order: Vec<BlockId>,
}

impl AnalysisCfg {
    pub fn build<F: CfgFunction>(func: &F) -> Self {
        let mut cfg = AnalysisCfg {
            entry: func.entry(),
            predecessors: HashMap::new(),
            successors: HashMap::new(),
            idom: HashMap::new(),
            rpo: Vec::new(),
            post_order: Vec::new(),
        };

        for block in func.blocks() {
            cfg.predecessors.insert(block.id(), Vec::new());
            cfg.successors.insert(block.id(), Vec::new());
        }

        for block in func.blocks() {
            let succs = block.successors();
            cfg.successors.insert(block.id(), succs.clone());
            for succ in succs {
                cfg.predecessors.entry(succ).or_default().push(block.id());
            }
        }

        cfg.compute_post_order(func);
        cfg.compute_dominators(func);
        cfg
    }

    fn compute_post_order<F: CfgFunction>(&mut self, func: &F) {
        let mut visited = HashSet::new();
        let mut post_order = Vec::new();

        fn dfs<F: CfgFunction>(
            block_id: BlockId,
            func: &F,
            cfg: &AnalysisCfg,
            visited: &mut HashSet<BlockId>,
            post_order: &mut Vec<BlockId>,
        ) {
            if visited.contains(&block_id) {
                return;
            }
            visited.insert(block_id);

            if let Some(succs) = cfg.successors.get(&block_id) {
                for &succ in succs {
                    if func.has_block(succ) {
                        dfs(succ, func, cfg, visited, post_order);
                    }
                }
            }

            post_order.push(block_id);
        }

        dfs(func.entry(), func, self, &mut visited, &mut post_order);
        self.post_order = post_order.clone();
        self.rpo = post_order.into_iter().rev().collect();
    }

    fn compute_dominators<F: CfgFunction>(&mut self, func: &F) {
        if func.blocks().is_empty() {
            return;
        }

        self.idom = compute_idom(func.entry(), func.blocks(), &self.predecessors, &self.rpo);
    }

    pub fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        dominates_in_idom(a, b, &self.idom)
    }
}

#[derive(Debug, Clone)]
pub struct BlockLiveness {
    pub live_in: HashMap<BlockId, HashSet<VReg>>,
    pub live_out: HashMap<BlockId, HashSet<VReg>>,
}

impl BlockLiveness {
    pub fn compute<F: CfgFunction>(func: &F, cfg: &AnalysisCfg) -> Self {
        let mut info = BlockLiveness {
            live_in: HashMap::new(),
            live_out: HashMap::new(),
        };

        for block in func.blocks() {
            info.live_in.insert(block.id(), HashSet::new());
            info.live_out.insert(block.id(), HashSet::new());
        }

        let mut changed = true;
        while changed {
            changed = false;

            for &block_id in &cfg.post_order {
                let block = func.block(block_id);

                let mut live_out = HashSet::new();
                for succ_id in block.successors() {
                    if let Some(succ_live_in) = info.live_in.get(&succ_id) {
                        live_out.extend(succ_live_in);
                    }
                }

                let mut live_in = live_out.clone();

                for def in block.terminator().defs() {
                    live_in.remove(&def);
                }
                for use_vreg in block.terminator().uses() {
                    live_in.insert(use_vreg);
                }

                for inst in block.instructions().iter().rev() {
                    for def in inst.defs() {
                        live_in.remove(&def);
                    }
                    for use_vreg in inst.uses() {
                        live_in.insert(use_vreg);
                    }
                }

                let old_live_in = info.live_in.get(&block_id).cloned().unwrap_or_default();
                let old_live_out = info.live_out.get(&block_id).cloned().unwrap_or_default();

                if live_in != old_live_in || live_out != old_live_out {
                    changed = true;
                    info.live_in.insert(block_id, live_in);
                    info.live_out.insert(block_id, live_out);
                }
            }
        }

        info
    }
}

#[derive(Debug, Clone)]
pub struct GenericLoopInfo {
    pub loops: HashMap<BlockId, HashSet<BlockId>>,
    pub loop_depth: HashMap<BlockId, usize>,
}

impl GenericLoopInfo {
    pub fn compute<F: CfgFunction>(func: &F, cfg: &AnalysisCfg) -> Self {
        let mut info = GenericLoopInfo {
            loops: HashMap::new(),
            loop_depth: HashMap::new(),
        };

        for block in func.blocks() {
            info.loop_depth.insert(block.id(), 0);
        }

        let mut back_edges: Vec<(BlockId, BlockId)> = Vec::new();
        for block in func.blocks() {
            for &succ in cfg.successors.get(&block.id()).unwrap_or(&Vec::new()) {
                if cfg.dominates(succ, block.id()) {
                    back_edges.push((block.id(), succ));
                }
            }
        }

        for (tail, header) in back_edges {
            let mut loop_blocks = HashSet::new();
            loop_blocks.insert(header);

            let mut worklist = VecDeque::new();
            if tail != header {
                loop_blocks.insert(tail);
                worklist.push_back(tail);
            }

            while let Some(block) = worklist.pop_front() {
                for &pred in cfg.predecessors.get(&block).unwrap_or(&Vec::new()) {
                    if !loop_blocks.contains(&pred) {
                        loop_blocks.insert(pred);
                        worklist.push_back(pred);
                    }
                }
            }

            info.loops.entry(header).or_default().extend(loop_blocks);
        }

        for blocks in info.loops.values() {
            for &block in blocks {
                *info.loop_depth.entry(block).or_insert(0) += 1;
            }
        }

        info
    }
}

fn compute_idom<B>(
    entry: BlockId,
    blocks: &[B],
    predecessors: &HashMap<BlockId, Vec<BlockId>>,
    rpo: &[BlockId],
) -> HashMap<BlockId, BlockId>
where
    B: CfgBlock,
{
    let rpo_index: HashMap<BlockId, usize> = rpo.iter().enumerate().map(|(i, &b)| (b, i)).collect();

    let mut doms: HashMap<BlockId, Option<BlockId>> = HashMap::new();
    for block in blocks {
        doms.insert(block.id(), None);
    }
    doms.insert(entry, Some(entry));

    let mut changed = true;
    while changed {
        changed = false;

        for &block_id in rpo {
            if block_id == entry {
                continue;
            }

            let preds = predecessors.get(&block_id).cloned().unwrap_or_default();
            let mut new_idom = None;

            for &pred in &preds {
                if doms.get(&pred).and_then(|d| *d).is_some() {
                    new_idom = Some(pred);
                    break;
                }
            }

            if let Some(mut idom) = new_idom {
                for &pred in &preds {
                    if pred == idom {
                        continue;
                    }
                    if doms.get(&pred).and_then(|d| *d).is_some() {
                        idom = intersect(pred, idom, &doms, &rpo_index);
                    }
                }

                if doms.get(&block_id).and_then(|d| *d) != Some(idom) {
                    doms.insert(block_id, Some(idom));
                    changed = true;
                }
            }
        }
    }

    let mut idom = HashMap::new();
    for (block_id, dom) in doms {
        if let Some(parent) = dom
            && block_id != parent
        {
            idom.insert(block_id, parent);
        }
    }
    idom
}

fn intersect(
    b1: BlockId,
    b2: BlockId,
    doms: &HashMap<BlockId, Option<BlockId>>,
    rpo_index: &HashMap<BlockId, usize>,
) -> BlockId {
    let get_idx = |b: BlockId| rpo_index.get(&b).copied().unwrap_or(usize::MAX);

    let mut finger1 = b1;
    let mut finger2 = b2;

    while finger1 != finger2 {
        while get_idx(finger1) > get_idx(finger2) {
            match doms.get(&finger1).and_then(|d| *d) {
                Some(dom) if dom != finger1 => finger1 = dom,
                _ => return finger2,
            }
        }
        while get_idx(finger2) > get_idx(finger1) {
            match doms.get(&finger2).and_then(|d| *d) {
                Some(dom) if dom != finger2 => finger2 = dom,
                _ => return finger1,
            }
        }
    }
    finger1
}

fn dominates_in_idom(a: BlockId, b: BlockId, idom: &HashMap<BlockId, BlockId>) -> bool {
    if a == b {
        return true;
    }
    let mut current = b;
    while let Some(&dom) = idom.get(&current) {
        if dom == a {
            return true;
        }
        if dom == current {
            break;
        }
        current = dom;
    }
    false
}

/// Control Flow Graph built from MIR
#[derive(Debug)]
pub struct CFG {
    /// Entry block
    pub entry: BlockId,
    /// Predecessors for each block
    pub predecessors: HashMap<BlockId, Vec<BlockId>>,
    /// Successors for each block (computed from terminators)
    pub successors: HashMap<BlockId, Vec<BlockId>>,
    /// Immediate dominator for each block
    pub idom: HashMap<BlockId, BlockId>,
    /// Reverse post-order traversal (for dataflow analysis)
    pub rpo: Vec<BlockId>,
    /// Post-order traversal
    pub post_order: Vec<BlockId>,
    /// Dominance frontiers for each block (used in SSA construction)
    pub dominance_frontiers: HashMap<BlockId, HashSet<BlockId>>,
}

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
        dominates_in_idom(a, b, &self.idom)
    }

    /// Get all blocks reachable from entry
    pub fn reachable_blocks(&self) -> HashSet<BlockId> {
        self.rpo.iter().copied().collect()
    }
}

/// Liveness analysis results
#[derive(Debug)]
pub struct LivenessInfo {
    /// Virtual registers live at the start of each block
    pub live_in: HashMap<BlockId, HashSet<VReg>>,
    /// Virtual registers live at the end of each block
    pub live_out: HashMap<BlockId, HashSet<VReg>>,
    /// Def-use chains: for each vreg, list of (block, instruction index) where it's defined/used
    pub defs: HashMap<VReg, Vec<(BlockId, usize)>>,
    pub uses: HashMap<VReg, Vec<(BlockId, usize)>>,
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

/// Live interval for a virtual register (used in register allocation)
#[derive(Debug, Clone)]
pub struct LiveInterval {
    pub vreg: VReg,
    /// Start point (instruction index in linearized program)
    pub start: usize,
    /// End point (instruction index in linearized program)
    pub end: usize,
    /// All use points
    pub use_points: Vec<usize>,
}

impl LiveInterval {
    /// Check if two intervals overlap
    pub fn overlaps(&self, other: &LiveInterval) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Compute live intervals from liveness info (for linear scan register allocation)
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

/// Loop information
#[derive(Debug)]
pub struct LoopInfo {
    /// Natural loops: header -> set of blocks in loop
    pub loops: HashMap<BlockId, HashSet<BlockId>>,
    /// Loop depth for each block (0 = not in a loop)
    pub loop_depth: HashMap<BlockId, usize>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::mir::{MirInst, MirValue};

    fn make_test_function() -> MirFunction {
        // Create a simple function:
        // bb0: v0 = 1; if v0 goto bb1 else bb2
        // bb1: v1 = v0 + 1; goto bb3
        // bb2: v1 = v0 - 1; goto bb3
        // bb3: return v1

        let mut func = MirFunction::new();

        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        let bb3 = func.alloc_block();

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        // bb0
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).terminator = MirInst::Branch {
            cond: v0,
            if_true: bb1,
            if_false: bb2,
        };

        // bb1
        func.block_mut(bb1).instructions.push(MirInst::BinOp {
            dst: v1,
            op: super::super::mir::BinOpKind::Add,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::Const(1),
        });
        func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

        // bb2
        func.block_mut(bb2).instructions.push(MirInst::BinOp {
            dst: v1,
            op: super::super::mir::BinOpKind::Sub,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::Const(1),
        });
        func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

        // bb3
        func.block_mut(bb3).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v1)),
        };

        func
    }

    #[test]
    fn test_cfg_construction() {
        let func = make_test_function();
        let cfg = CFG::build(&func);

        // Check successors
        assert_eq!(cfg.successors.get(&BlockId(0)).unwrap().len(), 2);
        assert_eq!(cfg.successors.get(&BlockId(1)).unwrap(), &vec![BlockId(3)]);
        assert_eq!(cfg.successors.get(&BlockId(2)).unwrap(), &vec![BlockId(3)]);
        assert!(cfg.successors.get(&BlockId(3)).unwrap().is_empty());

        // Check predecessors
        assert!(cfg.predecessors.get(&BlockId(0)).unwrap().is_empty());
        assert_eq!(cfg.predecessors.get(&BlockId(3)).unwrap().len(), 2);
    }

    #[test]
    fn test_dominators() {
        let func = make_test_function();
        let cfg = CFG::build(&func);

        // bb0 dominates everything
        assert!(cfg.dominates(BlockId(0), BlockId(0)));
        assert!(cfg.dominates(BlockId(0), BlockId(1)));
        assert!(cfg.dominates(BlockId(0), BlockId(2)));
        assert!(cfg.dominates(BlockId(0), BlockId(3)));

        // bb1 and bb2 don't dominate bb3 (both paths lead to bb3)
        assert!(!cfg.dominates(BlockId(1), BlockId(3)));
        assert!(!cfg.dominates(BlockId(2), BlockId(3)));
    }

    #[test]
    fn test_dominance_frontiers() {
        let func = make_test_function();
        let cfg = CFG::build(&func);

        // In a diamond CFG (bb0 branches to bb1/bb2, both jump to bb3):
        // - DF(bb0) = {} (entry dominates everything)
        // - DF(bb1) = {bb3} (bb1 dominates itself, but at bb3 control can come from bb2)
        // - DF(bb2) = {bb3} (bb2 dominates itself, but at bb3 control can come from bb1)
        // - DF(bb3) = {} (bb3 has no successors)

        assert!(cfg.dominance_frontier(BlockId(0)).is_empty());
        assert!(cfg.dominance_frontier(BlockId(1)).contains(&BlockId(3)));
        assert!(cfg.dominance_frontier(BlockId(2)).contains(&BlockId(3)));
        assert!(cfg.dominance_frontier(BlockId(3)).is_empty());
    }

    #[test]
    fn test_liveness_analysis() {
        let func = make_test_function();
        let cfg = CFG::build(&func);
        let liveness = LivenessInfo::compute(&func, &cfg);

        // v0 should be live in bb1 and bb2 (used there)
        assert!(
            liveness
                .live_in
                .get(&BlockId(1))
                .unwrap()
                .contains(&VReg(0))
        );
        assert!(
            liveness
                .live_in
                .get(&BlockId(2))
                .unwrap()
                .contains(&VReg(0))
        );

        // v1 should be live in bb3 (used in return)
        assert!(
            liveness
                .live_in
                .get(&BlockId(3))
                .unwrap()
                .contains(&VReg(1))
        );
    }

    #[test]
    fn test_live_intervals() {
        let func = make_test_function();
        let cfg = CFG::build(&func);
        let liveness = LivenessInfo::compute(&func, &cfg);
        let intervals = compute_live_intervals(&func, &cfg, &liveness);

        // Should have intervals for v0 and v1
        assert_eq!(intervals.len(), 2);

        // v0 should start before v1
        let v0_interval = intervals.iter().find(|i| i.vreg.0 == 0).unwrap();
        let v1_interval = intervals.iter().find(|i| i.vreg.0 == 1).unwrap();
        assert!(v0_interval.start <= v1_interval.start);
    }
}
