//! Graph Coloring Register Allocator (Chaitin-Briggs with Iterated Register Coalescing)
//!
//! This implements the classic graph coloring algorithm for register allocation,
//! optimized for eBPF's constraints (4 callee-saved registers, 512-byte stack).
//!
//! ## Why Graph Coloring for eBPF
//!
//! Although graph coloring is O(n²), eBPF programs are small (typically <500 vregs),
//! making the cost negligible. The benefits are significant:
//! - Optimal register usage minimizes spills (critical with 512-byte stack limit)
//! - Coalescing eliminates unnecessary moves (reduces instruction count)
//! - Handles irregular constraints naturally (helper call clobbers, precolored regs)
//!
//! ## Algorithm Overview (Appel's Iterated Register Coalescing)
//!
//! 1. **Build**: Construct interference graph from liveness analysis
//! 2. **Simplify**: Remove low-degree non-move-related nodes (push to stack)
//! 3. **Coalesce**: Merge move-related nodes using Briggs/George criteria
//! 4. **Freeze**: Give up coalescing on some move-related node
//! 5. **Spill**: Select high-degree node as potential spill
//! 6. **Select**: Pop from stack and assign colors (registers)
//! 7. **Rewrite**: If actual spills, insert spill code and restart
//!
//! ## References
//!
//! - Chaitin, G. "Register Allocation & Spilling via Graph Coloring" (1982)
//! - Briggs, P. et al. "Improvements to Graph Coloring Register Allocation" (1994)
//! - Appel, A. "Modern Compiler Implementation" Chapter 11

use std::collections::{HashMap, HashSet, VecDeque};

use super::cfg::{CFG, LoopInfo};
use super::instruction::EbpfReg;
use super::lir::{LirBlock, LirFunction, LirInst};
use super::mir::{
    BasicBlock, BlockId, MirFunction, MirInst, MirValue, StackSlot, StackSlotId, StackSlotKind,
    VReg,
};
use super::reg_info;

pub trait RegAllocInst {
    fn defs(&self) -> Vec<VReg>;
    fn uses(&self) -> Vec<VReg>;
    fn move_pairs(&self) -> Vec<(VReg, VReg)>;
    fn call_clobbers(&self) -> &'static [EbpfReg];
    fn scratch_clobbers(&self) -> &'static [EbpfReg];
}

pub trait RegAllocBlock {
    type Inst: RegAllocInst;
    fn id(&self) -> BlockId;
    fn instructions(&self) -> &[Self::Inst];
    fn terminator(&self) -> &Self::Inst;
    fn successors(&self) -> Vec<BlockId>;
}

pub trait RegAllocFunction {
    type Inst: RegAllocInst;
    type Block: RegAllocBlock<Inst = Self::Inst>;
    fn entry(&self) -> BlockId;
    fn blocks(&self) -> &[Self::Block];
    fn block(&self, id: BlockId) -> &Self::Block;
    fn has_block(&self, id: BlockId) -> bool;
    fn vreg_count(&self) -> u32;
    fn param_count(&self) -> usize;
}

#[derive(Debug)]
struct AllocCfg {
    #[allow(dead_code)]
    entry: BlockId,
    predecessors: HashMap<BlockId, Vec<BlockId>>,
    successors: HashMap<BlockId, Vec<BlockId>>,
    rpo: Vec<BlockId>,
    post_order: Vec<BlockId>,
}

impl AllocCfg {
    fn build<F: RegAllocFunction>(func: &F) -> Self {
        let mut cfg = AllocCfg {
            entry: func.entry(),
            predecessors: HashMap::new(),
            successors: HashMap::new(),
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
        cfg
    }

    fn compute_post_order<F: RegAllocFunction>(&mut self, func: &F) {
        let mut visited = HashSet::new();
        let mut post_order = Vec::new();

        fn dfs<F: RegAllocFunction>(
            block_id: BlockId,
            func: &F,
            cfg: &AllocCfg,
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
}

pub(crate) fn compute_loop_depths<F: RegAllocFunction>(func: &F) -> HashMap<BlockId, usize> {
    let cfg = AllocCfg::build(func);
    compute_loop_depths_with_cfg(func, &cfg)
}

fn compute_loop_depths_with_cfg<F: RegAllocFunction>(
    func: &F,
    cfg: &AllocCfg,
) -> HashMap<BlockId, usize> {
    let mut loop_depth: HashMap<BlockId, usize> = HashMap::new();
    for block in func.blocks() {
        loop_depth.insert(block.id(), 0);
    }

    if cfg.rpo.is_empty() {
        return loop_depth;
    }

    let idom = compute_idom(func, cfg);

    let dominates = |a: BlockId, b: BlockId| -> bool {
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
    };

    let mut loops: HashMap<BlockId, HashSet<BlockId>> = HashMap::new();

    for &block_id in &cfg.rpo {
        let succs = cfg.successors.get(&block_id).cloned().unwrap_or_default();
        for succ in succs {
            if dominates(succ, block_id) {
                let mut loop_blocks = HashSet::new();
                loop_blocks.insert(succ);

                let mut worklist = VecDeque::new();
                if block_id != succ {
                    loop_blocks.insert(block_id);
                    worklist.push_back(block_id);
                }

                while let Some(node) = worklist.pop_front() {
                    for &pred in cfg.predecessors.get(&node).unwrap_or(&Vec::new()) {
                        if !loop_blocks.contains(&pred) {
                            loop_blocks.insert(pred);
                            worklist.push_back(pred);
                        }
                    }
                }

                loops.entry(succ).or_default().extend(loop_blocks);
            }
        }
    }

    for blocks in loops.values() {
        for &block in blocks {
            *loop_depth.entry(block).or_insert(0) += 1;
        }
    }

    loop_depth
}

fn compute_idom<F: RegAllocFunction>(func: &F, cfg: &AllocCfg) -> HashMap<BlockId, BlockId> {
    let entry = func.entry();
    let rpo_index: HashMap<BlockId, usize> =
        cfg.rpo.iter().enumerate().map(|(i, &b)| (b, i)).collect();

    let mut doms: HashMap<BlockId, Option<BlockId>> = HashMap::new();
    for block in func.blocks() {
        doms.insert(block.id(), None);
    }
    doms.insert(entry, Some(entry));

    let mut changed = true;
    while changed {
        changed = false;
        for &block_id in &cfg.rpo {
            if block_id == entry {
                continue;
            }

            let preds = cfg.predecessors.get(&block_id).cloned().unwrap_or_default();
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

#[derive(Debug)]
struct AllocLiveness {
    live_in: HashMap<BlockId, HashSet<VReg>>,
    live_out: HashMap<BlockId, HashSet<VReg>>,
}

impl AllocLiveness {
    fn compute<F: RegAllocFunction>(func: &F, cfg: &AllocCfg) -> Self {
        let mut info = AllocLiveness {
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

            for &block_id in cfg.post_order.iter() {
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

                let old_in = info.live_in.get(&block_id).cloned().unwrap_or_default();
                let old_out = info.live_out.get(&block_id).cloned().unwrap_or_default();

                if live_in != old_in || live_out != old_out {
                    changed = true;
                    info.live_in.insert(block_id, live_in);
                    info.live_out.insert(block_id, live_out);
                }
            }
        }

        info
    }
}

impl RegAllocInst for MirInst {
    fn defs(&self) -> Vec<VReg> {
        self.def().into_iter().collect()
    }

    fn uses(&self) -> Vec<VReg> {
        self.uses()
    }

    fn move_pairs(&self) -> Vec<(VReg, VReg)> {
        match self {
            MirInst::Copy {
                dst,
                src: MirValue::VReg(src),
            } => vec![(*dst, *src)],
            _ => Vec::new(),
        }
    }

    fn call_clobbers(&self) -> &'static [EbpfReg] {
        reg_info::call_clobbers(self)
    }

    fn scratch_clobbers(&self) -> &'static [EbpfReg] {
        reg_info::scratch_clobbers(self)
    }
}

impl RegAllocInst for LirInst {
    fn defs(&self) -> Vec<VReg> {
        self.defs()
    }

    fn uses(&self) -> Vec<VReg> {
        self.uses()
    }

    fn move_pairs(&self) -> Vec<(VReg, VReg)> {
        self.move_pairs()
    }

    fn call_clobbers(&self) -> &'static [EbpfReg] {
        self.call_clobbers()
    }

    fn scratch_clobbers(&self) -> &'static [EbpfReg] {
        self.scratch_clobbers()
    }
}

impl RegAllocBlock for BasicBlock {
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

impl RegAllocFunction for MirFunction {
    type Inst = MirInst;
    type Block = super::mir::BasicBlock;

    fn entry(&self) -> BlockId {
        self.entry
    }
    fn blocks(&self) -> &[Self::Block] {
        &self.blocks
    }
    fn block(&self, id: BlockId) -> &Self::Block {
        self.block(id)
    }
    fn has_block(&self, id: BlockId) -> bool {
        self.has_block(id)
    }
    fn vreg_count(&self) -> u32 {
        self.vreg_count
    }
    fn param_count(&self) -> usize {
        self.param_count
    }
}

impl RegAllocBlock for LirBlock {
    type Inst = LirInst;
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

impl RegAllocFunction for LirFunction {
    type Inst = LirInst;
    type Block = LirBlock;

    fn entry(&self) -> BlockId {
        self.entry
    }
    fn blocks(&self) -> &[Self::Block] {
        &self.blocks
    }
    fn block(&self, id: BlockId) -> &Self::Block {
        self.block(id)
    }
    fn has_block(&self, id: BlockId) -> bool {
        self.has_block(id)
    }
    fn vreg_count(&self) -> u32 {
        self.vreg_count
    }
    fn param_count(&self) -> usize {
        self.param_count
    }
}

/// Result of graph coloring register allocation
#[derive(Debug)]
pub struct ColoringResult {
    /// VReg -> physical register assignments
    pub coloring: HashMap<VReg, EbpfReg>,
    /// VReg -> stack slot for spilled registers
    pub spills: HashMap<VReg, StackSlotId>,
    /// Number of coalesced moves (eliminated)
    pub coalesced_moves: usize,
    /// Spill slots that need to be allocated
    pub spill_slots: Vec<StackSlot>,
}

/// A move instruction that may be coalesced
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Move {
    src: VReg,
    dst: VReg,
}

/// Interference graph for register allocation
struct InterferenceGraph {
    /// All virtual registers
    nodes: HashSet<VReg>,
    /// Adjacency sets: node -> set of interfering nodes
    adj_set: HashSet<(VReg, VReg)>,
    /// Adjacency lists for efficient iteration
    adj_list: HashMap<VReg, HashSet<VReg>>,
    /// Current degree of each node
    degree: HashMap<VReg, usize>,
    /// Moves involving each node
    move_list: HashMap<VReg, HashSet<Move>>,
    /// All move instructions
    all_moves: HashSet<Move>,
}

impl InterferenceGraph {
    fn new() -> Self {
        Self {
            nodes: HashSet::new(),
            adj_set: HashSet::new(),
            adj_list: HashMap::new(),
            degree: HashMap::new(),
            move_list: HashMap::new(),
            all_moves: HashSet::new(),
        }
    }

    /// Add a node to the graph
    fn add_node(&mut self, vreg: VReg) {
        if self.nodes.insert(vreg) {
            self.adj_list.entry(vreg).or_default();
            self.degree.entry(vreg).or_insert(0);
        }
    }

    /// Add an interference edge between two nodes
    fn add_edge(&mut self, u: VReg, v: VReg) {
        if u == v {
            return;
        }
        // Use canonical ordering for the set
        let (a, b) = if u.0 < v.0 { (u, v) } else { (v, u) };
        if self.adj_set.insert((a, b)) {
            self.adj_list.entry(u).or_default().insert(v);
            self.adj_list.entry(v).or_default().insert(u);
            *self.degree.entry(u).or_insert(0) += 1;
            *self.degree.entry(v).or_insert(0) += 1;
        }
    }

    /// Check if two nodes interfere
    fn interferes(&self, u: VReg, v: VReg) -> bool {
        let (a, b) = if u.0 < v.0 { (u, v) } else { (v, u) };
        self.adj_set.contains(&(a, b))
    }

    /// Get the degree of a node
    fn degree(&self, vreg: VReg) -> usize {
        self.degree.get(&vreg).copied().unwrap_or(0)
    }

    /// Get adjacent nodes
    fn adjacent(&self, vreg: VReg) -> impl Iterator<Item = VReg> + '_ {
        self.adj_list
            .get(&vreg)
            .into_iter()
            .flat_map(|s| s.iter().copied())
    }

    /// Add a move instruction
    fn add_move(&mut self, src: VReg, dst: VReg) {
        if src == dst {
            return;
        }
        let mv = Move { src, dst };
        self.all_moves.insert(mv);
        self.move_list.entry(src).or_default().insert(mv);
        self.move_list.entry(dst).or_default().insert(mv);
    }

    /// Get moves involving a node
    fn moves_for(&self, vreg: VReg) -> impl Iterator<Item = Move> + '_ {
        self.move_list
            .get(&vreg)
            .into_iter()
            .flat_map(|s| s.iter().copied())
    }
}

/// Worklist state for each node
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeState {
    /// Not yet categorized
    Initial,
    /// Precolored (fixed physical register)
    Precolored,
    /// Low-degree, non-move-related
    Simplify,
    /// Low-degree, move-related
    Freeze,
    /// High-degree
    Spill,
    /// Coalesced into another node
    Coalesced,
    /// On the select stack
    OnStack,
    /// Already colored
    Colored,
}

/// Move state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MoveState {
    /// Not yet processed
    Worklist,
    /// Successfully coalesced
    Coalesced,
    /// Constrained (both ends interfere after coalescing)
    Constrained,
    /// Frozen (gave up coalescing)
    Frozen,
    /// Active (still considering)
    Active,
}

/// The main graph coloring allocator
pub struct GraphColoringAllocator {
    /// Number of available registers (K)
    k: usize,
    /// Available physical registers
    available_regs: Vec<EbpfReg>,
    /// The interference graph
    graph: InterferenceGraph,
    /// State of each node
    node_state: HashMap<VReg, NodeState>,
    /// State of each move
    move_state: HashMap<Move, MoveState>,
    /// Simplify worklist: low-degree non-move-related nodes
    simplify_worklist: VecDeque<VReg>,
    /// Freeze worklist: low-degree move-related nodes
    freeze_worklist: HashSet<VReg>,
    /// Spill worklist: high-degree nodes
    spill_worklist: HashSet<VReg>,
    /// Move worklist: moves to consider for coalescing
    move_worklist: VecDeque<Move>,
    /// Active moves: moves not yet ready for coalescing
    active_moves: HashSet<Move>,
    /// Select stack: nodes removed during simplify, to be colored
    select_stack: Vec<VReg>,
    /// Coalesced nodes: node -> representative
    alias: HashMap<VReg, VReg>,
    /// Final coloring
    color: HashMap<VReg, EbpfReg>,
    /// Spilled nodes
    spilled_nodes: HashSet<VReg>,
    /// Spill cost for each node (uses / degree, adjusted for loops)
    spill_cost: HashMap<VReg, f64>,
    /// Precolored vregs (fixed register assignments)
    precolored: HashMap<VReg, EbpfReg>,
    /// Per-vreg register exclusions derived from clobbers
    forbidden_regs: HashMap<VReg, HashSet<EbpfReg>>,
}

impl GraphColoringAllocator {
    /// Create a new allocator with the given available registers
    pub fn new(available_regs: Vec<EbpfReg>) -> Self {
        let k = available_regs.len();
        Self {
            k,
            available_regs,
            graph: InterferenceGraph::new(),
            node_state: HashMap::new(),
            move_state: HashMap::new(),
            simplify_worklist: VecDeque::new(),
            freeze_worklist: HashSet::new(),
            spill_worklist: HashSet::new(),
            move_worklist: VecDeque::new(),
            active_moves: HashSet::new(),
            select_stack: Vec::new(),
            alias: HashMap::new(),
            color: HashMap::new(),
            spilled_nodes: HashSet::new(),
            spill_cost: HashMap::new(),
            precolored: HashMap::new(),
            forbidden_regs: HashMap::new(),
        }
    }

    /// Set precolored vregs (fixed register assignments)
    pub fn set_precolored(&mut self, precolored: HashMap<VReg, EbpfReg>) {
        self.precolored = precolored;
    }

    /// Run the full allocation algorithm
    pub fn allocate<F: RegAllocFunction>(
        &mut self,
        func: &F,
        loop_depths: Option<&HashMap<BlockId, usize>>,
    ) -> ColoringResult {
        let cfg = AllocCfg::build(func);
        let liveness = AllocLiveness::compute(func, &cfg);

        // Build interference graph
        self.build(func, &cfg, &liveness);

        // Compute spill costs
        self.compute_spill_costs(func, &cfg, loop_depths);

        // Initialize worklists
        self.make_worklist();

        // Main loop: simplify, coalesce, freeze, or select spill
        loop {
            if !self.simplify_worklist.is_empty() {
                self.simplify();
            } else if !self.move_worklist.is_empty() {
                self.coalesce();
            } else if !self.freeze_worklist.is_empty() {
                self.freeze();
            } else if !self.spill_worklist.is_empty() {
                self.select_spill();
            } else {
                break;
            }
        }

        // Assign colors
        self.assign_colors();

        // Count coalesced moves
        let coalesced_moves = self
            .move_state
            .values()
            .filter(|&&s| s == MoveState::Coalesced)
            .count();

        // Build spill slots (reuse slots for non-interfering vregs)
        let (spill_map, spill_slots) = self.build_spill_slots();

        ColoringResult {
            coloring: self.color.clone(),
            spills: spill_map,
            coalesced_moves,
            spill_slots,
        }
    }

    fn build_spill_slots(&self) -> (HashMap<VReg, StackSlotId>, Vec<StackSlot>) {
        if self.spilled_nodes.is_empty() {
            return (HashMap::new(), Vec::new());
        }

        let mut spilled: Vec<VReg> = self.spilled_nodes.iter().copied().collect();
        spilled.sort_by(|a, b| self.graph.degree(*b).cmp(&self.graph.degree(*a)));

        let mut slot_for: HashMap<VReg, u32> = HashMap::new();
        let mut max_slot: u32 = 0;

        for vreg in spilled {
            let mut used: HashSet<u32> = HashSet::new();
            for neighbor in self.graph.adjacent(vreg) {
                if self.spilled_nodes.contains(&neighbor) {
                    if let Some(&slot) = slot_for.get(&neighbor) {
                        used.insert(slot);
                    }
                }
            }
            let mut slot = 0u32;
            while used.contains(&slot) {
                slot += 1;
            }
            slot_for.insert(vreg, slot);
            if slot > max_slot {
                max_slot = slot;
            }
        }

        let mut spill_slots = Vec::new();
        for slot_idx in 0..=max_slot {
            spill_slots.push(StackSlot {
                id: StackSlotId(slot_idx),
                size: 8,
                align: 8,
                kind: StackSlotKind::Spill,
                offset: None,
            });
        }

        let spill_map = slot_for
            .into_iter()
            .map(|(vreg, slot)| (vreg, StackSlotId(slot)))
            .collect();

        (spill_map, spill_slots)
    }

    /// Build the interference graph from liveness information
    fn build<F: RegAllocFunction>(&mut self, func: &F, cfg: &AllocCfg, liveness: &AllocLiveness) {
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
    fn build_interference_from_liveness<F: RegAllocFunction>(
        &mut self,
        func: &F,
        cfg: &AllocCfg,
        liveness: &AllocLiveness,
    ) {
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
    fn add_interference_for_inst<I: RegAllocInst>(&mut self, inst: &I, live: &HashSet<VReg>) {
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

    fn apply_call_clobbers<I: RegAllocInst>(&mut self, inst: &I, live: &HashSet<VReg>) {
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

    fn apply_scratch_clobbers<I: RegAllocInst>(&mut self, inst: &I, live: &HashSet<VReg>) {
        let regs = inst.scratch_clobbers();
        if regs.is_empty() {
            return;
        }
        self.forbid_regs_for_live(live, regs);
    }

    /// Update live set for an instruction (backward)
    fn update_live_for_inst<I: RegAllocInst>(&mut self, inst: &I, live: &mut HashSet<VReg>) {
        for def in inst.defs() {
            live.remove(&def);
        }

        for use_vreg in inst.uses() {
            live.insert(use_vreg);
        }
    }

    /// Process instruction for liveness (used during initial build)
    fn process_instruction_liveness<I: RegAllocInst>(
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
    fn compute_spill_costs<F: RegAllocFunction>(
        &mut self,
        func: &F,
        cfg: &AllocCfg,
        loop_depths: Option<&HashMap<BlockId, usize>>,
    ) {
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

    /// Initialize worklists based on node degree and move-relatedness
    fn make_worklist(&mut self) {
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

    fn is_precolored(&self, vreg: VReg) -> bool {
        matches!(self.node_state.get(&vreg), Some(NodeState::Precolored))
    }

    fn is_forbidden(&self, vreg: VReg, reg: EbpfReg) -> bool {
        self.forbidden_regs
            .get(&vreg)
            .map(|set| set.contains(&reg))
            .unwrap_or(false)
    }

    fn effective_k(&self, vreg: VReg) -> usize {
        if self.is_precolored(vreg) {
            return 1;
        }
        self.available_regs
            .iter()
            .filter(|reg| !self.is_forbidden(vreg, **reg))
            .count()
    }

    fn forbid_regs_for_live(&mut self, live: &HashSet<VReg>, regs: &[EbpfReg]) {
        if regs.is_empty() {
            return;
        }
        for vreg in live {
            let entry = self.forbidden_regs.entry(*vreg).or_default();
            entry.extend(regs.iter().copied());
        }
    }

    /// Check if a node is involved in any active move
    fn is_move_related(&self, vreg: VReg) -> bool {
        for mv in self.graph.moves_for(vreg) {
            match self.move_state.get(&mv) {
                Some(MoveState::Worklist) | Some(MoveState::Active) | None => return true,
                _ => {}
            }
        }
        false
    }

    /// Get active moves for a node
    fn node_moves(&self, vreg: VReg) -> Vec<Move> {
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
    fn simplify(&mut self) {
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
    fn decrement_degree(&mut self, vreg: VReg) {
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
    fn enable_moves(&mut self, vreg: VReg) {
        for mv in self.node_moves(vreg) {
            if self.move_state.get(&mv) == Some(&MoveState::Active) {
                self.active_moves.remove(&mv);
                self.move_worklist.push_back(mv);
                self.move_state.insert(mv, MoveState::Worklist);
            }
        }
    }

    /// Coalesce: attempt to merge move-related nodes
    fn coalesce(&mut self) {
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
    fn can_coalesce(&self, u: VReg, v: VReg) -> bool {
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
    fn george(&self, u: VReg, v: VReg) -> bool {
        for t in self.graph.adjacent(v) {
            if self.graph.degree(t) >= self.k && !self.graph.interferes(t, u) {
                return false;
            }
        }
        true
    }

    /// Add node to simplify worklist if appropriate
    fn add_worklist(&mut self, vreg: VReg) {
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
    fn combine(&mut self, u: VReg, v: VReg) {
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
    fn get_alias(&self, vreg: VReg) -> VReg {
        if self.node_state.get(&vreg) == Some(&NodeState::Coalesced) {
            if let Some(&alias) = self.alias.get(&vreg) {
                return self.get_alias(alias);
            }
        }
        vreg
    }

    /// Freeze: give up coalescing on a move-related node
    fn freeze(&mut self) {
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
    fn freeze_moves(&mut self, vreg: VReg) {
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
    fn select_spill(&mut self) {
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
    fn assign_colors(&mut self) {
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

/// Convenience function to perform graph coloring allocation
pub fn allocate_registers(func: &MirFunction, available_regs: Vec<EbpfReg>) -> ColoringResult {
    let cfg = CFG::build(func);
    let loop_info = LoopInfo::compute(func, &cfg);
    let mut allocator = GraphColoringAllocator::new(available_regs);
    allocator.allocate(func, Some(&loop_info.loop_depth))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::mir::{BinOpKind, MirInst, MirValue, StackSlotKind, StringAppendType};

    fn make_simple_function() -> MirFunction {
        // v0 = 1
        // v1 = 2
        // v2 = v0 + v1
        // return v2
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::Const(2),
        });
        func.block_mut(bb0).instructions.push(MirInst::BinOp {
            dst: v2,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::VReg(v1),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v2)),
        };

        func
    }

    fn make_coalesce_function() -> MirFunction {
        // v0 = 1
        // v1 = v0  <-- this move should be coalesced
        // return v1
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::VReg(v0),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v1)),
        };

        func
    }

    fn make_pressure_function() -> MirFunction {
        // v0 = 1
        // v1 = 2
        // v2 = 3
        // v3 = 4
        // v4 = v0 + v1
        // v5 = v2 + v3
        // v6 = v4 + v5
        // return v6
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();
        let v3 = func.alloc_vreg();
        let v4 = func.alloc_vreg();
        let v5 = func.alloc_vreg();
        let v6 = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::Const(2),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v2,
            src: MirValue::Const(3),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v3,
            src: MirValue::Const(4),
        });
        func.block_mut(bb0).instructions.push(MirInst::BinOp {
            dst: v4,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::VReg(v1),
        });
        func.block_mut(bb0).instructions.push(MirInst::BinOp {
            dst: v5,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v2),
            rhs: MirValue::VReg(v3),
        });
        func.block_mut(bb0).instructions.push(MirInst::BinOp {
            dst: v6,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v4),
            rhs: MirValue::VReg(v5),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v6)),
        };

        func
    }

    #[test]
    fn test_simple_allocation() {
        let func = make_simple_function();
        let available = vec![EbpfReg::R6, EbpfReg::R7, EbpfReg::R8];

        let result = allocate_registers(&func, available);

        // All vregs should be colored, no spills
        assert_eq!(result.coloring.len(), 3);
        assert!(result.spills.is_empty());
    }

    #[test]
    fn test_coalescing() {
        let func = make_coalesce_function();
        let available = vec![EbpfReg::R6, EbpfReg::R7, EbpfReg::R8];

        let result = allocate_registers(&func, available);

        // Should coalesce v0 and v1 to the same register
        assert!(
            result.coalesced_moves > 0,
            "Should have coalesced at least one move"
        );

        // v0 and v1 should have the same color
        let v0_color = result.coloring.get(&VReg(0));
        let v1_color = result.coloring.get(&VReg(1));
        assert_eq!(v0_color, v1_color, "Coalesced nodes should have same color");
    }

    #[test]
    fn test_register_pressure() {
        let func = make_pressure_function();
        // Only 3 registers for 7 virtual registers
        let available = vec![EbpfReg::R6, EbpfReg::R7, EbpfReg::R8];

        let result = allocate_registers(&func, available);

        // With good allocation, we might need some spills
        let total = result.coloring.len() + result.spills.len();
        assert!(total > 0, "Should have some allocations");

        // Verify no two simultaneously live vregs share the same register
        // (This would require checking against live intervals)
    }

    #[test]
    fn test_register_pressure_allocation_stable() {
        let func = make_pressure_function();
        let available = vec![EbpfReg::R6, EbpfReg::R7, EbpfReg::R8];

        let mut baseline: Option<(Vec<(u32, EbpfReg)>, Vec<u32>, usize)> = None;

        for _ in 0..8 {
            let result = allocate_registers(&func, available.clone());
            let mut coloring: Vec<(u32, EbpfReg)> = result
                .coloring
                .iter()
                .map(|(vreg, reg)| (vreg.0, *reg))
                .collect();
            coloring.sort_by_key(|(vreg, _)| *vreg);

            let mut spills: Vec<u32> = result.spills.keys().map(|vreg| vreg.0).collect();
            spills.sort_unstable();

            let signature = (coloring, spills, result.coalesced_moves);
            if let Some(expected) = &baseline {
                assert_eq!(
                    &signature, expected,
                    "register allocation result should be stable across runs"
                );
            } else {
                baseline = Some(signature);
            }
        }
    }

    #[test]
    fn test_empty_function() {
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;
        func.block_mut(bb0).terminator = MirInst::Return { val: None };

        let result = allocate_registers(&func, vec![EbpfReg::R6, EbpfReg::R7, EbpfReg::R8]);

        assert!(result.coloring.is_empty());
        assert!(result.spills.is_empty());
    }

    #[test]
    fn test_interference_detection() {
        // v0 = 1
        // v1 = 2
        // v2 = v0 + v1  <-- v0 and v1 are both live here, so they interfere
        // return v2
        let func = make_simple_function();
        let cfg = AllocCfg::build(&func);
        let liveness = AllocLiveness::compute(&func, &cfg);
        let mut allocator = GraphColoringAllocator::new(vec![EbpfReg::R6, EbpfReg::R7]);
        allocator.build(&func, &cfg, &liveness);

        // v0 and v1 should interfere (both live at the BinOp)
        assert!(
            allocator.graph.interferes(VReg(0), VReg(1)),
            "v0 and v1 should interfere"
        );
    }

    fn make_list_function() -> MirFunction {
        use crate::compiler::mir::StackSlotKind;
        // v0 = ListNew (list pointer)
        // v1 = 1
        // ListPush(v0, v1)
        // v2 = 2
        // ListPush(v0, v2)
        // EmitEvent(v0)
        // return
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg(); // list ptr
        let v1 = func.alloc_vreg(); // item 1
        let v2 = func.alloc_vreg(); // item 2

        // Allocate stack slot for list buffer
        let slot = func.alloc_stack_slot(32, 8, StackSlotKind::ListBuffer);

        func.block_mut(bb0).instructions.push(MirInst::ListNew {
            dst: v0,
            buffer: slot,
            max_len: 3,
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0)
            .instructions
            .push(MirInst::ListPush { list: v0, item: v1 });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v2,
            src: MirValue::Const(2),
        });
        func.block_mut(bb0)
            .instructions
            .push(MirInst::ListPush { list: v0, item: v2 });
        func.block_mut(bb0)
            .instructions
            .push(MirInst::EmitEvent { data: v0, size: 24 });
        func.block_mut(bb0).terminator = MirInst::Return { val: None };

        func
    }

    fn make_string_append_int_function() -> MirFunction {
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let slot = func.alloc_stack_slot(32, 8, StackSlotKind::StringBuffer);
        let len = func.alloc_vreg();
        let val = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: len,
            src: MirValue::Const(0),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: val,
            src: MirValue::Const(42),
        });
        func.block_mut(bb0)
            .instructions
            .push(MirInst::StringAppend {
                dst_buffer: slot,
                dst_len: len,
                val: MirValue::VReg(val),
                val_type: StringAppendType::Integer,
            });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(val)),
        };

        func
    }

    fn make_helper_call_clobber_function() -> MirFunction {
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let v_keep = func.alloc_vreg();
        let v_ret = func.alloc_vreg();
        let v_out = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v_keep,
            src: MirValue::Const(7),
        });
        func.block_mut(bb0).instructions.push(MirInst::CallHelper {
            dst: v_ret,
            helper: 14, // bpf_get_current_pid_tgid
            args: vec![],
        });
        func.block_mut(bb0).instructions.push(MirInst::BinOp {
            dst: v_out,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v_keep),
            rhs: MirValue::VReg(v_ret),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v_out)),
        };

        func
    }

    fn make_subfn_call_clobber_function() -> MirFunction {
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let v_keep = func.alloc_vreg();
        let v_arg = func.alloc_vreg();
        let v_ret = func.alloc_vreg();
        let v_out = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v_keep,
            src: MirValue::Const(11),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v_arg,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).instructions.push(MirInst::CallSubfn {
            dst: v_ret,
            subfn: crate::compiler::mir::SubfunctionId(0),
            args: vec![v_arg],
        });
        func.block_mut(bb0).instructions.push(MirInst::BinOp {
            dst: v_out,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v_keep),
            rhs: MirValue::VReg(v_ret),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v_out)),
        };

        func
    }

    #[test]
    fn test_list_register_allocation() {
        let func = make_list_function();
        let available = vec![EbpfReg::R6, EbpfReg::R7, EbpfReg::R8];

        let result = allocate_registers(&func, available);

        // All vregs should be colored (no spills needed for this simple case)
        assert_eq!(result.coloring.len(), 3, "Should color all 3 vregs");
        assert!(result.spills.is_empty(), "Should have no spills");

        // v0 (list ptr) must have a register since it's used across multiple instructions
        assert!(
            result.coloring.contains_key(&VReg(0)),
            "List pointer vreg v0 must be colored"
        );

        // Print the coloring for debugging
        eprintln!("List register allocation:");
        for (vreg, reg) in &result.coloring {
            eprintln!("  {} -> {:?}", vreg, reg);
        }
    }

    #[test]
    fn test_list_push_clobber_constraints() {
        let func = make_list_function();
        let available = vec![
            EbpfReg::R1,
            EbpfReg::R2,
            EbpfReg::R3,
            EbpfReg::R4,
            EbpfReg::R5,
            EbpfReg::R6,
        ];

        let result = allocate_registers(&func, available);

        let v0_reg = result
            .coloring
            .get(&VReg(0))
            .copied()
            .expect("v0 should be colored");

        assert!(
            v0_reg != EbpfReg::R1 && v0_reg != EbpfReg::R2,
            "List pointer should avoid R1/R2 due to ListPush scratch usage, got {:?}",
            v0_reg
        );
    }

    #[test]
    fn test_list_interference() {
        let func = make_list_function();
        let cfg = AllocCfg::build(&func);
        let liveness = AllocLiveness::compute(&func, &cfg);
        let mut allocator =
            GraphColoringAllocator::new(vec![EbpfReg::R6, EbpfReg::R7, EbpfReg::R8]);
        allocator.build(&func, &cfg, &liveness);

        // v0 should be in the graph (defined by ListNew)
        assert!(
            allocator.graph.nodes.contains(&VReg(0)),
            "v0 (list ptr from ListNew) should be in graph"
        );

        // v0 and v1 should interfere (v0 is live when v1 is used in ListPush)
        assert!(
            allocator.graph.interferes(VReg(0), VReg(1)),
            "v0 (list) and v1 (item) should interfere"
        );
    }

    #[test]
    fn test_string_append_int_clobber_constraints() {
        let func = make_string_append_int_function();
        let available = vec![
            EbpfReg::R1,
            EbpfReg::R2,
            EbpfReg::R3,
            EbpfReg::R4,
            EbpfReg::R5,
            EbpfReg::R6,
            EbpfReg::R7,
            EbpfReg::R8,
        ];

        let result = allocate_registers(&func, available);
        let val_reg = result
            .coloring
            .get(&VReg(1))
            .copied()
            .expect("val vreg should be colored");

        assert!(
            !matches!(
                val_reg,
                EbpfReg::R1 | EbpfReg::R2 | EbpfReg::R3 | EbpfReg::R4 | EbpfReg::R5
            ),
            "StringAppend integer source should avoid R1-R5 scratch regs, got {:?}",
            val_reg
        );
    }

    #[test]
    fn test_helper_call_clobber_constraints() {
        let func = make_helper_call_clobber_function();
        let available = vec![
            EbpfReg::R1,
            EbpfReg::R2,
            EbpfReg::R3,
            EbpfReg::R4,
            EbpfReg::R5,
            EbpfReg::R6,
        ];

        let result = allocate_registers(&func, available);
        let keep_reg = result
            .coloring
            .get(&VReg(0))
            .copied()
            .expect("value live across helper call should be colored");

        assert!(
            !matches!(
                keep_reg,
                EbpfReg::R1 | EbpfReg::R2 | EbpfReg::R3 | EbpfReg::R4 | EbpfReg::R5
            ),
            "value live across helper call should avoid R1-R5, got {:?}",
            keep_reg
        );
    }

    #[test]
    fn test_subfn_call_clobber_constraints() {
        let func = make_subfn_call_clobber_function();
        let available = vec![
            EbpfReg::R1,
            EbpfReg::R2,
            EbpfReg::R3,
            EbpfReg::R4,
            EbpfReg::R5,
            EbpfReg::R6,
        ];

        let result = allocate_registers(&func, available);
        let keep_reg = result
            .coloring
            .get(&VReg(0))
            .copied()
            .expect("value live across subfn call should be colored");

        assert!(
            !matches!(
                keep_reg,
                EbpfReg::R1 | EbpfReg::R2 | EbpfReg::R3 | EbpfReg::R4 | EbpfReg::R5
            ),
            "value live across subfn call should avoid R1-R5, got {:?}",
            keep_reg
        );
    }

    #[test]
    fn test_lir_loop_depths() {
        use crate::compiler::lir::{LirFunction, LirInst};

        let mut func = LirFunction::new();
        let entry = func.alloc_block();
        let header = func.alloc_block();
        let body = func.alloc_block();
        let exit = func.alloc_block();
        func.entry = entry;

        let counter = func.alloc_vreg();

        func.block_mut(entry).terminator = LirInst::Jump { target: header };
        func.block_mut(header).terminator = LirInst::LoopHeader {
            counter,
            limit: 10,
            body,
            exit,
        };
        func.block_mut(body).terminator = LirInst::LoopBack {
            counter,
            step: 1,
            header,
        };
        func.block_mut(exit).terminator = LirInst::Return { val: None };

        let depths = compute_loop_depths(&func);
        assert_eq!(depths.get(&entry).copied().unwrap_or(0), 0);
        assert_eq!(depths.get(&header).copied().unwrap_or(0), 1);
        assert_eq!(depths.get(&body).copied().unwrap_or(0), 1);
        assert_eq!(depths.get(&exit).copied().unwrap_or(0), 0);
    }
}
