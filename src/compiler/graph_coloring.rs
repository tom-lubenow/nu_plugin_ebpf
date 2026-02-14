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

use super::cfg::{
    AnalysisCfg, BlockLiveness, CFG, CfgBlock, CfgFunction, CfgInst, GenericLoopInfo, LoopInfo,
};
use super::instruction::EbpfReg;
use super::lir::{LirBlock, LirFunction, LirInst};
use super::mir::{
    BlockId, MirFunction, MirInst, MirValue, StackSlot, StackSlotId, StackSlotKind, VReg,
};
use super::reg_info;

pub trait RegAllocInst: CfgInst {
    fn move_pairs(&self) -> Vec<(VReg, VReg)>;
    fn call_clobbers(&self) -> &'static [EbpfReg];
    fn scratch_clobbers(&self) -> &'static [EbpfReg];
}

pub trait RegAllocFunction: CfgFunction {
    fn vreg_count(&self) -> u32;
    fn param_count(&self) -> usize;
}

pub(crate) fn compute_loop_depths<F: RegAllocFunction>(func: &F) -> HashMap<BlockId, usize>
where
    F::Inst: RegAllocInst,
{
    let cfg = AnalysisCfg::build(func);
    GenericLoopInfo::compute(func, &cfg).loop_depth
}

impl RegAllocInst for MirInst {
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

impl CfgInst for LirInst {
    fn defs(&self) -> Vec<VReg> {
        self.defs()
    }

    fn uses(&self) -> Vec<VReg> {
        self.uses()
    }
}

impl CfgBlock for LirBlock {
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

impl RegAllocFunction for MirFunction {
    fn vreg_count(&self) -> u32 {
        self.vreg_count
    }
    fn param_count(&self) -> usize {
        self.param_count
    }
}

impl CfgFunction for LirFunction {
    type Inst = LirInst;
    type Block = LirBlock;

    fn entry(&self) -> BlockId {
        self.entry
    }

    fn blocks(&self) -> &[Self::Block] {
        &self.blocks
    }

    fn block(&self, id: BlockId) -> &Self::Block {
        LirFunction::block(self, id)
    }

    fn has_block(&self, id: BlockId) -> bool {
        LirFunction::has_block(self, id)
    }
}

impl RegAllocFunction for LirFunction {
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

#[path = "graph_coloring/build.rs"]
mod build;

#[path = "graph_coloring/util.rs"]
mod util;

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
    ) -> ColoringResult
    where
        F::Inst: RegAllocInst,
    {
        let cfg = AnalysisCfg::build(func);
        let liveness = BlockLiveness::compute(func, &cfg);

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
mod tests;
