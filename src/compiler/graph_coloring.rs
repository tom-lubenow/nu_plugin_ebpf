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

use super::cfg::{CFG, LivenessInfo, LoopInfo};
use super::instruction::EbpfReg;
use super::mir::{MirFunction, MirInst, MirValue, StackSlot, StackSlotId, StackSlotKind, VReg};

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
    /// Next spill slot ID
    next_spill_slot: u32,
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
            next_spill_slot: 0,
        }
    }

    /// Run the full allocation algorithm
    pub fn allocate(
        &mut self,
        func: &MirFunction,
        cfg: &CFG,
        liveness: &LivenessInfo,
    ) -> ColoringResult {
        // Build interference graph
        self.build(func, cfg, liveness);

        // Compute spill costs
        self.compute_spill_costs(func, cfg);

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

        // Build spill slots
        let mut spill_slots = Vec::new();
        let mut spill_map = HashMap::new();
        for &vreg in &self.spilled_nodes {
            let slot_id = StackSlotId(self.next_spill_slot);
            self.next_spill_slot += 1;
            spill_slots.push(StackSlot {
                id: slot_id,
                size: 8,
                align: 8,
                kind: StackSlotKind::Spill,
                offset: None, // Will be assigned during stack layout
            });
            spill_map.insert(vreg, slot_id);
        }

        ColoringResult {
            coloring: self.color.clone(),
            spills: spill_map,
            coalesced_moves,
            spill_slots,
        }
    }

    /// Build the interference graph from liveness information
    fn build(&mut self, func: &MirFunction, cfg: &CFG, liveness: &LivenessInfo) {
        // Add all vregs as nodes
        for i in 0..func.vreg_count {
            self.graph.add_node(VReg(i));
            self.node_state.insert(VReg(i), NodeState::Initial);
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
            self.process_instruction_liveness(&block.terminator, &mut live, inst_idx);
            inst_idx += 1;

            // Process instructions in reverse
            for inst in block.instructions.iter().rev() {
                self.process_instruction_liveness(inst, &mut live, inst_idx);

                // Check for move instructions that could be coalesced
                if let MirInst::Copy {
                    dst,
                    src: MirValue::VReg(src),
                } = inst
                {
                    self.graph.add_move(*src, *dst);
                }

                inst_idx += 1;
            }
        }

        // Add interference edges between all simultaneously live vregs
        self.build_interference_from_liveness(func, cfg, liveness);
    }

    /// Build interference edges from liveness analysis
    fn build_interference_from_liveness(
        &mut self,
        func: &MirFunction,
        cfg: &CFG,
        liveness: &LivenessInfo,
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
            self.add_interference_for_inst(&block.terminator, &live);
            self.update_live_for_inst(&block.terminator, &mut live);

            // Process instructions in reverse
            for inst in block.instructions.iter().rev() {
                self.add_interference_for_inst(inst, &live);
                self.update_live_for_inst(inst, &mut live);
            }
        }
    }

    /// Add interference edges for an instruction
    fn add_interference_for_inst(&mut self, inst: &MirInst, live: &HashSet<VReg>) {
        // Get the definition (if any)
        if let Some(def) = self.get_def(inst) {
            // The defined vreg interferes with all live vregs (except itself)
            // Special case for moves: don't add interference between src and dst
            let move_src = if let MirInst::Copy {
                src: MirValue::VReg(src),
                ..
            } = inst
            {
                Some(*src)
            } else {
                None
            };

            for &live_vreg in live {
                if live_vreg != def && Some(live_vreg) != move_src {
                    self.graph.add_edge(def, live_vreg);
                }
            }
        }
    }

    /// Update live set for an instruction (backward)
    fn update_live_for_inst(&mut self, inst: &MirInst, live: &mut HashSet<VReg>) {
        // Remove definition
        if let Some(def) = self.get_def(inst) {
            live.remove(&def);
        }

        // Add uses
        for use_vreg in self.get_uses(inst) {
            live.insert(use_vreg);
        }
    }

    /// Process instruction for liveness (used during initial build)
    fn process_instruction_liveness(
        &mut self,
        inst: &MirInst,
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

        // Update liveness
        if let Some(def) = self.get_def(inst) {
            live.remove(&def);
        }
        for use_vreg in self.get_uses(inst) {
            live.insert(use_vreg);
        }
    }

    /// Get the vreg defined by an instruction (if any)
    fn get_def(&self, inst: &MirInst) -> Option<VReg> {
        // Use the MirInst::def() method which handles all instruction types
        inst.def()
    }

    /// Get all vregs used by an instruction
    fn get_uses(&self, inst: &MirInst) -> Vec<VReg> {
        // Use the MirInst::uses() method which handles all instruction types
        inst.uses()
    }

    /// Compute spill costs for each vreg
    fn compute_spill_costs(&mut self, func: &MirFunction, cfg: &CFG) {
        // Count uses and defs, weighted by loop depth
        let loop_info = LoopInfo::compute(func, cfg);

        for i in 0..func.vreg_count {
            let vreg = VReg(i);
            self.spill_cost.insert(vreg, 0.0);
        }

        for &block_id in cfg.rpo.iter() {
            let block = func.block(block_id);
            let depth = loop_info.loop_depth.get(&block_id).copied().unwrap_or(0);
            let weight = 10.0_f64.powi(depth as i32); // 10^depth

            for inst in &block.instructions {
                // Count definition
                if let Some(def) = self.get_def(inst) {
                    *self.spill_cost.entry(def).or_insert(0.0) += weight;
                }
                // Count uses
                for use_vreg in self.get_uses(inst) {
                    *self.spill_cost.entry(use_vreg).or_insert(0.0) += weight;
                }
            }

            // Terminator
            if let Some(def) = self.get_def(&block.terminator) {
                *self.spill_cost.entry(def).or_insert(0.0) += weight;
            }
            for use_vreg in self.get_uses(&block.terminator) {
                *self.spill_cost.entry(use_vreg).or_insert(0.0) += weight;
            }
        }
    }

    /// Initialize worklists based on node degree and move-relatedness
    fn make_worklist(&mut self) {
        let nodes: Vec<VReg> = self.graph.nodes.iter().copied().collect();

        for vreg in nodes {
            if self.node_state.get(&vreg) != Some(&NodeState::Initial) {
                continue;
            }

            let degree = self.graph.degree(vreg);
            let move_related = self.is_move_related(vreg);

            if degree >= self.k {
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
        for mv in self.graph.all_moves.iter().copied() {
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
        self.graph
            .moves_for(vreg)
            .filter(|mv| {
                matches!(
                    self.move_state.get(mv),
                    Some(MoveState::Worklist) | Some(MoveState::Active) | None
                )
            })
            .collect()
    }

    /// Simplify: remove a low-degree non-move-related node
    fn simplify(&mut self) {
        if let Some(vreg) = self.simplify_worklist.pop_front() {
            self.select_stack.push(vreg);
            self.node_state.insert(vreg, NodeState::OnStack);

            // Decrement degree of neighbors
            let neighbors: Vec<VReg> = self.graph.adjacent(vreg).collect();
            for neighbor in neighbors {
                self.decrement_degree(neighbor);
            }
        }
    }

    /// Decrement degree when a neighbor is removed
    fn decrement_degree(&mut self, vreg: VReg) {
        let old_degree = self.graph.degree.get(&vreg).copied().unwrap_or(0);
        if old_degree == 0 {
            return;
        }

        let new_degree = old_degree - 1;
        self.graph.degree.insert(vreg, new_degree);

        // If degree dropped below K, move from spill to freeze/simplify
        if old_degree == self.k {
            // Enable moves for this node and its neighbors
            let neighbors: Vec<VReg> = self.graph.adjacent(vreg).collect();
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

        // Order so that if one is precolored, it's u
        let (u, v) = (x, y); // We don't have precolored nodes in our current setup

        if u == v {
            // Already coalesced
            self.move_state.insert(mv, MoveState::Coalesced);
            self.add_worklist(u);
        } else if self.graph.interferes(u, v) {
            // Constrained: can't coalesce interfering nodes
            self.move_state.insert(mv, MoveState::Constrained);
            self.add_worklist(u);
            self.add_worklist(v);
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
        let mut high_degree_neighbors = HashSet::new();

        for neighbor in self.graph.adjacent(u) {
            if self.graph.degree(neighbor) >= self.k {
                high_degree_neighbors.insert(neighbor);
            }
        }
        for neighbor in self.graph.adjacent(v) {
            if self.graph.degree(neighbor) >= self.k {
                high_degree_neighbors.insert(neighbor);
            }
        }

        high_degree_neighbors.len() < self.k
    }

    /// Add node to simplify worklist if appropriate
    fn add_worklist(&mut self, vreg: VReg) {
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
        let v_neighbors: Vec<VReg> = self.graph.adjacent(v).collect();
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
        // Pick any node from freeze worklist
        let vreg = match self.freeze_worklist.iter().next().copied() {
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
                .find(|r| !used_colors.contains(r));

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
    let liveness = LivenessInfo::compute(func, &cfg);
    let mut allocator = GraphColoringAllocator::new(available_regs);
    allocator.allocate(func, &cfg, &liveness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::mir::{BinOpKind, MirInst, MirValue};

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
        let cfg = CFG::build(&func);
        let liveness = LivenessInfo::compute(&func, &cfg);
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
    fn test_list_interference() {
        let func = make_list_function();
        let cfg = CFG::build(&func);
        let liveness = LivenessInfo::compute(&func, &cfg);
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
}
