//! SSA (Static Single Assignment) construction pass
//!
//! This pass transforms MIR into SSA form by:
//! 1. Inserting phi functions at dominance frontiers
//! 2. Renaming variables to unique versions
//!
//! SSA form provides several benefits:
//! - Each variable is defined exactly once
//! - Def-use chains are explicit
//! - Enables more powerful optimizations (SCCP, GVN, etc.)
//!
//! Based on the algorithm from:
//! "Efficiently Computing Static Single Assignment Form and the Control Dependence Graph"
//! by Cytron, Ferrante, Rosen, Wegman, and Zadeck (1991)

use std::collections::{HashMap, HashSet, VecDeque};

use super::MirPass;
use crate::compiler::cfg::CFG;
use crate::compiler::mir::{BlockId, MirFunction, MirInst, VReg};

/// SSA construction pass
///
/// Transforms MIR into SSA form by inserting phi functions and renaming variables.
pub struct SsaConstruction;

impl MirPass for SsaConstruction {
    fn name(&self) -> &str {
        "ssa-construction"
    }

    fn run(&self, func: &mut MirFunction, cfg: &CFG) -> bool {
        let builder = SsaBuilder::new(func, cfg);
        builder.build()
    }
}

/// Internal builder for SSA construction
struct SsaBuilder<'a> {
    func: &'a mut MirFunction,
    cfg: &'a CFG,
    /// Maps original vreg -> set of blocks where it's defined
    def_sites: HashMap<VReg, HashSet<BlockId>>,
    /// Current version number for each original vreg
    version_counter: HashMap<VReg, u32>,
    /// Stack of current definitions for each original vreg (for renaming)
    def_stacks: HashMap<VReg, Vec<VReg>>,
    /// Maps new vreg -> original vreg it was derived from
    vreg_origin: HashMap<VReg, VReg>,
    /// All original vregs (before SSA transformation)
    original_vregs: HashSet<VReg>,
}

impl<'a> SsaBuilder<'a> {
    fn new(func: &'a mut MirFunction, cfg: &'a CFG) -> Self {
        Self {
            func,
            cfg,
            def_sites: HashMap::new(),
            version_counter: HashMap::new(),
            def_stacks: HashMap::new(),
            vreg_origin: HashMap::new(),
            original_vregs: HashSet::new(),
        }
    }

    fn build(mut self) -> bool {
        // Collect definition sites for all vregs
        self.collect_def_sites();

        if self.original_vregs.is_empty() {
            return false;
        }

        // Insert phi functions at dominance frontiers
        self.insert_phi_functions();

        // Rename variables using DFS on dominator tree
        self.rename_variables();

        true
    }

    /// Collect all definition sites for each vreg
    fn collect_def_sites(&mut self) {
        for block in &self.func.blocks {
            for inst in &block.instructions {
                if let Some(vreg) = inst.def() {
                    self.def_sites.entry(vreg).or_default().insert(block.id);
                    self.original_vregs.insert(vreg);
                }
            }
            // Also check terminator (though most don't define values)
            if let Some(vreg) = block.terminator.def() {
                self.def_sites.entry(vreg).or_default().insert(block.id);
                self.original_vregs.insert(vreg);
            }
        }

        // Initialize version counters and def stacks
        for &vreg in &self.original_vregs {
            self.version_counter.insert(vreg, 0);
            self.def_stacks.insert(vreg, Vec::new());
        }
    }

    /// Insert phi functions at iterated dominance frontiers
    ///
    /// For each variable v:
    /// 1. Start with the set of blocks where v is defined
    /// 2. Add phi functions at the dominance frontier of these blocks
    /// 3. Since adding a phi is also a definition, iterate until fixed point
    fn insert_phi_functions(&mut self) {
        // For each variable, compute where phi functions are needed
        let phi_locations = self.compute_phi_locations();

        // Insert the phi functions
        for (vreg, blocks) in phi_locations {
            for block_id in blocks {
                // Create phi with empty args (will be filled during renaming)
                let phi = MirInst::Phi {
                    dst: vreg,
                    args: Vec::new(),
                };

                // Insert at the beginning of the block
                if let Some(block) = self.func.blocks.iter_mut().find(|b| b.id == block_id) {
                    block.instructions.insert(0, phi);
                }
            }
        }
    }

    /// Compute the iterated dominance frontier for phi placement
    fn compute_phi_locations(&self) -> HashMap<VReg, HashSet<BlockId>> {
        let mut phi_locations: HashMap<VReg, HashSet<BlockId>> = HashMap::new();

        for (&vreg, def_blocks) in &self.def_sites {
            let mut has_phi: HashSet<BlockId> = HashSet::new();
            let mut worklist: VecDeque<BlockId> = def_blocks.iter().copied().collect();
            let mut processed: HashSet<BlockId> = def_blocks.clone();

            while let Some(block) = worklist.pop_front() {
                // For each block in the dominance frontier
                for &frontier_block in &self.cfg.dominance_frontier(block) {
                    if !has_phi.contains(&frontier_block) {
                        // Place a phi here
                        has_phi.insert(frontier_block);
                        phi_locations
                            .entry(vreg)
                            .or_default()
                            .insert(frontier_block);

                        // Adding a phi is a new definition site - add to worklist
                        if !processed.contains(&frontier_block) {
                            processed.insert(frontier_block);
                            worklist.push_back(frontier_block);
                        }
                    }
                }
            }
        }

        phi_locations
    }

    /// Rename variables using a DFS traversal of the dominator tree
    fn rename_variables(&mut self) {
        // Build children map for dominator tree traversal
        let dom_children = self.build_dominator_tree_children();

        // Start renaming from entry block
        self.rename_block(self.cfg.entry, &dom_children);
    }

    /// Build a map of block -> children in dominator tree
    fn build_dominator_tree_children(&self) -> HashMap<BlockId, Vec<BlockId>> {
        let mut children: HashMap<BlockId, Vec<BlockId>> = HashMap::new();

        // Initialize empty lists for all blocks
        for block in &self.func.blocks {
            children.insert(block.id, Vec::new());
        }

        // Build parent -> children relationship from idom
        for block in &self.func.blocks {
            if let Some(&idom) = self.cfg.idom.get(&block.id) {
                children.entry(idom).or_default().push(block.id);
            }
        }

        children
    }

    /// Rename variables in a block and its dominated children (DFS)
    fn rename_block(&mut self, block_id: BlockId, dom_children: &HashMap<BlockId, Vec<BlockId>>) {
        // Track how many definitions we push onto stacks (to pop later)
        let mut pushed_counts: HashMap<VReg, usize> = HashMap::new();

        // Get the block (we need to work with indices due to borrow checker)
        let block_idx = self.func.blocks.iter().position(|b| b.id == block_id);
        if block_idx.is_none() {
            return;
        }
        let block_idx = block_idx.unwrap();

        // Process instructions in the block
        let num_instructions = self.func.blocks[block_idx].instructions.len();
        for i in 0..num_instructions {
            let inst = &self.func.blocks[block_idx].instructions[i];

            // For phi functions, handle specially (they're already placed, just update args)
            if let MirInst::Phi { dst, args } = inst {
                let orig_vreg = *dst;
                let existing_args = args.clone();

                // Generate new version
                let new_vreg = self.new_version(orig_vreg);
                *pushed_counts.entry(orig_vreg).or_insert(0) += 1;

                // Update the phi destination, preserving existing args
                self.func.blocks[block_idx].instructions[i] = MirInst::Phi {
                    dst: new_vreg,
                    args: existing_args, // Preserve args filled by predecessors
                };
                continue;
            }

            // First, rename all uses to current version
            let new_inst = self.rename_uses(&self.func.blocks[block_idx].instructions[i].clone());
            self.func.blocks[block_idx].instructions[i] = new_inst;

            // Then, handle definitions - create new version
            if let Some(def_vreg) = self.func.blocks[block_idx].instructions[i].def() {
                if self.original_vregs.contains(&def_vreg) {
                    let orig_vreg = self.get_original_vreg(def_vreg);
                    let new_vreg = self.new_version(orig_vreg);
                    *pushed_counts.entry(orig_vreg).or_insert(0) += 1;

                    // Update the instruction's destination
                    update_def(&mut self.func.blocks[block_idx].instructions[i], new_vreg);
                }
            }
        }

        // Rename uses in terminator
        let new_term = self.rename_uses(&self.func.blocks[block_idx].terminator.clone());
        self.func.blocks[block_idx].terminator = new_term;

        // Fill in phi arguments in successor blocks
        let successors = self.func.blocks[block_idx].successors();
        for succ_id in successors {
            self.fill_phi_args(succ_id, block_id);
        }

        // Recurse into dominated children
        if let Some(children) = dom_children.get(&block_id) {
            for &child in children {
                self.rename_block(child, dom_children);
            }
        }

        // Pop the definitions we pushed onto stacks
        for (vreg, count) in pushed_counts {
            if let Some(stack) = self.def_stacks.get_mut(&vreg) {
                for _ in 0..count {
                    stack.pop();
                }
            }
        }
    }

    /// Create a new version of a vreg
    fn new_version(&mut self, orig_vreg: VReg) -> VReg {
        let counter = self.version_counter.entry(orig_vreg).or_insert(0);
        *counter += 1;

        // Allocate new vreg for this version
        let new_vreg = self.func.alloc_vreg();
        self.vreg_origin.insert(new_vreg, orig_vreg);

        // Push onto def stack
        self.def_stacks.entry(orig_vreg).or_default().push(new_vreg);

        new_vreg
    }

    /// Get the current version of a vreg (top of stack)
    fn current_version(&self, orig_vreg: VReg) -> Option<VReg> {
        self.def_stacks
            .get(&orig_vreg)
            .and_then(|stack| stack.last().copied())
    }

    /// Get the original vreg that a versioned vreg was derived from
    fn get_original_vreg(&self, vreg: VReg) -> VReg {
        self.vreg_origin.get(&vreg).copied().unwrap_or(vreg)
    }

    /// Rename all uses in an instruction to their current versions
    fn rename_uses(&self, inst: &MirInst) -> MirInst {
        if matches!(inst, MirInst::Phi { .. }) {
            // Phi args are handled separately by fill_phi_args.
            return inst.clone();
        }
        inst.map_uses(|vreg| self.rename_vreg(vreg))
    }

    /// Rename a vreg to its current version
    fn rename_vreg(&self, vreg: VReg) -> VReg {
        // If this vreg has versions, use the current one
        if self.original_vregs.contains(&vreg) {
            self.current_version(vreg).unwrap_or(vreg)
        } else {
            // This is already a versioned vreg or not a variable we track
            let orig = self.get_original_vreg(vreg);
            self.current_version(orig).unwrap_or(vreg)
        }
    }

    /// Fill in phi arguments from a predecessor block
    fn fill_phi_args(&mut self, succ_id: BlockId, pred_id: BlockId) {
        if let Some(succ_block) = self.func.blocks.iter_mut().find(|b| b.id == succ_id) {
            for inst in &mut succ_block.instructions {
                if let MirInst::Phi { dst, args } = inst {
                    // Find the original vreg this phi is for
                    let orig_vreg = self.vreg_origin.get(dst).copied().unwrap_or(*dst);

                    // Get the current version from the predecessor
                    if let Some(pred_version) = self
                        .def_stacks
                        .get(&orig_vreg)
                        .and_then(|s| s.last().copied())
                    {
                        args.push((pred_id, pred_version));
                    }
                }
            }
        }
    }
}

/// Update the destination of an instruction (free function to avoid borrow issues)
fn update_def(inst: &mut MirInst, new_dst: VReg) {
    match inst {
        MirInst::Copy { dst, .. }
        | MirInst::BinOp { dst, .. }
        | MirInst::UnaryOp { dst, .. }
        | MirInst::Load { dst, .. }
        | MirInst::LoadSlot { dst, .. }
        | MirInst::LoadCtxField { dst, .. }
        | MirInst::CallHelper { dst, .. }
        | MirInst::CallKfunc { dst, .. }
        | MirInst::CallSubfn { dst, .. }
        | MirInst::MapLookup { dst, .. }
        | MirInst::StrCmp { dst, .. }
        | MirInst::StopTimer { dst, .. }
        | MirInst::LoopHeader { counter: dst, .. }
        | MirInst::ListNew { dst, .. }
        | MirInst::ListLen { dst, .. }
        | MirInst::ListGet { dst, .. }
        | MirInst::Phi { dst, .. } => {
            *dst = new_dst;
        }
        // ReadStr's dst is StackSlotId, not VReg
        // These don't have VReg destinations
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::mir::{BinOpKind, MirValue};

    fn make_diamond_function() -> MirFunction {
        // bb0: v0 = 1; branch v0 -> bb1, bb2
        // bb1: v1 = v0 + 1; jump bb3
        // bb2: v1 = v0 - 1; jump bb3  <- v1 defined in both paths
        // bb3: return v1              <- needs phi for v1

        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        let bb3 = func.alloc_block();
        func.entry = bb0;

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
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::Const(1),
        });
        func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

        // bb2
        func.block_mut(bb2).instructions.push(MirInst::BinOp {
            dst: v1,
            op: BinOpKind::Sub,
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

    fn make_loop_function() -> MirFunction {
        // bb0: v0 = 0; jump bb1
        // bb1: v0 = v0 + 1; branch v0 -> bb1, bb2  <- loop, v0 defined inside
        // bb2: return v0

        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();

        // bb0
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(0),
        });
        func.block_mut(bb0).terminator = MirInst::Jump { target: bb1 };

        // bb1 - loop body
        func.block_mut(bb1).instructions.push(MirInst::BinOp {
            dst: v0,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v0),
            rhs: MirValue::Const(1),
        });
        func.block_mut(bb1).terminator = MirInst::Branch {
            cond: v0,
            if_true: bb1,
            if_false: bb2,
        };

        // bb2
        func.block_mut(bb2).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v0)),
        };

        func
    }

    #[test]
    fn test_phi_insertion_diamond() {
        let mut func = make_diamond_function();
        let cfg = CFG::build(&func);

        let pass = SsaConstruction;
        let changed = pass.run(&mut func, &cfg);

        assert!(changed);

        // bb3 should have a phi for v1
        let bb3 = func.block(BlockId(3));
        let has_phi = bb3
            .instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::Phi { .. }));
        assert!(has_phi, "bb3 should have a phi function");
    }

    #[test]
    fn test_phi_insertion_loop() {
        let mut func = make_loop_function();
        let cfg = CFG::build(&func);

        let pass = SsaConstruction;
        let changed = pass.run(&mut func, &cfg);

        assert!(changed);

        // bb1 should have a phi for v0 (loop header)
        let bb1 = func.block(BlockId(1));
        let has_phi = bb1
            .instructions
            .iter()
            .any(|inst| matches!(inst, MirInst::Phi { .. }));
        assert!(has_phi, "bb1 (loop header) should have a phi function");
    }

    #[test]
    fn test_ssa_unique_definitions() {
        let mut func = make_diamond_function();
        let cfg = CFG::build(&func);

        let pass = SsaConstruction;
        pass.run(&mut func, &cfg);

        // After SSA, each vreg should be defined at most once
        let mut def_counts: HashMap<VReg, usize> = HashMap::new();

        for block in &func.blocks {
            for inst in &block.instructions {
                if let Some(vreg) = inst.def() {
                    *def_counts.entry(vreg).or_insert(0) += 1;
                }
            }
        }

        for (vreg, count) in &def_counts {
            assert_eq!(
                *count, 1,
                "VReg {:?} should be defined exactly once, but was defined {} times",
                vreg, count
            );
        }
    }

    #[test]
    fn test_phi_args_from_predecessors() {
        let mut func = make_diamond_function();
        let cfg = CFG::build(&func);

        let pass = SsaConstruction;
        pass.run(&mut func, &cfg);

        // Find the phi in bb3
        let bb3 = func.block(BlockId(3));
        let phi = bb3
            .instructions
            .iter()
            .find(|inst| matches!(inst, MirInst::Phi { .. }));

        if let Some(MirInst::Phi { args, .. }) = phi {
            // Should have 2 arguments (from bb1 and bb2)
            assert_eq!(args.len(), 2, "Phi should have 2 arguments");

            // Check that args come from the correct predecessors
            let pred_blocks: HashSet<_> = args.iter().map(|(block, _)| *block).collect();
            assert!(pred_blocks.contains(&BlockId(1)));
            assert!(pred_blocks.contains(&BlockId(2)));
        } else {
            panic!("Expected phi in bb3");
        }
    }
}
