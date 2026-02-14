//! Branch Optimization pass
//!
//! This pass simplifies control flow:
//!
//! - **Same-target branches**: `if cond goto A else A` → `goto A`
//! - **Jump threading**: Branch/jump to unconditional jump skips intermediate block
//! - **Empty block elimination**: Blocks with only a jump are bypassed
//!
//! These optimizations reduce code size and improve execution efficiency.

use std::collections::HashMap;

use super::MirPass;
use crate::compiler::cfg::CFG;
use crate::compiler::mir::{BlockId, MirFunction, MirInst};

/// Branch Optimization pass
pub struct BranchOptimization;

impl MirPass for BranchOptimization {
    fn name(&self) -> &str {
        "branch_opt"
    }

    fn run(&self, func: &mut MirFunction, _cfg: &CFG) -> bool {
        let mut changed = false;

        // Build jump target map for threading
        let jump_targets = self.build_jump_targets(func);

        // Optimize terminators
        for block in &mut func.blocks {
            if self.optimize_terminator(&mut block.terminator, &jump_targets) {
                changed = true;
            }
        }

        changed
    }
}

impl BranchOptimization {
    /// Build a map of blocks that are just unconditional jumps
    /// Maps block_id -> ultimate target (following chains of jumps)
    fn build_jump_targets(&self, func: &MirFunction) -> HashMap<BlockId, BlockId> {
        let mut jump_targets: HashMap<BlockId, BlockId> = HashMap::new();

        // First pass: find blocks that are pure jumps (no instructions, just Jump terminator)
        for block in &func.blocks {
            if block.instructions.is_empty() {
                if let MirInst::Jump { target } = &block.terminator {
                    jump_targets.insert(block.id, *target);
                }
            }
        }

        // Resolve chains: if A -> B and B -> C, then A -> C
        // Use iterative resolution to handle chains of any length
        let mut resolved: HashMap<BlockId, BlockId> = HashMap::new();

        for &block_id in jump_targets.keys() {
            let target = self.resolve_jump_chain(block_id, &jump_targets);
            // Only record if we actually thread through something
            if target != block_id {
                resolved.insert(block_id, target);
            }
        }

        resolved
    }

    /// Follow jump chain to find ultimate target
    fn resolve_jump_chain(
        &self,
        start: BlockId,
        jump_targets: &HashMap<BlockId, BlockId>,
    ) -> BlockId {
        let mut current = start;
        let mut visited = std::collections::HashSet::new();

        while let Some(&target) = jump_targets.get(&current) {
            // Cycle detection
            if !visited.insert(current) {
                break;
            }
            current = target;
        }

        current
    }

    /// Optimize a terminator instruction
    fn optimize_terminator(
        &self,
        term: &mut MirInst,
        jump_targets: &HashMap<BlockId, BlockId>,
    ) -> bool {
        match term {
            // Same-target branch optimization
            MirInst::Branch {
                cond: _,
                if_true,
                if_false,
            } => {
                let mut changed = false;

                // Thread through empty blocks
                if let Some(&new_true) = jump_targets.get(if_true) {
                    *if_true = new_true;
                    changed = true;
                }
                if let Some(&new_false) = jump_targets.get(if_false) {
                    *if_false = new_false;
                    changed = true;
                }

                // After threading, check if both targets are the same
                if if_true == if_false {
                    *term = MirInst::Jump { target: *if_true };
                    return true;
                }

                changed
            }

            // Jump threading
            MirInst::Jump { target } => {
                if let Some(&new_target) = jump_targets.get(target) {
                    *target = new_target;
                    return true;
                }
                false
            }

            // LoopBack can also be threaded
            MirInst::LoopBack {
                header,
                counter,
                step,
            } => {
                if let Some(&new_header) = jump_targets.get(header) {
                    *term = MirInst::LoopBack {
                        header: new_header,
                        counter: *counter,
                        step: *step,
                    };
                    return true;
                }
                false
            }

            // Other terminators don't have jump targets to optimize
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests;
