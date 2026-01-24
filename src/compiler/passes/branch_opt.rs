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
mod tests {
    use super::*;
    use crate::compiler::mir::MirValue;

    #[test]
    fn test_same_target_branch() {
        // bb0: branch v0 -> bb1, bb1  (should become: jump bb1)
        // bb1: return 0
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).terminator = MirInst::Branch {
            cond: v0,
            if_true: bb1,
            if_false: bb1, // Same target!
        };

        func.block_mut(bb1).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let cfg = CFG::build(&func);
        let pass = BranchOptimization;
        let changed = pass.run(&mut func, &cfg);

        assert!(changed);

        // Should now be a simple jump
        match &func.block(bb0).terminator {
            MirInst::Jump { target } => {
                assert_eq!(*target, bb1);
            }
            other => panic!("Expected Jump, got {:?}", other),
        }
    }

    #[test]
    fn test_jump_threading() {
        // bb0: jump bb1
        // bb1: jump bb2  (empty block)
        // bb2: return 0
        //
        // Should become: bb0: jump bb2
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        func.entry = bb0;

        func.block_mut(bb0).terminator = MirInst::Jump { target: bb1 };
        func.block_mut(bb1).terminator = MirInst::Jump { target: bb2 }; // Empty block, just jump
        func.block_mut(bb2).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let cfg = CFG::build(&func);
        let pass = BranchOptimization;
        let changed = pass.run(&mut func, &cfg);

        assert!(changed);

        // bb0 should now jump directly to bb2
        match &func.block(bb0).terminator {
            MirInst::Jump { target } => {
                assert_eq!(*target, bb2, "Should thread through bb1 to bb2");
            }
            other => panic!("Expected Jump, got {:?}", other),
        }
    }

    #[test]
    fn test_branch_threading() {
        // bb0: v0 = 1; branch v0 -> bb1, bb2
        // bb1: jump bb3  (empty)
        // bb2: return 1
        // bb3: return 0
        //
        // Should thread bb1 -> bb3 in the branch
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        let bb3 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).terminator = MirInst::Branch {
            cond: v0,
            if_true: bb1,
            if_false: bb2,
        };

        func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 }; // Empty, just jump
        func.block_mut(bb2).terminator = MirInst::Return {
            val: Some(MirValue::Const(1)),
        };
        func.block_mut(bb3).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let cfg = CFG::build(&func);
        let pass = BranchOptimization;
        let changed = pass.run(&mut func, &cfg);

        assert!(changed);

        // Branch should now go directly to bb3 for if_true
        match &func.block(bb0).terminator {
            MirInst::Branch {
                if_true, if_false, ..
            } => {
                assert_eq!(*if_true, bb3, "if_true should be threaded to bb3");
                assert_eq!(*if_false, bb2, "if_false should remain bb2");
            }
            other => panic!("Expected Branch, got {:?}", other),
        }
    }

    #[test]
    fn test_chain_threading() {
        // bb0: jump bb1
        // bb1: jump bb2  (empty)
        // bb2: jump bb3  (empty)
        // bb3: return 0
        //
        // Should thread all the way to bb3
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        let bb3 = func.alloc_block();
        func.entry = bb0;

        func.block_mut(bb0).terminator = MirInst::Jump { target: bb1 };
        func.block_mut(bb1).terminator = MirInst::Jump { target: bb2 };
        func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };
        func.block_mut(bb3).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let cfg = CFG::build(&func);
        let pass = BranchOptimization;
        let changed = pass.run(&mut func, &cfg);

        assert!(changed);

        // bb0 should jump directly to bb3
        match &func.block(bb0).terminator {
            MirInst::Jump { target } => {
                assert_eq!(*target, bb3, "Should thread through entire chain to bb3");
            }
            other => panic!("Expected Jump, got {:?}", other),
        }
    }

    #[test]
    fn test_no_threading_with_instructions() {
        // bb0: jump bb1
        // bb1: v0 = 1; jump bb2  (has instructions, should NOT thread)
        // bb2: return v0
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();

        func.block_mut(bb0).terminator = MirInst::Jump { target: bb1 };
        func.block_mut(bb1).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(1),
        });
        func.block_mut(bb1).terminator = MirInst::Jump { target: bb2 };
        func.block_mut(bb2).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v0)),
        };

        let cfg = CFG::build(&func);
        let pass = BranchOptimization;
        let changed = pass.run(&mut func, &cfg);

        // Should NOT change - bb1 has instructions
        assert!(!changed);

        match &func.block(bb0).terminator {
            MirInst::Jump { target } => {
                assert_eq!(
                    *target, bb1,
                    "Should NOT thread past bb1 (has instructions)"
                );
            }
            other => panic!("Expected Jump, got {:?}", other),
        }
    }

    #[test]
    fn test_no_change_needed() {
        // bb0: jump bb1
        // bb1: return 0  (not a jump, can't thread)
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        func.entry = bb0;

        func.block_mut(bb0).terminator = MirInst::Jump { target: bb1 };
        func.block_mut(bb1).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        let cfg = CFG::build(&func);
        let pass = BranchOptimization;
        let changed = pass.run(&mut func, &cfg);

        assert!(!changed, "No threading possible");
    }
}
