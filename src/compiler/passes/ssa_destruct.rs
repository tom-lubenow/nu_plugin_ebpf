//! SSA Destruction pass
//!
//! This pass transforms MIR out of SSA form by eliminating phi functions.
//! It must be run after all SSA-based optimizations and before register allocation.
//!
//! The algorithm:
//! 1. For each phi `dst = phi(src1:pred1, src2:pred2, ...)`:
//!    - Insert `dst = src_i` at the end of each predecessor pred_i
//!    - Remove the phi
//!
//! This is the "naive" SSA destruction algorithm. More sophisticated approaches
//! handle critical edge splitting and parallel copy insertion, but this simple
//! version is correct for our use case.
//!
//! Critical edges (edges from a block with multiple successors to a block with
//! multiple predecessors) are handled by the register allocator through spilling.

use std::collections::HashMap;

use super::MirPass;
use crate::compiler::cfg::CFG;
use crate::compiler::mir::{BlockId, MirFunction, MirInst, MirValue, VReg};

/// SSA destruction pass - eliminates phi functions by inserting copies
pub struct SsaDestruction;

impl MirPass for SsaDestruction {
    fn name(&self) -> &str {
        "ssa-destruction"
    }

    fn run(&self, func: &mut MirFunction, _cfg: &CFG) -> bool {
        let mut changed = false;

        // Collect phi information before modifying
        let phi_info = self.collect_phis(func);

        if phi_info.is_empty() {
            return false;
        }

        // Insert copies in predecessor blocks
        for (_block_id, phis) in &phi_info {
            for phi in phis {
                for &(pred_id, src_vreg) in &phi.args {
                    // Insert copy at end of predecessor (before terminator)
                    self.insert_copy(func, pred_id, phi.dst, src_vreg);
                }
            }
            changed = true;
        }

        // Remove phis from their blocks
        for block in &mut func.blocks {
            let before = block.instructions.len();
            block
                .instructions
                .retain(|inst| !matches!(inst, MirInst::Phi { .. }));
            if block.instructions.len() < before {
                changed = true;
            }
        }

        changed
    }
}

/// Information about a phi function
struct PhiInfo {
    dst: VReg,
    args: Vec<(BlockId, VReg)>,
}

impl SsaDestruction {
    /// Collect all phi functions and their information
    fn collect_phis(&self, func: &MirFunction) -> HashMap<BlockId, Vec<PhiInfo>> {
        let mut result: HashMap<BlockId, Vec<PhiInfo>> = HashMap::new();

        for block in &func.blocks {
            for inst in &block.instructions {
                if let MirInst::Phi { dst, args } = inst {
                    result.entry(block.id).or_default().push(PhiInfo {
                        dst: *dst,
                        args: args.clone(),
                    });
                }
            }
        }

        result
    }

    /// Insert a copy instruction at the end of a block (before the terminator)
    fn insert_copy(&self, func: &mut MirFunction, block_id: BlockId, dst: VReg, src: VReg) {
        if let Some(block) = func.blocks.iter_mut().find(|b| b.id == block_id) {
            // Insert copy before terminator
            // Note: instructions don't include the terminator, so we just append
            block.instructions.push(MirInst::Copy {
                dst,
                src: MirValue::VReg(src),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::mir::BinOpKind;

    fn make_ssa_function() -> MirFunction {
        // This represents a diamond CFG after SSA construction:
        // bb0: v0_1 = 1; branch v0_1 -> bb1, bb2
        // bb1: v1_1 = v0_1 + 1; jump bb3
        // bb2: v1_2 = v0_1 - 1; jump bb3
        // bb3: v1_3 = phi(v1_1:bb1, v1_2:bb2); return v1_3

        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        let bb3 = func.alloc_block();
        func.entry = bb0;

        let v0_1 = func.alloc_vreg(); // v0_1
        let v1_1 = func.alloc_vreg(); // v1_1
        let v1_2 = func.alloc_vreg(); // v1_2
        let v1_3 = func.alloc_vreg(); // v1_3 (phi result)

        // bb0
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0_1,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).terminator = MirInst::Branch {
            cond: v0_1,
            if_true: bb1,
            if_false: bb2,
        };

        // bb1
        func.block_mut(bb1).instructions.push(MirInst::BinOp {
            dst: v1_1,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v0_1),
            rhs: MirValue::Const(1),
        });
        func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

        // bb2
        func.block_mut(bb2).instructions.push(MirInst::BinOp {
            dst: v1_2,
            op: BinOpKind::Sub,
            lhs: MirValue::VReg(v0_1),
            rhs: MirValue::Const(1),
        });
        func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

        // bb3 with phi
        func.block_mut(bb3).instructions.push(MirInst::Phi {
            dst: v1_3,
            args: vec![(bb1, v1_1), (bb2, v1_2)],
        });
        func.block_mut(bb3).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v1_3)),
        };

        func
    }

    #[test]
    fn test_phi_elimination() {
        let mut func = make_ssa_function();
        let cfg = CFG::build(&func);

        // Verify we have a phi before
        let bb3 = func.block(BlockId(3));
        assert!(
            bb3.instructions
                .iter()
                .any(|i| matches!(i, MirInst::Phi { .. })),
            "Should have phi before destruction"
        );

        let pass = SsaDestruction;
        let changed = pass.run(&mut func, &cfg);

        assert!(changed);

        // Verify phi is gone
        let bb3 = func.block(BlockId(3));
        assert!(
            !bb3.instructions
                .iter()
                .any(|i| matches!(i, MirInst::Phi { .. })),
            "Should not have phi after destruction"
        );
    }

    #[test]
    fn test_copies_inserted() {
        let mut func = make_ssa_function();
        let cfg = CFG::build(&func);

        let pass = SsaDestruction;
        pass.run(&mut func, &cfg);

        // bb1 should have a copy to v1_3 (the phi dst)
        let bb1 = func.block(BlockId(1));
        let has_copy = bb1
            .instructions
            .iter()
            .any(|i| matches!(i, MirInst::Copy { .. }));
        assert!(has_copy, "bb1 should have a copy instruction");

        // bb2 should also have a copy
        let bb2 = func.block(BlockId(2));
        let has_copy = bb2
            .instructions
            .iter()
            .any(|i| matches!(i, MirInst::Copy { .. }));
        assert!(has_copy, "bb2 should have a copy instruction");
    }

    #[test]
    fn test_no_phis_no_change() {
        // Function without phis
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;
        let v0 = func.alloc_vreg();
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(42),
        });
        func.block_mut(bb0).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v0)),
        };

        let cfg = CFG::build(&func);
        let pass = SsaDestruction;
        let changed = pass.run(&mut func, &cfg);

        assert!(!changed, "Should not change function without phis");
    }
}
