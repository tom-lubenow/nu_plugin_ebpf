//! Dead Code Elimination (DCE) pass
//!
//! This pass removes:
//! 1. Unused instructions (definitions without uses)
//! 2. Unreachable basic blocks
//! 3. Trivially dead code

use std::collections::HashSet;

use super::MirPass;
use crate::compiler::cfg::CFG;
use crate::compiler::mir::{MirFunction, MirInst, VReg};

/// Dead Code Elimination pass
pub struct DeadCodeElimination;

impl MirPass for DeadCodeElimination {
    fn name(&self) -> &str {
        "dce"
    }

    fn run(&self, func: &mut MirFunction, cfg: &CFG) -> bool {
        let mut changed = false;

        // Phase 1: Remove unreachable blocks
        if self.remove_unreachable_blocks(func, cfg) {
            changed = true;
        }

        // Phase 2: Remove unused definitions
        if self.remove_dead_instructions(func) {
            changed = true;
        }

        changed
    }
}

impl DeadCodeElimination {
    /// Remove blocks not reachable from entry
    fn remove_unreachable_blocks(&self, func: &mut MirFunction, cfg: &CFG) -> bool {
        let reachable = cfg.reachable_blocks();
        let before = func.blocks.len();

        // Keep only reachable blocks
        func.blocks.retain(|block| reachable.contains(&block.id));

        func.blocks.len() < before
    }

    /// Remove instructions whose results are never used
    fn remove_dead_instructions(&self, func: &mut MirFunction) -> bool {
        let mut changed = false;

        // Collect all used vregs
        let mut used_vregs: HashSet<VReg> = HashSet::new();

        // First pass: collect all uses
        for block in &func.blocks {
            for inst in &block.instructions {
                for vreg in inst.uses() {
                    used_vregs.insert(vreg);
                }
            }
            for vreg in block.terminator.uses() {
                used_vregs.insert(vreg);
            }
        }

        // Second pass: remove dead definitions
        for block in &mut func.blocks {
            let before = block.instructions.len();

            block.instructions.retain(|inst| {
                // Keep if no definition OR definition is used
                match inst.def() {
                    Some(vreg) => {
                        let keep = used_vregs.contains(&vreg) || has_side_effects(inst);
                        if !keep {
                            // This instruction's result is unused - remove it
                        }
                        keep
                    }
                    None => {
                        // Instructions without definitions (stores, etc.) - keep if side effects
                        has_side_effects(inst)
                    }
                }
            });

            if block.instructions.len() < before {
                changed = true;
            }
        }

        changed
    }
}

/// Check if an instruction has side effects (should not be removed even if unused)
fn has_side_effects(inst: &MirInst) -> bool {
    match inst {
        // Pure computations - can be removed if unused
        MirInst::Copy { .. }
        | MirInst::BinOp { .. }
        | MirInst::UnaryOp { .. }
        | MirInst::Load { .. }
        | MirInst::LoadSlot { .. }
        | MirInst::LoadCtxField { .. }
        | MirInst::ListLen { .. }
        | MirInst::ListGet { .. }
        | MirInst::Phi { .. } => false,

        // Side effects - cannot be removed
        MirInst::Store { .. }
        | MirInst::StoreSlot { .. }
        | MirInst::RecordStore { .. }
        | MirInst::ListNew { .. }
        | MirInst::ListPush { .. }
        | MirInst::CallHelper { .. }
        | MirInst::CallKfunc { .. }
        | MirInst::CallSubfn { .. }
        | MirInst::MapLookup { .. }
        | MirInst::MapUpdate { .. }
        | MirInst::MapDelete { .. }
        | MirInst::EmitEvent { .. }
        | MirInst::EmitRecord { .. }
        | MirInst::ReadStr { .. }
        | MirInst::StrCmp { .. }
        | MirInst::Histogram { .. }
        | MirInst::StartTimer
        | MirInst::StopTimer { .. }
        | MirInst::StringAppend { .. }
        | MirInst::IntToString { .. } => true,

        // Control flow - handled separately (terminators)
        MirInst::Jump { .. }
        | MirInst::Branch { .. }
        | MirInst::Return { .. }
        | MirInst::TailCall { .. }
        | MirInst::LoopHeader { .. }
        | MirInst::LoopBack { .. }
        | MirInst::Placeholder => true, // Keep placeholder so it triggers error if not replaced
    }
}

#[cfg(test)]
mod tests;
