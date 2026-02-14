//! Copy Propagation pass
//!
//! This pass replaces uses of copy destinations with their sources:
//! ```text
//! v1 = v0
//! v2 = v1 + 3   =>   v2 = v0 + 3
//! ```
//!
//! After propagation, the original copy may become dead and can be removed by DCE.
//!
//! This pass is particularly useful after SSA destruction, which inserts copies
//! to eliminate phi functions. Copy propagation cleans up those copies.

use std::collections::HashMap;

use super::MirPass;
use crate::compiler::cfg::CFG;
use crate::compiler::mir::{MirFunction, MirInst, MirValue, VReg};

/// Copy Propagation pass
pub struct CopyPropagation;

impl MirPass for CopyPropagation {
    fn name(&self) -> &str {
        "copy_prop"
    }

    fn run(&self, func: &mut MirFunction, _cfg: &CFG) -> bool {
        let mut changed = false;

        // Build copy map: dst -> src (transitively resolved)
        let copy_map = self.build_copy_map(func);

        if copy_map.is_empty() {
            return false;
        }

        // Replace uses of copy destinations with sources
        for block in &mut func.blocks {
            for inst in &mut block.instructions {
                if self.propagate_copies(inst, &copy_map) {
                    changed = true;
                }
            }
            if self.propagate_copies(&mut block.terminator, &copy_map) {
                changed = true;
            }
        }

        changed
    }
}

impl CopyPropagation {
    /// Build a map from copy destinations to their (transitively resolved) sources
    fn build_copy_map(&self, func: &MirFunction) -> HashMap<VReg, VReg> {
        let mut copy_map: HashMap<VReg, VReg> = HashMap::new();

        // First pass: collect direct copies (vreg to vreg only)
        for block in &func.blocks {
            for inst in &block.instructions {
                if let MirInst::Copy {
                    dst,
                    src: MirValue::VReg(src),
                } = inst
                {
                    // Don't propagate self-copies
                    if dst != src {
                        copy_map.insert(*dst, *src);
                    }
                }
            }
        }

        // Resolve transitive copies: if v2 = v1 and v1 = v0, then v2 -> v0
        // We need to be careful about cycles (shouldn't happen in well-formed SSA)
        let mut resolved: HashMap<VReg, VReg> = HashMap::new();

        for &dst in copy_map.keys() {
            let src = self.resolve_copy_chain(dst, &copy_map);
            if src != dst {
                resolved.insert(dst, src);
            }
        }

        resolved
    }

    /// Follow the copy chain to find the ultimate source
    fn resolve_copy_chain(&self, start: VReg, copy_map: &HashMap<VReg, VReg>) -> VReg {
        let mut current = start;
        let mut visited = std::collections::HashSet::new();

        while let Some(&src) = copy_map.get(&current) {
            // Detect cycles (shouldn't happen, but be safe)
            if !visited.insert(current) {
                break;
            }
            current = src;
        }

        current
    }

    /// Propagate copies in all operand use-sites of an instruction.
    fn propagate_copies(&self, inst: &mut MirInst, copy_map: &HashMap<VReg, VReg>) -> bool {
        let mut changed = false;
        inst.visit_uses_mut(|vreg| {
            if let Some(&new_vreg) = copy_map.get(vreg)
                && *vreg != new_vreg
            {
                *vreg = new_vreg;
                changed = true;
            }
        });

        changed
    }
}

#[cfg(test)]
mod tests;
