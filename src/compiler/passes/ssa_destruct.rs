//! SSA Destruction pass
//!
//! This pass transforms MIR out of SSA form by eliminating phi functions.
//! It must be run after all SSA-based optimizations and before register allocation.
//!
//! The algorithm:
//! 1. For each phi `dst = phi(src1:pred1, src2:pred2, ...)`, collect edge-local
//!    parallel copies `(pred_i -> this_block): dst <- src_i`.
//! 2. Lower each edge's parallel-copy set to a sequential copy list with
//!    cycle-breaking temporaries.
//! 3. For critical edges (multiple predecessors + multiple successors),
//!    split the edge so copies execute only on the intended path.
//! 4. Remove all phi instructions.

use std::collections::{HashMap, HashSet};

use super::MirPass;
use crate::compiler::cfg::CFG;
use crate::compiler::mir::{BlockId, MirFunction, MirInst, MirValue, VReg};

/// SSA destruction pass - eliminates phi functions by inserting copies
pub struct SsaDestruction;

impl MirPass for SsaDestruction {
    fn name(&self) -> &str {
        "ssa-destruction"
    }

    fn run(&self, func: &mut MirFunction, cfg: &CFG) -> bool {
        // Collect edge-local parallel copy sets before mutating control flow.
        let edge_copies = self.collect_edge_copies(func);
        if edge_copies.is_empty() {
            return false;
        }

        let mut edges: Vec<_> = edge_copies.into_iter().collect();
        edges.sort_by_key(|((pred, succ), _)| (pred.0, succ.0));

        for ((pred, succ), copies) in edges {
            let lowered = self.lower_parallel_copies(func, copies);
            if lowered.is_empty() {
                continue;
            }
            if self.is_critical_edge(cfg, pred, succ) {
                self.split_edge_and_insert_copies(func, pred, succ, lowered);
            } else {
                self.insert_copies(func, pred, lowered);
            }
        }

        // Remove phis from their blocks after all copy insertion/splitting.
        for block in &mut func.blocks {
            block
                .instructions
                .retain(|inst| !matches!(inst, MirInst::Phi { .. }));
        }

        true
    }
}

#[derive(Debug, Clone, Copy)]
struct ParallelCopy {
    dst: VReg,
    src: VReg,
}

impl SsaDestruction {
    /// Collect parallel-copy sets per control-flow edge `(pred -> succ)`.
    fn collect_edge_copies(
        &self,
        func: &MirFunction,
    ) -> HashMap<(BlockId, BlockId), Vec<ParallelCopy>> {
        let mut result: HashMap<(BlockId, BlockId), Vec<ParallelCopy>> = HashMap::new();

        for succ in &func.blocks {
            for inst in &succ.instructions {
                if let MirInst::Phi { dst, args } = inst {
                    for &(pred, src) in args {
                        result
                            .entry((pred, succ.id))
                            .or_default()
                            .push(ParallelCopy { dst: *dst, src });
                    }
                }
            }
        }

        result
    }

    /// Lower a parallel-copy set into a sequential copy list.
    ///
    /// Uses a standard "ready move" strategy:
    /// - emit non-cyclic copies whose destination is not used as a source
    /// - for cycles, spill one source to a fresh temporary and continue
    fn lower_parallel_copies(
        &self,
        func: &mut MirFunction,
        copies: Vec<ParallelCopy>,
    ) -> Vec<MirInst> {
        let mut pending: HashMap<VReg, VReg> = HashMap::new();
        let mut dst_order = Vec::new();

        for copy in copies {
            if copy.dst == copy.src {
                continue;
            }
            if !pending.contains_key(&copy.dst) {
                dst_order.push(copy.dst);
            }
            // Duplicate destinations are unexpected in valid SSA but keep
            // deterministic "last writer wins" behavior.
            pending.insert(copy.dst, copy.src);
        }

        let mut lowered = Vec::new();
        while !pending.is_empty() {
            let mut blocked = HashSet::new();
            for src in pending.values() {
                if pending.contains_key(src) {
                    blocked.insert(*src);
                }
            }

            let mut ready = Vec::new();
            for &dst in &dst_order {
                if pending.contains_key(&dst) && !blocked.contains(&dst) {
                    ready.push(dst);
                }
            }

            if !ready.is_empty() {
                for dst in ready {
                    let src = pending
                        .remove(&dst)
                        .expect("ready destination must exist in pending set");
                    lowered.push(MirInst::Copy {
                        dst,
                        src: MirValue::VReg(src),
                    });
                }
                continue;
            }

            // All remaining moves are cyclic: break one cycle with a temp.
            let cycle_dst = dst_order
                .iter()
                .copied()
                .find(|dst| pending.contains_key(dst))
                .expect("pending set must contain at least one destination");
            let cycle_src = pending[&cycle_dst];
            let temp = func.alloc_vreg();
            lowered.push(MirInst::Copy {
                dst: temp,
                src: MirValue::VReg(cycle_src),
            });
            pending.insert(cycle_dst, temp);
        }

        lowered
    }

    fn insert_copies(&self, func: &mut MirFunction, block_id: BlockId, copies: Vec<MirInst>) {
        if copies.is_empty() {
            return;
        }

        if let Some(block) = func.blocks.iter_mut().find(|b| b.id == block_id) {
            block.instructions.extend(copies);
        }
    }

    fn split_edge_and_insert_copies(
        &self,
        func: &mut MirFunction,
        pred: BlockId,
        succ: BlockId,
        copies: Vec<MirInst>,
    ) {
        if copies.is_empty() {
            return;
        }

        // Predict next block id so we can retarget the terminator first without
        // creating an orphan block if the edge lookup fails.
        let split_id = BlockId(func.blocks.len() as u32);
        let redirected = {
            let pred_block = func.block_mut(pred);
            Self::redirect_edge(&mut pred_block.terminator, succ, split_id)
        };

        if !redirected {
            // Fallback: preserve progress by inserting in predecessor, even
            // though this should not happen for a valid `(pred, succ)` edge.
            self.insert_copies(func, pred, copies);
            return;
        }

        let allocated = func.alloc_block();
        debug_assert_eq!(allocated, split_id);

        let split_block = func.block_mut(split_id);
        split_block.instructions = copies;
        split_block.terminator = MirInst::Jump { target: succ };
    }

    fn redirect_edge(term: &mut MirInst, old_target: BlockId, new_target: BlockId) -> bool {
        match term {
            MirInst::Jump { target } => {
                if *target == old_target {
                    *target = new_target;
                    true
                } else {
                    false
                }
            }
            MirInst::Branch {
                if_true, if_false, ..
            } => {
                let mut changed = false;
                if *if_true == old_target {
                    *if_true = new_target;
                    changed = true;
                }
                if *if_false == old_target {
                    *if_false = new_target;
                    changed = true;
                }
                changed
            }
            MirInst::LoopHeader { body, exit, .. } => {
                let mut changed = false;
                if *body == old_target {
                    *body = new_target;
                    changed = true;
                }
                if *exit == old_target {
                    *exit = new_target;
                    changed = true;
                }
                changed
            }
            MirInst::LoopBack { header, .. } => {
                if *header == old_target {
                    *header = new_target;
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn is_critical_edge(&self, cfg: &CFG, pred: BlockId, succ: BlockId) -> bool {
        let pred_succs = cfg
            .successors
            .get(&pred)
            .map(|succs| succs.iter().copied().collect::<HashSet<_>>().len())
            .unwrap_or(0);
        let succ_preds = cfg
            .predecessors
            .get(&succ)
            .map(|preds| preds.iter().copied().collect::<HashSet<_>>().len())
            .unwrap_or(0);
        pred_succs > 1 && succ_preds > 1
    }
}

#[cfg(test)]
mod tests;
