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
    fn test_parallel_copy_multi_phi_join_ordering() {
        // bb0: cond=1; branch bb1, bb2
        // bb1: b=10; c=20; jump bb3
        // bb2: b2=30; c2=40; jump bb3
        // bb3:
        //   b = phi(c:bb1, b2:bb2)
        //   a = phi(b:bb1, c2:bb2)
        //   return a
        //
        // On edge bb1->bb3 this requires parallel copies:
        //   b <- c
        //   a <- b
        // Correct lowering must emit a <- b before b <- c.
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        let bb3 = func.alloc_block();
        func.entry = bb0;

        let cond = func.alloc_vreg();
        let a = func.alloc_vreg();
        let b = func.alloc_vreg();
        let c = func.alloc_vreg();
        let b2 = func.alloc_vreg();
        let c2 = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: cond,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).terminator = MirInst::Branch {
            cond,
            if_true: bb1,
            if_false: bb2,
        };

        func.block_mut(bb1).instructions.push(MirInst::Copy {
            dst: b,
            src: MirValue::Const(10),
        });
        func.block_mut(bb1).instructions.push(MirInst::Copy {
            dst: c,
            src: MirValue::Const(20),
        });
        func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

        func.block_mut(bb2).instructions.push(MirInst::Copy {
            dst: b2,
            src: MirValue::Const(30),
        });
        func.block_mut(bb2).instructions.push(MirInst::Copy {
            dst: c2,
            src: MirValue::Const(40),
        });
        func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

        func.block_mut(bb3).instructions.push(MirInst::Phi {
            dst: b,
            args: vec![(bb1, c), (bb2, b2)],
        });
        func.block_mut(bb3).instructions.push(MirInst::Phi {
            dst: a,
            args: vec![(bb1, b), (bb2, c2)],
        });
        func.block_mut(bb3).terminator = MirInst::Return {
            val: Some(MirValue::VReg(a)),
        };

        let cfg = CFG::build(&func);
        let pass = SsaDestruction;
        pass.run(&mut func, &cfg);

        let bb1 = func.block(bb1);
        let tail_copies: Vec<_> = bb1
            .instructions
            .iter()
            .filter_map(|inst| match inst {
                MirInst::Copy {
                    dst,
                    src: MirValue::VReg(src),
                } => Some((*dst, *src)),
                _ => None,
            })
            .collect();

        let inserted = &tail_copies[tail_copies.len() - 2..];
        assert_eq!(
            inserted[0],
            (a, b),
            "must preserve old b before rewriting b"
        );
        assert_eq!(inserted[1], (b, c));
    }

    #[test]
    fn test_parallel_copy_loop_header_swap_cycle() {
        // bb0: x0=1; y0=2; cond=1; jump bb1
        // bb1:
        //   x = phi(x0:bb0, y:bb2)
        //   y = phi(y0:bb0, x:bb2)
        //   branch cond -> bb2, bb3
        // bb2: jump bb1
        // bb3: return x
        //
        // Backedge bb2->bb1 requires a swap:
        //   x <- y
        //   y <- x
        // Correct lowering needs a temporary.
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        let bb3 = func.alloc_block();
        func.entry = bb0;

        let x0 = func.alloc_vreg();
        let y0 = func.alloc_vreg();
        let cond = func.alloc_vreg();
        let x = func.alloc_vreg();
        let y = func.alloc_vreg();
        let pre_temp_vreg_count = func.vreg_count;

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: x0,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: y0,
            src: MirValue::Const(2),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: cond,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).terminator = MirInst::Jump { target: bb1 };

        func.block_mut(bb1).instructions.push(MirInst::Phi {
            dst: x,
            args: vec![(bb0, x0), (bb2, y)],
        });
        func.block_mut(bb1).instructions.push(MirInst::Phi {
            dst: y,
            args: vec![(bb0, y0), (bb2, x)],
        });
        func.block_mut(bb1).terminator = MirInst::Branch {
            cond,
            if_true: bb2,
            if_false: bb3,
        };

        func.block_mut(bb2).terminator = MirInst::Jump { target: bb1 };
        func.block_mut(bb3).terminator = MirInst::Return {
            val: Some(MirValue::VReg(x)),
        };

        let cfg = CFG::build(&func);
        let pass = SsaDestruction;
        pass.run(&mut func, &cfg);

        assert_eq!(
            func.vreg_count,
            pre_temp_vreg_count + 1,
            "swap cycle should allocate one temporary"
        );

        let bb2 = func.block(bb2);
        let copies: Vec<_> = bb2
            .instructions
            .iter()
            .filter_map(|inst| match inst {
                MirInst::Copy {
                    dst,
                    src: MirValue::VReg(src),
                } => Some((*dst, *src)),
                _ => None,
            })
            .collect();

        assert_eq!(copies.len(), 3, "swap cycle should lower to 3 copies");
        let temp = copies[0].0;
        assert_ne!(temp, x);
        assert_ne!(temp, y);
        assert_eq!(copies[0], (temp, y));
        assert_eq!(copies[1], (y, x));
        assert_eq!(copies[2], (x, temp));
    }

    #[test]
    fn test_critical_edge_is_split_for_phi_copies() {
        // bb0: cond=1; branch bb1, bb2
        // bb1: v1=11; branch cond -> bb3, bb4
        // bb2: v2=22; jump bb3
        // bb3: p = phi(v1:bb1, v2:bb2); return p
        // bb4: return cond
        //
        // Edge bb1->bb3 is critical and must be split so phi copy for `p`
        // does not execute on bb1->bb4.
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        let bb3 = func.alloc_block();
        let bb4 = func.alloc_block();
        func.entry = bb0;

        let cond = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();
        let p = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: cond,
            src: MirValue::Const(1),
        });
        func.block_mut(bb0).terminator = MirInst::Branch {
            cond,
            if_true: bb1,
            if_false: bb2,
        };

        func.block_mut(bb1).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::Const(11),
        });
        func.block_mut(bb1).terminator = MirInst::Branch {
            cond,
            if_true: bb3,
            if_false: bb4,
        };

        func.block_mut(bb2).instructions.push(MirInst::Copy {
            dst: v2,
            src: MirValue::Const(22),
        });
        func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

        func.block_mut(bb3).instructions.push(MirInst::Phi {
            dst: p,
            args: vec![(bb1, v1), (bb2, v2)],
        });
        func.block_mut(bb3).terminator = MirInst::Return {
            val: Some(MirValue::VReg(p)),
        };
        func.block_mut(bb4).terminator = MirInst::Return {
            val: Some(MirValue::VReg(cond)),
        };

        let old_block_count = func.blocks.len();
        let cfg = CFG::build(&func);
        let pass = SsaDestruction;
        pass.run(&mut func, &cfg);

        assert_eq!(
            func.blocks.len(),
            old_block_count + 1,
            "critical edge should be split with a new block"
        );

        let bb1_block = func.block(bb1);
        let split_id = match bb1_block.terminator {
            MirInst::Branch {
                if_true, if_false, ..
            } => {
                assert_eq!(if_false, bb4);
                assert_ne!(if_true, bb3);
                if_true
            }
            _ => panic!("expected bb1 to end in a branch"),
        };

        assert!(
            !bb1_block.instructions.iter().any(|inst| {
                matches!(
                    inst,
                    MirInst::Copy {
                        dst,
                        src: MirValue::VReg(src)
                    } if *dst == p && *src == v1
                )
            }),
            "bb1 should not contain bb1->bb3 phi copy directly"
        );

        let split = func.block(split_id);
        assert!(
            split.instructions.iter().any(|inst| {
                matches!(
                    inst,
                    MirInst::Copy {
                        dst,
                        src: MirValue::VReg(src)
                    } if *dst == p && *src == v1
                )
            }),
            "split block must contain the edge-local phi copy"
        );
        assert!(
            matches!(split.terminator, MirInst::Jump { target } if target == bb3),
            "split block should jump to phi block"
        );
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
