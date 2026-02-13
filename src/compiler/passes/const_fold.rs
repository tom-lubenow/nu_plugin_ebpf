//! Constant Folding / SCCP pass
//!
//! This pass performs sparse conditional constant propagation (SCCP):
//! - Tracks per-vreg constant lattice values
//! - Tracks executable CFG edges from branch feasibility
//! - Folds constant expressions (including phi-derived constants)
//! - Simplifies branches and prunes unreachable blocks/phi inputs

use std::collections::{HashMap, HashSet};

use super::MirPass;
use crate::compiler::cfg::CFG;
use crate::compiler::mir::{BinOpKind, BlockId, MirFunction, MirInst, MirValue, UnaryOpKind, VReg};

/// Constant Folding pass (implemented as SCCP)
pub struct ConstantFolding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LatticeValue {
    /// Value has not been discovered yet
    Unknown,
    /// Value is provably a specific constant
    Constant(i64),
    /// Value is not a compile-time constant
    Overdefined,
}

#[derive(Debug, Default)]
struct SccpResult {
    values: HashMap<VReg, LatticeValue>,
    reachable_blocks: HashSet<BlockId>,
    executable_edges: HashSet<(BlockId, BlockId)>,
}

impl MirPass for ConstantFolding {
    fn name(&self) -> &str {
        "const_fold"
    }

    fn run(&self, func: &mut MirFunction, cfg: &CFG) -> bool {
        if func.blocks.is_empty() {
            return false;
        }

        let sccp = self.run_sccp(func, cfg);

        let mut changed = false;
        if self.rewrite_with_constants(func, &sccp.values, &sccp.executable_edges) {
            changed = true;
        }
        if self.remove_unreachable_blocks(func, &sccp.reachable_blocks) {
            changed = true;
        }

        changed
    }
}

impl ConstantFolding {
    fn run_sccp(&self, func: &MirFunction, cfg: &CFG) -> SccpResult {
        let mut result = SccpResult::default();

        if !func.has_block(cfg.entry) {
            return result;
        }

        result.reachable_blocks.insert(cfg.entry);

        let mut changed = true;
        while changed {
            changed = false;

            for &block_id in &cfg.rpo {
                if !result.reachable_blocks.contains(&block_id) {
                    continue;
                }

                let block = func.block(block_id);

                // Phi nodes are evaluated from executable incoming edges only.
                for inst in &block.instructions {
                    match inst {
                        MirInst::Phi { dst, args } => {
                            let lattice = self.eval_phi(
                                block_id,
                                args,
                                &result.executable_edges,
                                &result.values,
                            );
                            if self.update_lattice(&mut result.values, *dst, lattice) {
                                changed = true;
                            }
                        }
                        _ => {
                            if let Some(dst) = inst.def() {
                                let lattice = self.eval_instruction(inst, &result.values);
                                if self.update_lattice(&mut result.values, dst, lattice) {
                                    changed = true;
                                }
                            }
                        }
                    }
                }

                if self.mark_successors_executable(
                    block_id,
                    &block.terminator,
                    &result.values,
                    &mut result.reachable_blocks,
                    &mut result.executable_edges,
                ) {
                    changed = true;
                }
            }
        }

        result
    }

    fn eval_phi(
        &self,
        block_id: BlockId,
        args: &[(BlockId, VReg)],
        executable_edges: &HashSet<(BlockId, BlockId)>,
        values: &HashMap<VReg, LatticeValue>,
    ) -> LatticeValue {
        let mut merged = LatticeValue::Unknown;
        let mut any_incoming = false;

        for &(pred, src) in args {
            if !executable_edges.contains(&(pred, block_id)) {
                continue;
            }
            any_incoming = true;
            let src_val = values.get(&src).copied().unwrap_or(LatticeValue::Unknown);
            merged = Self::merge_lattice(merged, src_val);
            if merged == LatticeValue::Overdefined {
                return merged;
            }
        }

        if any_incoming {
            merged
        } else {
            LatticeValue::Unknown
        }
    }

    fn eval_instruction(
        &self,
        inst: &MirInst,
        values: &HashMap<VReg, LatticeValue>,
    ) -> LatticeValue {
        match inst {
            MirInst::Copy { src, .. } => self.operand_lattice(src, values),
            MirInst::BinOp { op, lhs, rhs, .. } => {
                let lhs_val = self.operand_lattice(lhs, values);
                let rhs_val = self.operand_lattice(rhs, values);

                match (lhs_val, rhs_val) {
                    (LatticeValue::Constant(l), LatticeValue::Constant(r)) => self
                        .eval_binop(*op, l, r)
                        .map(LatticeValue::Constant)
                        .unwrap_or(LatticeValue::Overdefined),
                    (LatticeValue::Overdefined, _) | (_, LatticeValue::Overdefined) => {
                        LatticeValue::Overdefined
                    }
                    _ => LatticeValue::Unknown,
                }
            }
            MirInst::UnaryOp { op, src, .. } => {
                let src_val = self.operand_lattice(src, values);
                match src_val {
                    LatticeValue::Constant(v) => self
                        .eval_unaryop(*op, v)
                        .map(LatticeValue::Constant)
                        .unwrap_or(LatticeValue::Overdefined),
                    LatticeValue::Overdefined => LatticeValue::Overdefined,
                    LatticeValue::Unknown => LatticeValue::Unknown,
                }
            }
            MirInst::Phi { .. } => unreachable!("phi is handled separately"),
            _ => LatticeValue::Overdefined,
        }
    }

    fn mark_successors_executable(
        &self,
        block_id: BlockId,
        term: &MirInst,
        values: &HashMap<VReg, LatticeValue>,
        reachable_blocks: &mut HashSet<BlockId>,
        executable_edges: &mut HashSet<(BlockId, BlockId)>,
    ) -> bool {
        let mut changed = false;

        match term {
            MirInst::Jump { target } => {
                if self.mark_edge(block_id, *target, reachable_blocks, executable_edges) {
                    changed = true;
                }
            }
            MirInst::Branch {
                cond,
                if_true,
                if_false,
            } => {
                match values.get(cond).copied().unwrap_or(LatticeValue::Unknown) {
                    LatticeValue::Constant(c) => {
                        let target = if c != 0 { *if_true } else { *if_false };
                        if self.mark_edge(block_id, target, reachable_blocks, executable_edges) {
                            changed = true;
                        }
                    }
                    // Unknown: defer edge executability until condition becomes known.
                    LatticeValue::Unknown => {}
                    // Overdefined: both outcomes are feasible.
                    LatticeValue::Overdefined => {
                        if self.mark_edge(block_id, *if_true, reachable_blocks, executable_edges) {
                            changed = true;
                        }
                        if self.mark_edge(block_id, *if_false, reachable_blocks, executable_edges) {
                            changed = true;
                        }
                    }
                }
            }
            MirInst::LoopHeader { body, exit, .. } => {
                if self.mark_edge(block_id, *body, reachable_blocks, executable_edges) {
                    changed = true;
                }
                if self.mark_edge(block_id, *exit, reachable_blocks, executable_edges) {
                    changed = true;
                }
            }
            MirInst::LoopBack { header, .. } => {
                if self.mark_edge(block_id, *header, reachable_blocks, executable_edges) {
                    changed = true;
                }
            }
            MirInst::Return { .. } | MirInst::TailCall { .. } | MirInst::Placeholder => {}
            _ => {}
        }

        changed
    }

    fn mark_edge(
        &self,
        from: BlockId,
        to: BlockId,
        reachable_blocks: &mut HashSet<BlockId>,
        executable_edges: &mut HashSet<(BlockId, BlockId)>,
    ) -> bool {
        let mut changed = false;
        if executable_edges.insert((from, to)) {
            changed = true;
        }
        if reachable_blocks.insert(to) {
            changed = true;
        }
        changed
    }

    fn update_lattice(
        &self,
        values: &mut HashMap<VReg, LatticeValue>,
        vreg: VReg,
        new_value: LatticeValue,
    ) -> bool {
        let current = values.get(&vreg).copied().unwrap_or(LatticeValue::Unknown);
        let merged = Self::merge_lattice(current, new_value);
        if merged != current {
            values.insert(vreg, merged);
            true
        } else {
            false
        }
    }

    fn merge_lattice(a: LatticeValue, b: LatticeValue) -> LatticeValue {
        match (a, b) {
            (LatticeValue::Overdefined, _) | (_, LatticeValue::Overdefined) => {
                LatticeValue::Overdefined
            }
            (LatticeValue::Unknown, x) | (x, LatticeValue::Unknown) => x,
            (LatticeValue::Constant(c1), LatticeValue::Constant(c2)) => {
                if c1 == c2 {
                    LatticeValue::Constant(c1)
                } else {
                    LatticeValue::Overdefined
                }
            }
        }
    }

    fn operand_lattice(
        &self,
        val: &MirValue,
        values: &HashMap<VReg, LatticeValue>,
    ) -> LatticeValue {
        match val {
            MirValue::Const(c) => LatticeValue::Constant(*c),
            MirValue::VReg(v) => values.get(v).copied().unwrap_or(LatticeValue::Unknown),
            MirValue::StackSlot(_) => LatticeValue::Overdefined,
        }
    }

    fn value_for_vreg(&self, vreg: VReg, values: &HashMap<VReg, LatticeValue>) -> MirValue {
        match values.get(&vreg).copied().unwrap_or(LatticeValue::Unknown) {
            LatticeValue::Constant(c) => MirValue::Const(c),
            _ => MirValue::VReg(vreg),
        }
    }

    fn const_for_vreg(&self, vreg: VReg, values: &HashMap<VReg, LatticeValue>) -> Option<i64> {
        match values.get(&vreg).copied().unwrap_or(LatticeValue::Unknown) {
            LatticeValue::Constant(c) => Some(c),
            _ => None,
        }
    }

    fn rewrite_with_constants(
        &self,
        func: &mut MirFunction,
        values: &HashMap<VReg, LatticeValue>,
        executable_edges: &HashSet<(BlockId, BlockId)>,
    ) -> bool {
        let mut changed = false;

        for block in &mut func.blocks {
            for inst in &mut block.instructions {
                if self.rewrite_instruction(inst, block.id, values, executable_edges) {
                    changed = true;
                }
            }

            if self.rewrite_terminator(&mut block.terminator, values) {
                changed = true;
            }
        }

        changed
    }

    fn rewrite_instruction(
        &self,
        inst: &mut MirInst,
        block_id: BlockId,
        values: &HashMap<VReg, LatticeValue>,
        executable_edges: &HashSet<(BlockId, BlockId)>,
    ) -> bool {
        let mut changed = false;

        if let MirInst::Phi { dst, args } = inst {
            let before = args.len();
            args.retain(|(pred, _)| executable_edges.contains(&(*pred, block_id)));
            if args.len() != before {
                changed = true;
            }

            if let Some(c) = self.const_for_vreg(*dst, values) {
                *inst = MirInst::Copy {
                    dst: *dst,
                    src: MirValue::Const(c),
                };
                return true;
            }

            if args.len() == 1 {
                let src = self.value_for_vreg(args[0].1, values);
                *inst = MirInst::Copy { dst: *dst, src };
                return true;
            }

            return changed;
        }

        if let Some(dst) = inst.def()
            && let Some(c) = self.const_for_vreg(dst, values)
        {
            match inst {
                MirInst::Copy {
                    dst: existing_dst,
                    src: MirValue::Const(existing_c),
                } if *existing_dst == dst && *existing_c == c => {}
                _ => {
                    *inst = MirInst::Copy {
                        dst,
                        src: MirValue::Const(c),
                    };
                    return true;
                }
            }
        }

        match inst {
            MirInst::Copy { src, .. } => {
                if self.rewrite_value(src, values) {
                    changed = true;
                }
            }
            MirInst::BinOp { lhs, rhs, .. } => {
                if self.rewrite_value(lhs, values) {
                    changed = true;
                }
                if self.rewrite_value(rhs, values) {
                    changed = true;
                }
            }
            MirInst::UnaryOp { src, .. } => {
                if self.rewrite_value(src, values) {
                    changed = true;
                }
            }
            MirInst::Store { val, .. }
            | MirInst::StoreSlot { val, .. }
            | MirInst::RecordStore { val, .. }
            | MirInst::StringAppend { val, .. } => {
                if self.rewrite_value(val, values) {
                    changed = true;
                }
            }
            MirInst::CallHelper { args, .. } => {
                for arg in args {
                    if self.rewrite_value(arg, values) {
                        changed = true;
                    }
                }
            }
            MirInst::ListGet { idx, .. } | MirInst::TailCall { index: idx, .. } => {
                if self.rewrite_value(idx, values) {
                    changed = true;
                }
            }
            _ => {}
        }

        changed
    }

    fn rewrite_terminator(&self, term: &mut MirInst, values: &HashMap<VReg, LatticeValue>) -> bool {
        match term {
            MirInst::Branch {
                cond,
                if_true,
                if_false,
            } => {
                if let Some(c) = self.const_for_vreg(*cond, values) {
                    let target = if c != 0 { *if_true } else { *if_false };
                    *term = MirInst::Jump { target };
                    true
                } else {
                    false
                }
            }
            MirInst::Return { val } => {
                if let Some(value) = val {
                    self.rewrite_value(value, values)
                } else {
                    false
                }
            }
            MirInst::TailCall { index, .. } => self.rewrite_value(index, values),
            _ => false,
        }
    }

    fn rewrite_value(&self, value: &mut MirValue, values: &HashMap<VReg, LatticeValue>) -> bool {
        if let MirValue::VReg(vreg) = value
            && let Some(c) = self.const_for_vreg(*vreg, values)
        {
            *value = MirValue::Const(c);
            return true;
        }
        false
    }

    fn remove_unreachable_blocks(
        &self,
        func: &mut MirFunction,
        reachable: &HashSet<BlockId>,
    ) -> bool {
        let before = func.blocks.len();
        func.blocks.retain(|block| reachable.contains(&block.id));
        func.blocks.len() < before
    }

    /// Evaluate a binary operation on constants
    fn eval_binop(&self, op: BinOpKind, lhs: i64, rhs: i64) -> Option<i64> {
        match op {
            BinOpKind::Add => Some(lhs.wrapping_add(rhs)),
            BinOpKind::Sub => Some(lhs.wrapping_sub(rhs)),
            BinOpKind::Mul => Some(lhs.wrapping_mul(rhs)),
            BinOpKind::Div => {
                if rhs == 0 {
                    None // Don't fold division by zero
                } else {
                    Some(lhs.wrapping_div(rhs))
                }
            }
            BinOpKind::Mod => {
                if rhs == 0 {
                    None
                } else {
                    Some(lhs.wrapping_rem(rhs))
                }
            }
            BinOpKind::And => Some(lhs & rhs),
            BinOpKind::Or => Some(lhs | rhs),
            BinOpKind::Xor => Some(lhs ^ rhs),
            BinOpKind::Shl => Some(lhs << (rhs & 63)),
            BinOpKind::Shr => Some(lhs >> (rhs & 63)),
            BinOpKind::Eq => Some(if lhs == rhs { 1 } else { 0 }),
            BinOpKind::Ne => Some(if lhs != rhs { 1 } else { 0 }),
            BinOpKind::Lt => Some(if lhs < rhs { 1 } else { 0 }),
            BinOpKind::Le => Some(if lhs <= rhs { 1 } else { 0 }),
            BinOpKind::Gt => Some(if lhs > rhs { 1 } else { 0 }),
            BinOpKind::Ge => Some(if lhs >= rhs { 1 } else { 0 }),
        }
    }

    /// Evaluate a unary operation on a constant
    fn eval_unaryop(&self, op: UnaryOpKind, src: i64) -> Option<i64> {
        match op {
            UnaryOpKind::Not => Some(if src == 0 { 1 } else { 0 }),
            UnaryOpKind::BitNot => Some(!src),
            UnaryOpKind::Neg => Some(src.wrapping_neg()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_constant_add_function() -> MirFunction {
        // v0 = 2
        // v1 = 3
        // v2 = v0 + v1  <- should fold to v2 = 5
        // return v2
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        func.entry = bb0;

        let v0 = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v0,
            src: MirValue::Const(2),
        });
        func.block_mut(bb0).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::Const(3),
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

    fn make_constant_branch_function() -> MirFunction {
        // v0 = 1
        // if v0 goto bb1 else bb2  <- should fold to: goto bb1
        // bb1: return 1
        // bb2: return 0 (unreachable)
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
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

        func.block_mut(bb1).terminator = MirInst::Return {
            val: Some(MirValue::Const(1)),
        };
        func.block_mut(bb2).terminator = MirInst::Return {
            val: Some(MirValue::Const(0)),
        };

        func
    }

    fn make_phi_constant_function() -> MirFunction {
        // bb0: c = helper(); branch c -> bb1, bb2
        // bb1: v1 = 5; jump bb3
        // bb2: v2 = 5; jump bb3
        // bb3: v3 = phi(v1:bb1, v2:bb2); v4 = v3 + 1; return v4
        let mut func = MirFunction::new();
        let bb0 = func.alloc_block();
        let bb1 = func.alloc_block();
        let bb2 = func.alloc_block();
        let bb3 = func.alloc_block();
        func.entry = bb0;

        let cond = func.alloc_vreg();
        let v1 = func.alloc_vreg();
        let v2 = func.alloc_vreg();
        let v3 = func.alloc_vreg();
        let v4 = func.alloc_vreg();

        func.block_mut(bb0).instructions.push(MirInst::CallHelper {
            dst: cond,
            helper: 14,
            args: vec![],
        });
        func.block_mut(bb0).terminator = MirInst::Branch {
            cond,
            if_true: bb1,
            if_false: bb2,
        };

        func.block_mut(bb1).instructions.push(MirInst::Copy {
            dst: v1,
            src: MirValue::Const(5),
        });
        func.block_mut(bb1).terminator = MirInst::Jump { target: bb3 };

        func.block_mut(bb2).instructions.push(MirInst::Copy {
            dst: v2,
            src: MirValue::Const(5),
        });
        func.block_mut(bb2).terminator = MirInst::Jump { target: bb3 };

        func.block_mut(bb3).instructions.push(MirInst::Phi {
            dst: v3,
            args: vec![(bb1, v1), (bb2, v2)],
        });
        func.block_mut(bb3).instructions.push(MirInst::BinOp {
            dst: v4,
            op: BinOpKind::Add,
            lhs: MirValue::VReg(v3),
            rhs: MirValue::Const(1),
        });
        func.block_mut(bb3).terminator = MirInst::Return {
            val: Some(MirValue::VReg(v4)),
        };

        func
    }

    #[test]
    fn test_fold_constant_add() {
        let mut func = make_constant_add_function();
        let cfg = CFG::build(&func);
        let cf = ConstantFolding;

        let changed = cf.run(&mut func, &cfg);

        assert!(changed);

        // The third instruction should now be: v2 = 5
        let block = func.block(func.entry);
        match &block.instructions[2] {
            MirInst::Copy {
                dst: _,
                src: MirValue::Const(5),
            } => {}
            other => panic!("Expected Copy with const 5, got {:?}", other),
        }
    }

    #[test]
    fn test_fold_constant_branch() {
        let mut func = make_constant_branch_function();
        let cfg = CFG::build(&func);
        let cf = ConstantFolding;

        let changed = cf.run(&mut func, &cfg);

        assert!(changed);

        // The entry terminator should now be: Jump { target: bb1 }
        let block = func.block(func.entry);
        match &block.terminator {
            MirInst::Jump { target } => {
                assert_eq!(*target, BlockId(1)); // bb1
            }
            other => panic!("Expected Jump, got {:?}", other),
        }

        // bb2 should be removed as unreachable.
        assert_eq!(func.blocks.len(), 2);
        assert!(!func.has_block(BlockId(2)));
    }

    #[test]
    fn test_phi_driven_constant_propagation() {
        let mut func = make_phi_constant_function();
        let cfg = CFG::build(&func);
        let cf = ConstantFolding;

        let changed = cf.run(&mut func, &cfg);
        assert!(changed);

        let bb3 = func.block(BlockId(3));
        match &bb3.instructions[0] {
            MirInst::Copy {
                src: MirValue::Const(5),
                ..
            } => {}
            other => panic!("Expected phi to fold to const copy, got {:?}", other),
        }

        match &bb3.instructions[1] {
            MirInst::Copy {
                src: MirValue::Const(6),
                ..
            } => {}
            other => panic!("Expected add to fold to const copy, got {:?}", other),
        }

        match &bb3.terminator {
            MirInst::Return {
                val: Some(MirValue::Const(6)),
            } => {}
            other => panic!("Expected return const 6, got {:?}", other),
        }
    }

    #[test]
    fn test_all_binops() {
        let cf = ConstantFolding;

        // Test various operations
        assert_eq!(cf.eval_binop(BinOpKind::Add, 5, 3), Some(8));
        assert_eq!(cf.eval_binop(BinOpKind::Sub, 5, 3), Some(2));
        assert_eq!(cf.eval_binop(BinOpKind::Mul, 5, 3), Some(15));
        assert_eq!(cf.eval_binop(BinOpKind::Div, 6, 2), Some(3));
        assert_eq!(cf.eval_binop(BinOpKind::Div, 5, 0), None); // Division by zero
        assert_eq!(cf.eval_binop(BinOpKind::Mod, 7, 3), Some(1));
        assert_eq!(cf.eval_binop(BinOpKind::And, 0b1010, 0b1100), Some(0b1000));
        assert_eq!(cf.eval_binop(BinOpKind::Or, 0b1010, 0b1100), Some(0b1110));
        assert_eq!(cf.eval_binop(BinOpKind::Xor, 0b1010, 0b1100), Some(0b0110));
        assert_eq!(cf.eval_binop(BinOpKind::Eq, 5, 5), Some(1));
        assert_eq!(cf.eval_binop(BinOpKind::Eq, 5, 3), Some(0));
        assert_eq!(cf.eval_binop(BinOpKind::Lt, 3, 5), Some(1));
        assert_eq!(cf.eval_binop(BinOpKind::Lt, 5, 3), Some(0));
    }

    #[test]
    fn test_unary_ops() {
        let cf = ConstantFolding;

        assert_eq!(cf.eval_unaryop(UnaryOpKind::Not, 0), Some(1));
        assert_eq!(cf.eval_unaryop(UnaryOpKind::Not, 1), Some(0));
        assert_eq!(cf.eval_unaryop(UnaryOpKind::Not, 42), Some(0));
        assert_eq!(cf.eval_unaryop(UnaryOpKind::Neg, 5), Some(-5));
        assert_eq!(cf.eval_unaryop(UnaryOpKind::BitNot, 0), Some(-1));
    }
}
