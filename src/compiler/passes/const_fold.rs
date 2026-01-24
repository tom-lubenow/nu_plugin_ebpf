//! Constant Folding pass
//!
//! This pass evaluates constant expressions at compile time:
//! - Binary operations on constants
//! - Copy of constants (propagation)
//! - Simplifies branches on constant conditions

use std::collections::HashMap;

use super::MirPass;
use crate::compiler::cfg::CFG;
use crate::compiler::mir::{BinOpKind, MirFunction, MirInst, MirValue, UnaryOpKind, VReg};

/// Constant Folding pass
pub struct ConstantFolding;

impl MirPass for ConstantFolding {
    fn name(&self) -> &str {
        "const_fold"
    }

    fn run(&self, func: &mut MirFunction, _cfg: &CFG) -> bool {
        let mut changed = false;

        // Track known constant values
        let mut constants: HashMap<VReg, i64> = HashMap::new();

        // Process each block
        for block in &mut func.blocks {
            // Fold instructions
            for inst in &mut block.instructions {
                if self.fold_instruction(inst, &mut constants) {
                    changed = true;
                }
            }

            // Fold terminator (simplify constant branches)
            if self.fold_terminator(&mut block.terminator, &constants) {
                changed = true;
            }
        }

        changed
    }
}

impl ConstantFolding {
    /// Try to fold a single instruction
    fn fold_instruction(&self, inst: &mut MirInst, constants: &mut HashMap<VReg, i64>) -> bool {
        match inst {
            // Copy of constant - track it
            MirInst::Copy {
                dst,
                src: MirValue::Const(c),
            } => {
                constants.insert(*dst, *c);
                false // No change to the instruction itself
            }

            // Copy of known constant vreg - replace with constant
            MirInst::Copy {
                dst,
                src: MirValue::VReg(v),
            } => {
                if let Some(&c) = constants.get(v) {
                    constants.insert(*dst, c);
                    *inst = MirInst::Copy {
                        dst: *dst,
                        src: MirValue::Const(c),
                    };
                    true
                } else {
                    false
                }
            }

            // Binary operation with constant operands
            MirInst::BinOp { dst, op, lhs, rhs } => {
                let lhs_val = self.get_const_value(lhs, constants);
                let rhs_val = self.get_const_value(rhs, constants);

                match (lhs_val, rhs_val) {
                    (Some(l), Some(r)) => {
                        // Both operands are constants - evaluate at compile time
                        if let Some(result) = self.eval_binop(*op, l, r) {
                            constants.insert(*dst, result);
                            *inst = MirInst::Copy {
                                dst: *dst,
                                src: MirValue::Const(result),
                            };
                            true
                        } else {
                            false
                        }
                    }
                    (Some(l), None) => {
                        // LHS is constant - propagate only if not already a constant
                        if !matches!(lhs, MirValue::Const(_)) {
                            *lhs = MirValue::Const(l);
                            true
                        } else {
                            false
                        }
                    }
                    (None, Some(r)) => {
                        // RHS is constant - propagate only if not already a constant
                        if !matches!(rhs, MirValue::Const(_)) {
                            *rhs = MirValue::Const(r);
                            true
                        } else {
                            false
                        }
                    }
                    (None, None) => false,
                }
            }

            // Unary operation on constant
            MirInst::UnaryOp { dst, op, src } => {
                let src_val = self.get_const_value(src, constants);

                if let Some(s) = src_val
                    && let Some(result) = self.eval_unaryop(*op, s)
                {
                    constants.insert(*dst, result);
                    *inst = MirInst::Copy {
                        dst: *dst,
                        src: MirValue::Const(result),
                    };
                    return true;
                }
                false
            }

            _ => false,
        }
    }

    /// Try to simplify a terminator with constant condition
    fn fold_terminator(&self, term: &mut MirInst, constants: &HashMap<VReg, i64>) -> bool {
        match term {
            MirInst::Branch {
                cond,
                if_true,
                if_false,
            } => {
                if let Some(&c) = constants.get(cond) {
                    // Condition is known at compile time
                    let target = if c != 0 { *if_true } else { *if_false };
                    *term = MirInst::Jump { target };
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Get the constant value of an operand, if known
    fn get_const_value(&self, val: &MirValue, constants: &HashMap<VReg, i64>) -> Option<i64> {
        match val {
            MirValue::Const(c) => Some(*c),
            MirValue::VReg(v) => constants.get(v).copied(),
            MirValue::StackSlot(_) => None,
        }
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
    use crate::compiler::mir::BlockId;

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
        // bb2: return 0
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

        // The terminator should now be: Jump { target: bb1 }
        let block = func.block(func.entry);
        match &block.terminator {
            MirInst::Jump { target } => {
                assert_eq!(*target, BlockId(1)); // bb1
            }
            other => panic!("Expected Jump, got {:?}", other),
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
