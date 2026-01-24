//! Strength Reduction pass
//!
//! Converts expensive operations to cheaper equivalents:
//! - `x * 2^n` → `x << n`
//! - `x / 2^n` → `x >> n` (for positive divisor)
//! - `x % 2^n` → `x & (2^n - 1)`
//! - Identity operations (`x * 1`, `x + 0`, etc.) → `x`
//! - Zero operations (`x * 0`, `x & 0`) → `0`
//!
//! Algebraic identities (same operand on both sides):
//! - `x - x` → `0`
//! - `x ^ x` → `0`
//! - `x | x` → `x`
//! - `x & x` → `x`
//! - `x == x` → `1`
//! - `x != x` → `0`

use crate::compiler::cfg::CFG;
use crate::compiler::mir::{BinOpKind, MirFunction, MirInst, MirValue};

use super::MirPass;

/// Strength Reduction pass
pub struct StrengthReduction;

impl MirPass for StrengthReduction {
    fn name(&self) -> &str {
        "strength_reduce"
    }

    fn run(&self, func: &mut MirFunction, _cfg: &CFG) -> bool {
        let mut changed = false;

        for block in &mut func.blocks {
            for inst in &mut block.instructions {
                if let Some(new_inst) = self.reduce(inst) {
                    *inst = new_inst;
                    changed = true;
                }
            }
        }

        changed
    }
}

impl StrengthReduction {
    /// Try to reduce an instruction to a cheaper form
    fn reduce(&self, inst: &MirInst) -> Option<MirInst> {
        match inst {
            MirInst::BinOp { dst, op, lhs, rhs } => self.reduce_binop(*dst, *op, lhs, rhs),
            _ => None,
        }
    }

    /// Reduce operations where both operands are the same VReg
    fn reduce_same_operand(
        &self,
        dst: crate::compiler::mir::VReg,
        op: BinOpKind,
        lhs: &MirValue,
        rhs: &MirValue,
    ) -> Option<MirInst> {
        // Check if both operands are the same VReg
        let same_vreg = match (lhs, rhs) {
            (MirValue::VReg(l), MirValue::VReg(r)) if l == r => true,
            _ => false,
        };

        if !same_vreg {
            return None;
        }

        match op {
            // x - x = 0
            BinOpKind::Sub => Some(MirInst::Copy {
                dst,
                src: MirValue::Const(0),
            }),

            // x ^ x = 0
            BinOpKind::Xor => Some(MirInst::Copy {
                dst,
                src: MirValue::Const(0),
            }),

            // x | x = x
            BinOpKind::Or => Some(MirInst::Copy {
                dst,
                src: lhs.clone(),
            }),

            // x & x = x
            BinOpKind::And => Some(MirInst::Copy {
                dst,
                src: lhs.clone(),
            }),

            // x == x = 1 (always true)
            BinOpKind::Eq => Some(MirInst::Copy {
                dst,
                src: MirValue::Const(1),
            }),

            // x != x = 0 (always false)
            BinOpKind::Ne => Some(MirInst::Copy {
                dst,
                src: MirValue::Const(0),
            }),

            // x <= x = 1 (always true)
            BinOpKind::Le => Some(MirInst::Copy {
                dst,
                src: MirValue::Const(1),
            }),

            // x >= x = 1 (always true)
            BinOpKind::Ge => Some(MirInst::Copy {
                dst,
                src: MirValue::Const(1),
            }),

            // x < x = 0 (always false)
            BinOpKind::Lt => Some(MirInst::Copy {
                dst,
                src: MirValue::Const(0),
            }),

            // x > x = 0 (always false)
            BinOpKind::Gt => Some(MirInst::Copy {
                dst,
                src: MirValue::Const(0),
            }),

            _ => None,
        }
    }

    fn reduce_binop(
        &self,
        dst: crate::compiler::mir::VReg,
        op: BinOpKind,
        lhs: &MirValue,
        rhs: &MirValue,
    ) -> Option<MirInst> {
        // Check for same-operand algebraic identities first
        if let Some(result) = self.reduce_same_operand(dst, op, lhs, rhs) {
            return Some(result);
        }

        // Get constant value if RHS is constant
        let rhs_const = match rhs {
            MirValue::Const(c) => Some(*c),
            _ => None,
        };

        // Get constant value if LHS is constant
        let lhs_const = match lhs {
            MirValue::Const(c) => Some(*c),
            _ => None,
        };

        match op {
            // Multiplication reductions
            BinOpKind::Mul => {
                if let Some(c) = rhs_const {
                    // x * 0 = 0
                    if c == 0 {
                        return Some(MirInst::Copy {
                            dst,
                            src: MirValue::Const(0),
                        });
                    }
                    // x * 1 = x
                    if c == 1 {
                        return Some(MirInst::Copy {
                            dst,
                            src: lhs.clone(),
                        });
                    }
                    // x * 2^n = x << n
                    if c > 0 && (c & (c - 1)) == 0 {
                        let shift = c.trailing_zeros() as i64;
                        return Some(MirInst::BinOp {
                            dst,
                            op: BinOpKind::Shl,
                            lhs: lhs.clone(),
                            rhs: MirValue::Const(shift),
                        });
                    }
                }
                // 0 * x = 0, 1 * x = x
                if let Some(c) = lhs_const {
                    if c == 0 {
                        return Some(MirInst::Copy {
                            dst,
                            src: MirValue::Const(0),
                        });
                    }
                    if c == 1 {
                        return Some(MirInst::Copy {
                            dst,
                            src: rhs.clone(),
                        });
                    }
                }
                None
            }

            // Division reductions
            BinOpKind::Div => {
                if let Some(c) = rhs_const {
                    // x / 1 = x
                    if c == 1 {
                        return Some(MirInst::Copy {
                            dst,
                            src: lhs.clone(),
                        });
                    }
                    // x / 2^n = x >> n (for unsigned, which eBPF uses)
                    if c > 1 && (c & (c - 1)) == 0 {
                        let shift = c.trailing_zeros() as i64;
                        return Some(MirInst::BinOp {
                            dst,
                            op: BinOpKind::Shr,
                            lhs: lhs.clone(),
                            rhs: MirValue::Const(shift),
                        });
                    }
                }
                None
            }

            // Modulo reductions
            BinOpKind::Mod => {
                if let Some(c) = rhs_const {
                    // x % 1 = 0
                    if c == 1 {
                        return Some(MirInst::Copy {
                            dst,
                            src: MirValue::Const(0),
                        });
                    }
                    // x % 2^n = x & (2^n - 1)
                    if c > 1 && (c & (c - 1)) == 0 {
                        return Some(MirInst::BinOp {
                            dst,
                            op: BinOpKind::And,
                            lhs: lhs.clone(),
                            rhs: MirValue::Const(c - 1),
                        });
                    }
                }
                None
            }

            // Addition reductions
            BinOpKind::Add => {
                // x + 0 = x
                if rhs_const == Some(0) {
                    return Some(MirInst::Copy {
                        dst,
                        src: lhs.clone(),
                    });
                }
                // 0 + x = x
                if lhs_const == Some(0) {
                    return Some(MirInst::Copy {
                        dst,
                        src: rhs.clone(),
                    });
                }
                None
            }

            // Subtraction reductions
            BinOpKind::Sub => {
                // x - 0 = x
                if rhs_const == Some(0) {
                    return Some(MirInst::Copy {
                        dst,
                        src: lhs.clone(),
                    });
                }
                None
            }

            // Bitwise AND reductions
            BinOpKind::And => {
                // x & 0 = 0
                if rhs_const == Some(0) || lhs_const == Some(0) {
                    return Some(MirInst::Copy {
                        dst,
                        src: MirValue::Const(0),
                    });
                }
                // x & -1 = x (all bits set)
                if rhs_const == Some(-1) {
                    return Some(MirInst::Copy {
                        dst,
                        src: lhs.clone(),
                    });
                }
                if lhs_const == Some(-1) {
                    return Some(MirInst::Copy {
                        dst,
                        src: rhs.clone(),
                    });
                }
                None
            }

            // Bitwise OR reductions
            BinOpKind::Or => {
                // x | 0 = x
                if rhs_const == Some(0) {
                    return Some(MirInst::Copy {
                        dst,
                        src: lhs.clone(),
                    });
                }
                if lhs_const == Some(0) {
                    return Some(MirInst::Copy {
                        dst,
                        src: rhs.clone(),
                    });
                }
                // x | -1 = -1
                if rhs_const == Some(-1) || lhs_const == Some(-1) {
                    return Some(MirInst::Copy {
                        dst,
                        src: MirValue::Const(-1),
                    });
                }
                None
            }

            // Bitwise XOR reductions
            BinOpKind::Xor => {
                // x ^ 0 = x
                if rhs_const == Some(0) {
                    return Some(MirInst::Copy {
                        dst,
                        src: lhs.clone(),
                    });
                }
                if lhs_const == Some(0) {
                    return Some(MirInst::Copy {
                        dst,
                        src: rhs.clone(),
                    });
                }
                None
            }

            // Shift reductions
            BinOpKind::Shl | BinOpKind::Shr => {
                // x << 0 = x, x >> 0 = x
                if rhs_const == Some(0) {
                    return Some(MirInst::Copy {
                        dst,
                        src: lhs.clone(),
                    });
                }
                None
            }

            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::mir::MirValue;

    #[test]
    fn test_mul_by_power_of_two() {
        let sr = StrengthReduction;
        let dst = crate::compiler::mir::VReg(0);
        let lhs = MirValue::VReg(crate::compiler::mir::VReg(1));

        // x * 8 -> x << 3
        let inst = MirInst::BinOp {
            dst,
            op: BinOpKind::Mul,
            lhs: lhs.clone(),
            rhs: MirValue::Const(8),
        };

        let reduced = sr.reduce(&inst).unwrap();
        match reduced {
            MirInst::BinOp {
                op: BinOpKind::Shl,
                rhs: MirValue::Const(3),
                ..
            } => {}
            _ => panic!("Expected shift left by 3, got {:?}", reduced),
        }
    }

    #[test]
    fn test_div_by_power_of_two() {
        let sr = StrengthReduction;
        let dst = crate::compiler::mir::VReg(0);
        let lhs = MirValue::VReg(crate::compiler::mir::VReg(1));

        // x / 16 -> x >> 4
        let inst = MirInst::BinOp {
            dst,
            op: BinOpKind::Div,
            lhs: lhs.clone(),
            rhs: MirValue::Const(16),
        };

        let reduced = sr.reduce(&inst).unwrap();
        match reduced {
            MirInst::BinOp {
                op: BinOpKind::Shr,
                rhs: MirValue::Const(4),
                ..
            } => {}
            _ => panic!("Expected shift right by 4, got {:?}", reduced),
        }
    }

    #[test]
    fn test_mod_by_power_of_two() {
        let sr = StrengthReduction;
        let dst = crate::compiler::mir::VReg(0);
        let lhs = MirValue::VReg(crate::compiler::mir::VReg(1));

        // x % 8 -> x & 7
        let inst = MirInst::BinOp {
            dst,
            op: BinOpKind::Mod,
            lhs: lhs.clone(),
            rhs: MirValue::Const(8),
        };

        let reduced = sr.reduce(&inst).unwrap();
        match reduced {
            MirInst::BinOp {
                op: BinOpKind::And,
                rhs: MirValue::Const(7),
                ..
            } => {}
            _ => panic!("Expected AND with 7, got {:?}", reduced),
        }
    }

    #[test]
    fn test_mul_by_zero() {
        let sr = StrengthReduction;
        let dst = crate::compiler::mir::VReg(0);
        let lhs = MirValue::VReg(crate::compiler::mir::VReg(1));

        // x * 0 -> 0
        let inst = MirInst::BinOp {
            dst,
            op: BinOpKind::Mul,
            lhs: lhs.clone(),
            rhs: MirValue::Const(0),
        };

        let reduced = sr.reduce(&inst).unwrap();
        match reduced {
            MirInst::Copy {
                src: MirValue::Const(0),
                ..
            } => {}
            _ => panic!("Expected copy of 0, got {:?}", reduced),
        }
    }

    #[test]
    fn test_mul_by_one() {
        let sr = StrengthReduction;
        let dst = crate::compiler::mir::VReg(0);
        let lhs = MirValue::VReg(crate::compiler::mir::VReg(1));

        // x * 1 -> x
        let inst = MirInst::BinOp {
            dst,
            op: BinOpKind::Mul,
            lhs: lhs.clone(),
            rhs: MirValue::Const(1),
        };

        let reduced = sr.reduce(&inst).unwrap();
        match reduced {
            MirInst::Copy { src, .. } => assert_eq!(src, lhs),
            _ => panic!("Expected copy of lhs, got {:?}", reduced),
        }
    }

    #[test]
    fn test_add_zero() {
        let sr = StrengthReduction;
        let dst = crate::compiler::mir::VReg(0);
        let lhs = MirValue::VReg(crate::compiler::mir::VReg(1));

        // x + 0 -> x
        let inst = MirInst::BinOp {
            dst,
            op: BinOpKind::Add,
            lhs: lhs.clone(),
            rhs: MirValue::Const(0),
        };

        let reduced = sr.reduce(&inst).unwrap();
        match reduced {
            MirInst::Copy { src, .. } => assert_eq!(src, lhs),
            _ => panic!("Expected copy of lhs, got {:?}", reduced),
        }
    }

    #[test]
    fn test_no_reduction_for_non_power_of_two() {
        let sr = StrengthReduction;
        let dst = crate::compiler::mir::VReg(0);
        let lhs = MirValue::VReg(crate::compiler::mir::VReg(1));

        // x * 7 -> no change
        let inst = MirInst::BinOp {
            dst,
            op: BinOpKind::Mul,
            lhs: lhs.clone(),
            rhs: MirValue::Const(7),
        };

        assert!(sr.reduce(&inst).is_none());
    }

    // Algebraic identity tests

    #[test]
    fn test_x_sub_x() {
        let sr = StrengthReduction;
        let dst = crate::compiler::mir::VReg(0);
        let x = crate::compiler::mir::VReg(1);

        // x - x -> 0
        let inst = MirInst::BinOp {
            dst,
            op: BinOpKind::Sub,
            lhs: MirValue::VReg(x),
            rhs: MirValue::VReg(x),
        };

        let reduced = sr.reduce(&inst).unwrap();
        match reduced {
            MirInst::Copy {
                src: MirValue::Const(0),
                ..
            } => {}
            _ => panic!("Expected x - x = 0, got {:?}", reduced),
        }
    }

    #[test]
    fn test_x_xor_x() {
        let sr = StrengthReduction;
        let dst = crate::compiler::mir::VReg(0);
        let x = crate::compiler::mir::VReg(1);

        // x ^ x -> 0
        let inst = MirInst::BinOp {
            dst,
            op: BinOpKind::Xor,
            lhs: MirValue::VReg(x),
            rhs: MirValue::VReg(x),
        };

        let reduced = sr.reduce(&inst).unwrap();
        match reduced {
            MirInst::Copy {
                src: MirValue::Const(0),
                ..
            } => {}
            _ => panic!("Expected x ^ x = 0, got {:?}", reduced),
        }
    }

    #[test]
    fn test_x_or_x() {
        let sr = StrengthReduction;
        let dst = crate::compiler::mir::VReg(0);
        let x = crate::compiler::mir::VReg(1);

        // x | x -> x
        let inst = MirInst::BinOp {
            dst,
            op: BinOpKind::Or,
            lhs: MirValue::VReg(x),
            rhs: MirValue::VReg(x),
        };

        let reduced = sr.reduce(&inst).unwrap();
        match reduced {
            MirInst::Copy {
                src: MirValue::VReg(v),
                ..
            } => assert_eq!(v, x, "Expected x | x = x"),
            _ => panic!("Expected x | x = x, got {:?}", reduced),
        }
    }

    #[test]
    fn test_x_and_x() {
        let sr = StrengthReduction;
        let dst = crate::compiler::mir::VReg(0);
        let x = crate::compiler::mir::VReg(1);

        // x & x -> x
        let inst = MirInst::BinOp {
            dst,
            op: BinOpKind::And,
            lhs: MirValue::VReg(x),
            rhs: MirValue::VReg(x),
        };

        let reduced = sr.reduce(&inst).unwrap();
        match reduced {
            MirInst::Copy {
                src: MirValue::VReg(v),
                ..
            } => assert_eq!(v, x, "Expected x & x = x"),
            _ => panic!("Expected x & x = x, got {:?}", reduced),
        }
    }

    #[test]
    fn test_x_eq_x() {
        let sr = StrengthReduction;
        let dst = crate::compiler::mir::VReg(0);
        let x = crate::compiler::mir::VReg(1);

        // x == x -> 1
        let inst = MirInst::BinOp {
            dst,
            op: BinOpKind::Eq,
            lhs: MirValue::VReg(x),
            rhs: MirValue::VReg(x),
        };

        let reduced = sr.reduce(&inst).unwrap();
        match reduced {
            MirInst::Copy {
                src: MirValue::Const(1),
                ..
            } => {}
            _ => panic!("Expected x == x = 1, got {:?}", reduced),
        }
    }

    #[test]
    fn test_x_ne_x() {
        let sr = StrengthReduction;
        let dst = crate::compiler::mir::VReg(0);
        let x = crate::compiler::mir::VReg(1);

        // x != x -> 0
        let inst = MirInst::BinOp {
            dst,
            op: BinOpKind::Ne,
            lhs: MirValue::VReg(x),
            rhs: MirValue::VReg(x),
        };

        let reduced = sr.reduce(&inst).unwrap();
        match reduced {
            MirInst::Copy {
                src: MirValue::Const(0),
                ..
            } => {}
            _ => panic!("Expected x != x = 0, got {:?}", reduced),
        }
    }

    #[test]
    fn test_x_le_x() {
        let sr = StrengthReduction;
        let dst = crate::compiler::mir::VReg(0);
        let x = crate::compiler::mir::VReg(1);

        // x <= x -> 1
        let inst = MirInst::BinOp {
            dst,
            op: BinOpKind::Le,
            lhs: MirValue::VReg(x),
            rhs: MirValue::VReg(x),
        };

        let reduced = sr.reduce(&inst).unwrap();
        match reduced {
            MirInst::Copy {
                src: MirValue::Const(1),
                ..
            } => {}
            _ => panic!("Expected x <= x = 1, got {:?}", reduced),
        }
    }

    #[test]
    fn test_x_lt_x() {
        let sr = StrengthReduction;
        let dst = crate::compiler::mir::VReg(0);
        let x = crate::compiler::mir::VReg(1);

        // x < x -> 0
        let inst = MirInst::BinOp {
            dst,
            op: BinOpKind::Lt,
            lhs: MirValue::VReg(x),
            rhs: MirValue::VReg(x),
        };

        let reduced = sr.reduce(&inst).unwrap();
        match reduced {
            MirInst::Copy {
                src: MirValue::Const(0),
                ..
            } => {}
            _ => panic!("Expected x < x = 0, got {:?}", reduced),
        }
    }

    #[test]
    fn test_different_vregs_no_reduction() {
        let sr = StrengthReduction;
        let dst = crate::compiler::mir::VReg(0);
        let x = crate::compiler::mir::VReg(1);
        let y = crate::compiler::mir::VReg(2);

        // x - y -> no change (different vregs)
        let inst = MirInst::BinOp {
            dst,
            op: BinOpKind::Sub,
            lhs: MirValue::VReg(x),
            rhs: MirValue::VReg(y),
        };

        assert!(
            sr.reduce(&inst).is_none(),
            "Different vregs should not reduce"
        );
    }
}
