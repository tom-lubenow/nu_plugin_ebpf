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
mod tests;
