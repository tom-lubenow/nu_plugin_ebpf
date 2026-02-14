use super::*;

impl<'a> MirToEbpfCompiler<'a> {
    pub(super) fn compute_rematerializable_spills(
        &self,
        func: &LirFunction,
        spills: &HashMap<VReg, StackSlotId>,
    ) -> HashMap<VReg, RematExpr> {
        if spills.is_empty() {
            return HashMap::new();
        }

        let mut def_count: HashMap<VReg, usize> = HashMap::new();
        let mut single_defs: HashMap<VReg, LirInst> = HashMap::new();

        for block in &func.blocks {
            for inst in block
                .instructions
                .iter()
                .chain(std::iter::once(&block.terminator))
            {
                for dst in inst.defs() {
                    let count = def_count.entry(dst).or_insert(0);
                    *count += 1;
                    if *count == 1 {
                        single_defs.insert(dst, inst.clone());
                    } else {
                        single_defs.remove(&dst);
                    }
                }
            }
        }

        let mut known: HashMap<VReg, RematExpr> = HashMap::new();
        loop {
            let mut changed = false;
            for (&vreg, inst) in &single_defs {
                if known.contains_key(&vreg) {
                    continue;
                }
                if let Some(expr) = Self::derive_remat_expr(inst, &known) {
                    known.insert(vreg, expr);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        spills
            .keys()
            .filter_map(|vreg| known.get(vreg).copied().map(|expr| (*vreg, expr)))
            .collect()
    }

    fn derive_remat_expr(inst: &LirInst, known: &HashMap<VReg, RematExpr>) -> Option<RematExpr> {
        match inst {
            LirInst::Copy { src, .. } => Self::remat_expr_for_value(src, known),
            LirInst::UnaryOp { op, src, .. } => {
                let RematExpr::Const(value) = Self::remat_expr_for_value(src, known)? else {
                    return None;
                };
                Self::remat_const(Self::eval_const_unary(*op, value))
            }
            LirInst::BinOp { op, lhs, rhs, .. } => {
                let lhs_expr = Self::remat_expr_for_value(lhs, known)?;
                let rhs_expr = Self::remat_expr_for_value(rhs, known)?;
                match (lhs_expr, rhs_expr) {
                    (RematExpr::Const(lhs), RematExpr::Const(rhs)) => {
                        let value = Self::eval_const_binop(*op, lhs, rhs)?;
                        Self::remat_const(value)
                    }
                    (RematExpr::StackAddr { slot, addend }, RematExpr::Const(rhs)) => {
                        let rhs = i32::try_from(rhs).ok()?;
                        match op {
                            BinOpKind::Add => Some(RematExpr::StackAddr {
                                slot,
                                addend: addend.checked_add(rhs)?,
                            }),
                            BinOpKind::Sub => Some(RematExpr::StackAddr {
                                slot,
                                addend: addend.checked_sub(rhs)?,
                            }),
                            _ => None,
                        }
                    }
                    (RematExpr::Const(lhs), RematExpr::StackAddr { slot, addend }) => {
                        let lhs = i32::try_from(lhs).ok()?;
                        match op {
                            BinOpKind::Add => Some(RematExpr::StackAddr {
                                slot,
                                addend: lhs.checked_add(addend)?,
                            }),
                            _ => None,
                        }
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn remat_expr_for_value(
        value: &MirValue,
        known: &HashMap<VReg, RematExpr>,
    ) -> Option<RematExpr> {
        match value {
            MirValue::Const(v) => Self::remat_const(*v),
            MirValue::StackSlot(slot) => Some(RematExpr::StackAddr {
                slot: *slot,
                addend: 0,
            }),
            MirValue::VReg(vreg) => known.get(vreg).copied(),
        }
    }

    fn remat_const(value: i64) -> Option<RematExpr> {
        i32::try_from(value).ok()?;
        Some(RematExpr::Const(value))
    }

    fn eval_const_binop(op: BinOpKind, lhs: i64, rhs: i64) -> Option<i64> {
        match op {
            BinOpKind::Add => Some(lhs.wrapping_add(rhs)),
            BinOpKind::Sub => Some(lhs.wrapping_sub(rhs)),
            BinOpKind::Mul => Some(lhs.wrapping_mul(rhs)),
            BinOpKind::Div => {
                if rhs == 0 {
                    None
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

    fn eval_const_unary(op: UnaryOpKind, src: i64) -> i64 {
        match op {
            UnaryOpKind::Not => {
                if src == 0 {
                    1
                } else {
                    0
                }
            }
            UnaryOpKind::BitNot => !src,
            UnaryOpKind::Neg => src.wrapping_neg(),
        }
    }

    // === Register Allocation (Graph Coloring) ===
    //
    // Register allocation is performed upfront via graph coloring (Chaitin-Briggs).
    // At this point, vreg_to_phys contains the coloring and vreg_spills contains
    // spill slot offsets for vregs that couldn't be colored.

    /// Get the physical register for a virtual register
    /// Returns the pre-computed coloring, or handles spilled vregs
    fn alloc_reg(&mut self, vreg: VReg) -> Result<EbpfReg, CompileError> {
        // Check if this vreg was assigned a physical register by graph coloring
        if let Some(&phys) = self.vreg_to_phys.get(&vreg) {
            return Ok(phys);
        }

        // If the vreg was spilled, we need a temporary register
        // Use R0 as a scratch register for spilled values
        // (R0 is the return value register, safe to clobber mid-computation)
        Ok(EbpfReg::R0)
    }

    /// Allocate a register for a destination vreg
    pub(super) fn alloc_dst_reg(&mut self, vreg: VReg) -> Result<EbpfReg, CompileError> {
        self.alloc_reg(vreg)
    }

    fn emit_remat_expr(&mut self, dst: EbpfReg, expr: RematExpr) -> Result<(), CompileError> {
        match expr {
            RematExpr::Const(value) => {
                let imm = i32::try_from(value).map_err(|_| {
                    CompileError::UnsupportedInstruction(format!(
                        "rematerialized constant {} out of i32 range",
                        value
                    ))
                })?;
                self.instructions.push(EbpfInsn::mov64_imm(dst, imm));
            }
            RematExpr::StackAddr { slot, addend } => {
                let base = self.slot_offsets.get(&slot).copied().ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "stack slot {:?} not found for rematerialization",
                        slot
                    ))
                })?;
                let total = i32::from(base).checked_add(addend).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "rematerialized stack address offset overflow for {:?}",
                        slot
                    ))
                })?;
                self.instructions
                    .push(EbpfInsn::mov64_reg(dst, EbpfReg::R10));
                self.instructions.push(EbpfInsn::add64_imm(dst, total));
            }
        }
        Ok(())
    }

    /// Ensure a virtual register is in a physical register
    /// If the vreg is spilled, emit a reload instruction
    pub(super) fn ensure_reg(&mut self, vreg: VReg) -> Result<EbpfReg, CompileError> {
        // Check if this vreg has a physical register
        if let Some(&phys) = self.vreg_to_phys.get(&vreg) {
            return Ok(phys);
        }

        if let Some(expr) = self.vreg_remat.get(&vreg).copied() {
            let scratch = EbpfReg::R0;
            self.emit_remat_expr(scratch, expr)?;
            return Ok(scratch);
        }

        // The vreg is spilled - reload it to a scratch register
        if let Some(&offset) = self.vreg_spills.get(&vreg) {
            // Use R0 as scratch for reloads
            let scratch = EbpfReg::R0;
            self.instructions
                .push(EbpfInsn::ldxdw(scratch, EbpfReg::R10, offset));
            return Ok(scratch);
        }

        // Vreg wasn't allocated - this shouldn't happen with proper graph coloring
        // Fall back to R0 as scratch
        Ok(EbpfReg::R0)
    }
}
