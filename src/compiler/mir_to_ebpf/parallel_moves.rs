use super::*;

impl<'a> MirToEbpfCompiler<'a> {
    pub(super) fn compile_parallel_move(
        &mut self,
        moves: &[(VReg, VReg)],
    ) -> Result<(), CompileError> {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        enum Loc {
            Reg(EbpfReg),
            Stack(i16),
        }

        #[derive(Clone, Copy)]
        struct Move {
            dst: Loc,
            src: Loc,
        }

        let mut pending: Vec<Move> = Vec::new();
        let mut reg_sources: HashSet<EbpfReg> = HashSet::new();
        let mut has_stack = false;

        for (dst_vreg, src_vreg) in moves {
            let dst_loc = if let Some(&phys) = self.vreg_to_phys.get(dst_vreg) {
                Loc::Reg(phys)
            } else if let Some(&offset) = self.vreg_spills.get(dst_vreg) {
                Loc::Stack(offset)
            } else {
                Loc::Reg(EbpfReg::R0)
            };

            let src_loc = if let Some(&phys) = self.vreg_to_phys.get(src_vreg) {
                Loc::Reg(phys)
            } else if let Some(&offset) = self.vreg_spills.get(src_vreg) {
                Loc::Stack(offset)
            } else {
                Loc::Reg(EbpfReg::R0)
            };

            if matches!(dst_loc, Loc::Stack(_)) || matches!(src_loc, Loc::Stack(_)) {
                has_stack = true;
            }
            if let Loc::Reg(reg) = src_loc {
                reg_sources.insert(reg);
            }

            if dst_loc != src_loc {
                pending.push(Move {
                    dst: dst_loc,
                    src: src_loc,
                });
            }
        }

        if pending.is_empty() {
            return Ok(());
        }

        let cycle_temp = self.parallel_move_cycle_offset.ok_or_else(|| {
            CompileError::UnsupportedInstruction("ParallelMove requires a temp stack slot".into())
        })?;
        let scratch_temp = self.parallel_move_scratch_offset;

        let mut scratch_reg = None;
        if has_stack {
            scratch_reg = pending
                .iter()
                .filter_map(|m| match m.dst {
                    Loc::Reg(reg) if !reg_sources.contains(&reg) => Some(reg),
                    _ => None,
                })
                .next();

            if scratch_reg.is_none() {
                scratch_reg = pending
                    .iter()
                    .find_map(|m| match m.dst {
                        Loc::Reg(reg) => Some(reg),
                        _ => None,
                    })
                    .or_else(|| {
                        pending.iter().find_map(|m| match m.src {
                            Loc::Reg(reg) => Some(reg),
                            _ => None,
                        })
                    });

                if let Some(reg) = scratch_reg {
                    if reg_sources.contains(&reg) {
                        let scratch_temp = scratch_temp.ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "ParallelMove requires a scratch temp slot".into(),
                            )
                        })?;
                        self.instructions
                            .push(EbpfInsn::stxdw(EbpfReg::R10, scratch_temp, reg));
                        for mv in &mut pending {
                            if mv.src == Loc::Reg(reg) {
                                mv.src = Loc::Stack(scratch_temp);
                            }
                        }
                        reg_sources.remove(&reg);
                    }
                } else {
                    return Err(CompileError::UnsupportedInstruction(
                        "ParallelMove with stack slots requires at least one register".into(),
                    ));
                }
            }
        }

        let temp_loc = Loc::Stack(cycle_temp);

        while !pending.is_empty() {
            let dsts: HashSet<Loc> = pending.iter().map(|m| m.dst).collect();
            let ready_idx = pending.iter().position(|m| !dsts.contains(&m.src));

            if let Some(idx) = ready_idx {
                let mv = pending.remove(idx);
                match (mv.dst, mv.src) {
                    (Loc::Reg(dst), Loc::Reg(src)) => {
                        if dst != src {
                            self.instructions.push(EbpfInsn::mov64_reg(dst, src));
                        }
                    }
                    (Loc::Reg(dst), Loc::Stack(src_off)) => {
                        self.instructions
                            .push(EbpfInsn::ldxdw(dst, EbpfReg::R10, src_off));
                    }
                    (Loc::Stack(dst_off), Loc::Reg(src)) => {
                        self.instructions
                            .push(EbpfInsn::stxdw(EbpfReg::R10, dst_off, src));
                    }
                    (Loc::Stack(dst_off), Loc::Stack(src_off)) => {
                        let temp_reg = scratch_reg.ok_or_else(|| {
                            CompileError::UnsupportedInstruction(
                                "ParallelMove stack-to-stack needs a scratch register".into(),
                            )
                        })?;
                        self.instructions
                            .push(EbpfInsn::ldxdw(temp_reg, EbpfReg::R10, src_off));
                        self.instructions
                            .push(EbpfInsn::stxdw(EbpfReg::R10, dst_off, temp_reg));
                    }
                }
                continue;
            }

            // Cycle: break by saving one source to temp
            let src = pending[0].src;
            match (temp_loc, src) {
                (Loc::Reg(temp), Loc::Reg(src_reg)) => {
                    self.instructions.push(EbpfInsn::mov64_reg(temp, src_reg));
                }
                (Loc::Reg(temp), Loc::Stack(off)) => {
                    self.instructions
                        .push(EbpfInsn::ldxdw(temp, EbpfReg::R10, off));
                }
                (Loc::Stack(temp_off), Loc::Reg(src_reg)) => {
                    self.instructions
                        .push(EbpfInsn::stxdw(EbpfReg::R10, temp_off, src_reg));
                }
                (Loc::Stack(temp_off), Loc::Stack(src_off)) => {
                    let temp_reg = scratch_reg.ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "ParallelMove stack source requires a scratch register".into(),
                        )
                    })?;
                    self.instructions
                        .push(EbpfInsn::ldxdw(temp_reg, EbpfReg::R10, src_off));
                    self.instructions
                        .push(EbpfInsn::stxdw(EbpfReg::R10, temp_off, temp_reg));
                }
            }
            pending[0].src = temp_loc;
        }

        Ok(())
    }
}
