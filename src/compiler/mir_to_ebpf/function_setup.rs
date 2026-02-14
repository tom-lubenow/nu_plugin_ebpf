use super::*;

impl<'a> MirToEbpfCompiler<'a> {
    /// Run graph coloring register allocation for a function
    fn allocate_registers_for_function(
        &self,
        func: &LirFunction,
        available_regs: Vec<EbpfReg>,
        precolored: HashMap<VReg, EbpfReg>,
    ) -> ColoringResult {
        // Run graph coloring allocation
        let mut allocator = GraphColoringAllocator::new(available_regs);
        if !precolored.is_empty() {
            allocator.set_precolored(precolored);
        }
        let loop_depths = compute_loop_depths(func);
        allocator.allocate(func, Some(&loop_depths))
    }

    /// Layout stack slots and assign offsets for a function
    fn layout_stack_for_function(
        &self,
        func: &LirFunction,
        alloc: &ColoringResult,
    ) -> Result<
        (
            HashMap<StackSlotId, i16>,
            HashMap<VReg, i16>,
            i16,
            Option<i16>,
            Option<i16>,
        ),
        CompileError,
    > {
        let mut slots: Vec<StackSlot> = func.stack_slots.clone();
        let spill_base = slots.len() as u32;

        for (idx, slot) in alloc.spill_slots.iter().enumerate() {
            let mut slot = slot.clone();
            slot.id = StackSlotId(spill_base + idx as u32);
            slots.push(slot);
        }

        // Subfunction entry parameter shuffles are also parallel moves and may
        // contain cycles (e.g. R1 <-> R2), so they need the same temp slot.
        let needs_parallel_moves = Self::function_has_parallel_moves(func) || func.param_count > 0;
        let needs_scratch = needs_parallel_moves && Self::parallel_move_needs_scratch(func, alloc);
        let temp_slot_ids = if needs_parallel_moves {
            let base = spill_base + alloc.spill_slots.len() as u32;
            let cycle_id = StackSlotId(base);
            slots.push(StackSlot {
                id: cycle_id,
                size: 8,
                align: 8,
                kind: StackSlotKind::Spill,
                offset: None,
            });
            let scratch_id = if needs_scratch {
                let scratch_id = StackSlotId(base + 1);
                slots.push(StackSlot {
                    id: scratch_id,
                    size: 8,
                    align: 8,
                    kind: StackSlotKind::Spill,
                    offset: None,
                });
                Some(scratch_id)
            } else {
                None
            };
            Some((cycle_id, scratch_id))
        } else {
            None
        };

        // Sort slots by alignment (largest first) for better packing
        slots.sort_by(|a, b| b.align.cmp(&a.align).then(b.size.cmp(&a.size)));

        let mut stack_offset: i16 = 0;
        let mut slot_offsets: HashMap<StackSlotId, i16> = HashMap::new();

        for slot in slots {
            let aligned_size = slot.size.div_ceil(slot.align) * slot.align;
            stack_offset -= aligned_size as i16;
            if stack_offset < -512 {
                return Err(CompileError::StackOverflow);
            }
            slot_offsets.insert(slot.id, stack_offset);
        }

        let mut vreg_spills: HashMap<VReg, i16> = HashMap::new();
        for (vreg, slot_id) in &alloc.spills {
            let new_slot_id = StackSlotId(spill_base + slot_id.0);
            if let Some(&offset) = slot_offsets.get(&new_slot_id) {
                vreg_spills.insert(*vreg, offset);
            }
        }

        let (parallel_move_cycle_offset, parallel_move_scratch_offset) =
            if let Some((cycle_id, scratch_id)) = temp_slot_ids {
                let cycle = slot_offsets.get(&cycle_id).copied();
                let scratch = scratch_id.and_then(|id| slot_offsets.get(&id).copied());
                (cycle, scratch)
            } else {
                (None, None)
            };

        Ok((
            slot_offsets,
            vreg_spills,
            stack_offset,
            parallel_move_cycle_offset,
            parallel_move_scratch_offset,
        ))
    }

    fn function_has_parallel_moves(func: &LirFunction) -> bool {
        for block in &func.blocks {
            if block
                .instructions
                .iter()
                .any(|inst| matches!(inst, LirInst::ParallelMove { .. }))
            {
                return true;
            }
            if matches!(block.terminator, LirInst::ParallelMove { .. }) {
                return true;
            }
        }
        false
    }

    fn parallel_move_needs_scratch(func: &LirFunction, alloc: &ColoringResult) -> bool {
        #[derive(Clone, Copy)]
        enum Loc {
            Reg(EbpfReg),
            Stack,
        }

        let vreg_loc = |vreg: VReg| -> Loc {
            if alloc.spills.contains_key(&vreg) {
                return Loc::Stack;
            }
            if let Some(&reg) = alloc.coloring.get(&vreg) {
                return Loc::Reg(reg);
            }
            Loc::Reg(EbpfReg::R0)
        };

        for block in &func.blocks {
            let insts = block
                .instructions
                .iter()
                .chain(std::iter::once(&block.terminator));
            for inst in insts {
                if let LirInst::ParallelMove { moves } = inst {
                    let mut reg_sources = HashSet::new();
                    let mut reg_dests = Vec::new();
                    let mut has_stack = false;

                    for (dst, src) in moves {
                        let dst_loc = vreg_loc(*dst);
                        let src_loc = vreg_loc(*src);
                        if matches!(dst_loc, Loc::Stack) || matches!(src_loc, Loc::Stack) {
                            has_stack = true;
                        }
                        if let Loc::Reg(reg) = src_loc {
                            reg_sources.insert(reg);
                        }
                        if let Loc::Reg(reg) = dst_loc {
                            reg_dests.push(reg);
                        }
                    }

                    if has_stack {
                        let safe = reg_dests.iter().any(|r| !reg_sources.contains(r));
                        if !safe {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    pub(super) fn prepare_function_state(
        &mut self,
        func: &LirFunction,
        available_regs: Vec<EbpfReg>,
        precolored: HashMap<VReg, EbpfReg>,
    ) -> Result<ColoringResult, CompileError> {
        let alloc = self.allocate_registers_for_function(func, available_regs, precolored);
        let (
            slot_offsets,
            vreg_spills,
            stack_offset,
            parallel_move_cycle_offset,
            parallel_move_scratch_offset,
        ) = self.layout_stack_for_function(func, &alloc)?;
        let remat_spills = self.compute_rematerializable_spills(func, &alloc.spills);

        self.vreg_to_phys = alloc.coloring.clone();
        self.vreg_spills = vreg_spills;
        self.vreg_remat = remat_spills;
        self.slot_offsets = slot_offsets;
        self.stack_offset = stack_offset;
        self.parallel_move_cycle_offset = parallel_move_cycle_offset;
        self.parallel_move_scratch_offset = parallel_move_scratch_offset;
        self.callee_saved_offsets.clear();

        Ok(alloc)
    }

    pub(super) fn emit_callee_save_prologue(&mut self) -> Result<(), CompileError> {
        let mut regs: Vec<EbpfReg> = self
            .vreg_to_phys
            .values()
            .copied()
            .filter(|reg| matches!(reg, EbpfReg::R6 | EbpfReg::R7 | EbpfReg::R8 | EbpfReg::R9))
            .collect();
        regs.sort_by_key(|reg| reg.as_u8());
        regs.dedup();

        for reg in regs {
            self.check_stack_space(8)?;
            self.stack_offset -= 8;
            let offset = self.stack_offset;
            self.callee_saved_offsets.insert(reg, offset);
            self.instructions
                .push(EbpfInsn::stxdw(EbpfReg::R10, offset, reg));
        }

        Ok(())
    }

    pub(super) fn restore_callee_saved(&mut self) {
        if self.callee_saved_offsets.is_empty() {
            return;
        }
        let mut regs: Vec<EbpfReg> = self.callee_saved_offsets.keys().copied().collect();
        regs.sort_by_key(|reg| reg.as_u8());
        for reg in regs {
            if let Some(&offset) = self.callee_saved_offsets.get(&reg) {
                self.instructions
                    .push(EbpfInsn::ldxdw(reg, EbpfReg::R10, offset));
            }
        }
    }

    pub(super) fn emit_param_moves(&mut self, func: &LirFunction) -> Result<(), CompileError> {
        if func.param_count == 0 {
            return Ok(());
        }

        let arg_regs = [
            EbpfReg::R1,
            EbpfReg::R2,
            EbpfReg::R3,
            EbpfReg::R4,
            EbpfReg::R5,
        ];

        if func.param_count > arg_regs.len() {
            return Err(CompileError::UnsupportedInstruction(format!(
                "Function has {} params; BPF supports at most {}",
                func.param_count,
                arg_regs.len()
            )));
        }

        let cycle_temp = self.parallel_move_cycle_offset.ok_or_else(|| {
            CompileError::UnsupportedInstruction(
                "Parameter move lowering requires a temp stack slot".into(),
            )
        })?;

        let mut reg_moves: HashMap<EbpfReg, EbpfReg> = HashMap::new();

        for i in 0..func.param_count {
            let vreg = VReg(i as u32);
            let src = arg_regs[i];
            if let Some(&dst) = self.vreg_to_phys.get(&vreg) {
                if dst != src {
                    reg_moves.insert(src, dst);
                }
            } else if let Some(&offset) = self.vreg_spills.get(&vreg) {
                self.instructions
                    .push(EbpfInsn::stxdw(EbpfReg::R10, offset, src));
            }
        }

        while !reg_moves.is_empty() {
            let sources: HashSet<EbpfReg> = reg_moves.keys().copied().collect();
            let mut ready = Vec::new();

            for (&src, &dst) in &reg_moves {
                if !sources.contains(&dst) {
                    ready.push(src);
                }
            }

            if !ready.is_empty() {
                for src in ready {
                    if let Some(dst) = reg_moves.remove(&src) {
                        self.instructions.push(EbpfInsn::mov64_reg(dst, src));
                    }
                }
                continue;
            }

            // Cycle: spill one source to stack, rotate the cycle, then reload.
            let (&start_src, &start_dst) = reg_moves.iter().next().expect("cycle");
            self.instructions
                .push(EbpfInsn::stxdw(EbpfReg::R10, cycle_temp, start_src));
            reg_moves.remove(&start_src);

            let mut src = start_dst;
            while src != start_src {
                let dst = reg_moves.remove(&src).ok_or_else(|| {
                    CompileError::UnsupportedInstruction(
                        "Failed to lower cyclic parameter moves".into(),
                    )
                })?;
                self.instructions.push(EbpfInsn::mov64_reg(dst, src));
                src = dst;
            }

            self.instructions
                .push(EbpfInsn::ldxdw(start_dst, EbpfReg::R10, cycle_temp));
        }

        Ok(())
    }
}
