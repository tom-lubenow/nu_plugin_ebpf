use super::*;

impl<'a> MirToEbpfCompiler<'a> {
    /// Compile a LIR function
    pub(super) fn compile_function(&mut self, func: &LirFunction) -> Result<(), CompileError> {
        // Register allocation uses Chaitin-Briggs graph coloring for optimal results.

        // Use block order as listed; LIR is already low-level.
        let block_order: Vec<BlockId> = func.blocks.iter().map(|b| b.id).collect();

        // Emit function prologue: save R1 (context pointer) to R9
        // R1 contains the probe context (pt_regs for kprobe, etc.)
        // We save it to R9 which is callee-saved and not used by our register allocator
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R9, EbpfReg::R1));

        // Compile each block in CFG order
        for block_id in block_order {
            let block = func.block(block_id).clone();
            self.compile_block(&block)?;
        }

        Ok(())
    }

    /// Compile a basic block
    fn compile_block(&mut self, block: &LirBlock) -> Result<(), CompileError> {
        // Record block start offset
        self.block_offsets.insert(block.id, self.instructions.len());

        // Compile instructions
        for inst in &block.instructions {
            self.compile_instruction_with_spills(inst)?;
        }

        // Compile terminator
        self.compile_instruction_with_spills(&block.terminator)?;

        Ok(())
    }

    pub(super) fn compile_instruction_with_spills(
        &mut self,
        inst: &LirInst,
    ) -> Result<(), CompileError> {
        self.compile_instruction(inst)?;
        self.store_spilled_defs(inst);
        Ok(())
    }

    fn store_spilled_defs(&mut self, inst: &LirInst) {
        if matches!(inst, LirInst::ParallelMove { .. }) {
            return;
        }
        for dst in inst.defs() {
            let Some(&offset) = self.vreg_spills.get(&dst) else {
                continue;
            };
            if self.vreg_remat.contains_key(&dst) {
                continue;
            }
            let src_reg = self.vreg_to_phys.get(&dst).copied().unwrap_or(EbpfReg::R0);
            self.instructions
                .push(EbpfInsn::stxdw(EbpfReg::R10, offset, src_reg));
        }
    }

    /// Check if we have enough stack space
    pub(super) fn check_stack_space(&self, needed: i16) -> Result<(), CompileError> {
        if self.stack_offset - needed < -512 {
            Err(CompileError::StackOverflow)
        } else {
            Ok(())
        }
    }

    /// Fix up pending jumps after all blocks are compiled
    pub(super) fn fixup_jumps(&mut self) -> Result<(), CompileError> {
        for (insn_idx, target_block) in &self.pending_jumps {
            let target_offset = self
                .block_offsets
                .get(target_block)
                .copied()
                .ok_or_else(|| {
                    CompileError::UnsupportedInstruction(format!(
                        "Jump target block {:?} not found",
                        target_block
                    ))
                })?;

            // Calculate relative offset (target - source - 1)
            let rel_offset = (target_offset as i64 - *insn_idx as i64 - 1) as i16;

            // Update the jump instruction's offset field
            self.instructions[*insn_idx].offset = rel_offset;
        }
        Ok(())
    }

    /// Compile all subfunctions (BPF-to-BPF function calls)
    ///
    /// Each subfunction is appended after the main function.
    /// Subfunctions use the standard BPF calling convention:
    /// - R1-R5: arguments (up to 5)
    /// - R0: return value
    /// - Callee-saved: R6-R9, R10 (frame pointer)
    pub(super) fn compile_subfunctions(&mut self) -> Result<(), CompileError> {
        // Clone subfunctions to avoid borrowing issues
        let subfunctions: Vec<_> = self.lir.subfunctions.clone();

        for (idx, subfn) in subfunctions.iter().enumerate() {
            let subfn_id = SubfunctionId(idx as u32);
            self.current_types = self
                .program_types
                .subfunctions
                .get(idx)
                .cloned()
                .unwrap_or_default();

            // Record the start offset of this subfunction
            let start_offset = self.instructions.len();
            self.subfn_offsets.insert(subfn_id, start_offset);

            // Store temporary register/stack state
            let saved_vreg_to_phys = std::mem::take(&mut self.vreg_to_phys);
            let saved_vreg_spills = std::mem::take(&mut self.vreg_spills);
            let saved_vreg_remat = std::mem::take(&mut self.vreg_remat);
            let saved_slot_offsets = std::mem::take(&mut self.slot_offsets);
            let saved_stack_offset = self.stack_offset;
            let saved_block_offsets = std::mem::take(&mut self.block_offsets);
            let saved_pending_jumps = std::mem::take(&mut self.pending_jumps);
            let saved_callee_saved = std::mem::take(&mut self.callee_saved_offsets);

            // Prepare allocation and stack layout for this subfunction
            if subfn.param_count > 5 {
                return Err(CompileError::UnsupportedInstruction(format!(
                    "Subfunction {:?} has {} params; BPF supports at most 5",
                    subfn_id, subfn.param_count
                )));
            }
            self.prepare_function_state(
                subfn,
                self.available_regs.clone(),
                subfn.precolored.clone(),
            )?;

            // Emit callee-saved prologue for subfunction
            self.emit_callee_save_prologue()?;
            self.emit_param_moves(subfn)?;

            // Compile subfunction blocks
            // Note: subfunctions receive args in R1-R5 and save any used callee-saved regs.
            let block_order: Vec<BlockId> = subfn.blocks.iter().map(|b| b.id).collect();

            for block_id in block_order {
                let block = subfn.block(block_id).clone();
                self.compile_block(&block)?;
            }

            // Fix up jumps within this subfunction
            self.fixup_jumps()?;

            // Restore main function's register/stack state
            self.vreg_to_phys = saved_vreg_to_phys;
            self.vreg_spills = saved_vreg_spills;
            self.vreg_remat = saved_vreg_remat;
            self.slot_offsets = saved_slot_offsets;
            self.stack_offset = saved_stack_offset;
            self.block_offsets = saved_block_offsets;
            self.pending_jumps = saved_pending_jumps;
            self.callee_saved_offsets = saved_callee_saved;
        }

        Ok(())
    }

    /// Fix up subfunction call offsets
    ///
    /// BPF-to-BPF calls use relative offsets in the imm field.
    /// The offset is from the instruction after the call to the start of the target function.
    pub(super) fn fixup_subfn_calls(&mut self) -> Result<(), CompileError> {
        for (call_idx, subfn_id) in &self.subfn_calls {
            let subfn_offset = self.subfn_offsets.get(subfn_id).copied().ok_or_else(|| {
                CompileError::UnsupportedInstruction(format!(
                    "Subfunction {:?} not found",
                    subfn_id
                ))
            })?;

            // Calculate relative offset (target - source - 1)
            // For BPF calls, the offset is relative to the instruction after the call
            let rel_offset = (subfn_offset as i64 - *call_idx as i64 - 1) as i32;

            // Update the call instruction's imm field
            self.instructions[*call_idx].imm = rel_offset;
        }
        Ok(())
    }
}
