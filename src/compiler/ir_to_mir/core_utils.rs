use super::*;

impl<'a> HirToMirLowering<'a> {
    /// Get metadata for a register
    pub(super) fn get_metadata(&self, reg: RegId) -> Option<&RegMetadata> {
        self.reg_metadata.get(&reg.get())
    }

    /// Get or create metadata for a register
    pub(super) fn get_or_create_metadata(&mut self, reg: RegId) -> &mut RegMetadata {
        self.reg_metadata.entry(reg.get()).or_default()
    }

    /// Clear metadata for a register (when it's written to)
    /// Reserved for future use with more complex metadata tracking
    #[allow(dead_code)]
    pub(super) fn clear_metadata(&mut self, reg: RegId) {
        self.reg_metadata.remove(&reg.get());
    }

    /// Check if a register holds the context value
    pub(super) fn is_context_reg(&self, reg: RegId) -> bool {
        self.get_metadata(reg)
            .map(|m| m.is_context)
            .unwrap_or(false)
    }

    /// Get or create a VReg for a Nushell RegId
    pub(super) fn get_vreg(&mut self, reg: RegId) -> VReg {
        let reg_id = reg.get();
        if let Some(&vreg) = self.reg_map.get(&reg_id) {
            vreg
        } else {
            let vreg = self.func.alloc_vreg();
            self.reg_map.insert(reg_id, vreg);
            if let Some(hint) = self.current_type_hints.get(&reg_id) {
                self.vreg_type_hints
                    .entry(vreg)
                    .or_insert_with(|| hint.clone());
            }
            vreg
        }
    }

    /// Get the current block being built
    pub(super) fn current_block_mut(&mut self) -> &mut BasicBlock {
        self.func.block_mut(self.current_block)
    }

    /// Add an instruction to the current block
    pub(super) fn emit(&mut self, inst: MirInst) {
        self.current_block_mut().instructions.push(inst);
    }

    pub(super) fn stack_slot_size(&self, slot: StackSlotId) -> Option<usize> {
        self.func
            .stack_slots
            .iter()
            .find(|s| s.id == slot)
            .map(|s| s.size)
    }

    pub(super) fn ensure_string_slot_capacity(
        &mut self,
        slot: StackSlotId,
        required_len: usize,
    ) -> Result<usize, CompileError> {
        if required_len.saturating_add(1) > MAX_STRING_SIZE {
            return Err(CompileError::UnsupportedInstruction(format!(
                "string interpolation requires {} bytes (limit {})",
                required_len + 1,
                MAX_STRING_SIZE
            )));
        }

        let needed = align_to_eight(required_len.saturating_add(1))
            .min(MAX_STRING_SIZE)
            .max(16);
        let slot_entry = self
            .func
            .stack_slots
            .iter_mut()
            .find(|s| s.id == slot)
            .ok_or_else(|| CompileError::UnsupportedInstruction("string slot not found".into()))?;

        if needed > slot_entry.size {
            let old_size = slot_entry.size;
            slot_entry.size = needed;

            let mut offset = old_size;
            while offset < needed {
                self.emit(MirInst::StoreSlot {
                    slot,
                    offset: offset as i32,
                    val: MirValue::Const(0),
                    ty: MirType::U64,
                });
                offset += 8;
            }
        }

        Ok(needed)
    }

    /// Set the terminator for the current block
    pub(super) fn terminate(&mut self, inst: MirInst) {
        self.func.block_mut(self.current_block).terminator = inst;
    }
}
