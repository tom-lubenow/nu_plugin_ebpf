use super::*;

impl<'a> HirToMirLowering<'a> {
    pub(super) fn fixed_copy_chunk(remaining: usize, offsets: &[usize]) -> (MirType, usize) {
        for (size, ty) in [
            (8usize, MirType::U64),
            (4usize, MirType::U32),
            (2usize, MirType::U16),
            (1usize, MirType::U8),
        ] {
            if remaining >= size && offsets.iter().all(|offset| offset % size == 0) {
                return (ty, size);
            }
        }
        (MirType::U8, 1)
    }

    pub(super) fn emit_ptr_copy(
        &mut self,
        dst_ptr: VReg,
        src_ptr: VReg,
        size: usize,
    ) -> Result<(), CompileError> {
        self.emit_ptr_copy_with_offsets(dst_ptr, 0, src_ptr, 0, size)
    }

    pub(super) fn emit_ptr_copy_with_offsets(
        &mut self,
        dst_ptr: VReg,
        dst_offset: usize,
        src_ptr: VReg,
        src_offset: usize,
        size: usize,
    ) -> Result<(), CompileError> {
        let mut offset = 0usize;
        while offset < size {
            let (chunk_ty, chunk_size) =
                Self::fixed_copy_chunk(size - offset, &[dst_offset + offset, src_offset + offset]);
            let tmp = self.func.alloc_vreg();
            self.emit(MirInst::Load {
                dst: tmp,
                ptr: src_ptr,
                offset: (src_offset + offset) as i32,
                ty: chunk_ty.clone(),
            });
            self.vreg_type_hints.insert(tmp, chunk_ty.clone());
            self.emit(MirInst::Store {
                ptr: dst_ptr,
                offset: (dst_offset + offset) as i32,
                val: MirValue::VReg(tmp),
                ty: chunk_ty,
            });
            offset += chunk_size;
        }
        Ok(())
    }

    pub(super) fn emit_ptr_zero(
        &mut self,
        dst_ptr: VReg,
        dst_offset: usize,
        size: usize,
    ) -> Result<(), CompileError> {
        let mut offset = 0usize;
        while offset < size {
            let (chunk_ty, chunk_size) =
                Self::fixed_copy_chunk(size - offset, &[dst_offset + offset]);
            self.emit(MirInst::Store {
                ptr: dst_ptr,
                offset: (dst_offset + offset) as i32,
                val: MirValue::Const(0),
                ty: chunk_ty,
            });
            offset += chunk_size;
        }
        Ok(())
    }

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

    pub(super) fn assign_fresh_vreg(&mut self, reg: RegId) -> VReg {
        let reg_id = reg.get();
        let vreg = self.func.alloc_vreg();
        let had_mapping = self.reg_map.insert(reg_id, vreg).is_some();
        if !had_mapping && let Some(hint) = self.current_type_hints.get(&reg_id) {
            self.vreg_type_hints
                .entry(vreg)
                .or_insert_with(|| hint.clone());
        }
        vreg
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

    pub(super) fn record_stack_slot_type(&mut self, slot: StackSlotId, ty: MirType) {
        self.stack_slot_type_hints.entry(slot).or_insert(ty);
    }

    pub(super) fn record_list_buffer_slot_type(&mut self, slot: StackSlotId, max_len: usize) {
        self.record_stack_slot_type(
            slot,
            MirType::Array {
                elem: Box::new(MirType::I64),
                len: max_len.saturating_add(1),
            },
        );
    }

    pub(super) fn stored_generic_map_value_type(&self, ty: &MirType) -> MirType {
        match ty {
            MirType::Ptr {
                pointee,
                address_space:
                    crate::compiler::mir::AddressSpace::Stack | crate::compiler::mir::AddressSpace::Map,
            } if matches!(
                pointee.as_ref(),
                MirType::Array { .. } | MirType::Struct { .. }
            ) =>
            {
                pointee.as_ref().clone()
            }
            _ => ty.clone(),
        }
    }

    pub(super) fn register_named_map_value_type(&mut self, map: &MapRef, ty: &MirType) {
        let ty = self.stored_generic_map_value_type(ty);
        if self.conflicting_map_value_types.contains(map) {
            return;
        }

        match self.map_value_types.get(map) {
            Some(existing) if existing != &ty => {
                self.map_value_types.remove(map);
                self.conflicting_map_value_types.insert(map.clone());
            }
            Some(_) => {}
            None => {
                self.map_value_types.insert(map.clone(), ty);
            }
        }
    }

    pub(super) fn named_map_value_type(&self, map: &MapRef) -> Option<&MirType> {
        if self.conflicting_map_value_types.contains(map) {
            None
        } else {
            self.map_value_types.get(map)
        }
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
            self.stack_slot_type_hints.insert(
                slot,
                MirType::Array {
                    elem: Box::new(MirType::U8),
                    len: needed,
                },
            );

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
