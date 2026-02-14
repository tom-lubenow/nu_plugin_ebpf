use super::*;

impl<'a> MirToEbpfCompiler<'a> {
    pub(super) fn compile_load_ctx_field_inst(
        &mut self,
        dst: VReg,
        field: &CtxField,
        slot: Option<StackSlotId>,
    ) -> Result<(), CompileError> {
        let dst_reg = self.alloc_dst_reg(dst)?;
        self.compile_load_ctx_field(dst_reg, field, slot)
    }

    pub(super) fn compile_emit_event_inst(
        &mut self,
        data: VReg,
        size: usize,
    ) -> Result<(), CompileError> {
        self.needs_ringbuf = true;
        let data_reg = self.ensure_reg(data)?;
        self.compile_emit_event(data_reg, size)
    }

    pub(super) fn compile_emit_record_inst(
        &mut self,
        fields: &[RecordFieldDef],
    ) -> Result<(), CompileError> {
        self.needs_ringbuf = true;
        self.compile_emit_record(fields)
    }

    pub(super) fn compile_map_lookup_inst(
        &mut self,
        dst: VReg,
        map: &crate::compiler::mir::MapRef,
        key: VReg,
    ) -> Result<(), CompileError> {
        let dst_reg = self.alloc_dst_reg(dst)?;
        let key_reg = self.ensure_reg(key)?;
        self.compile_generic_map_lookup(dst, dst_reg, map, key, key_reg)
    }

    pub(super) fn compile_map_update_inst(
        &mut self,
        map: &crate::compiler::mir::MapRef,
        key: VReg,
        val: VReg,
        flags: u64,
    ) -> Result<(), CompileError> {
        if map.name == COUNTER_MAP_NAME {
            self.register_counter_map_kind(COUNTER_MAP_NAME, map.kind)?;
            let key_reg = self.ensure_reg(key)?;
            self.compile_counter_map_update(&map.name, key_reg)?;
        } else if map.name == STRING_COUNTER_MAP_NAME {
            self.register_counter_map_kind(STRING_COUNTER_MAP_NAME, map.kind)?;
            let key_reg = self.ensure_reg(key)?;
            self.compile_counter_map_update(&map.name, key_reg)?;
        } else {
            let key_reg = self.ensure_reg(key)?;
            let val_reg = self.ensure_reg(val)?;
            self.compile_generic_map_update(map, key, key_reg, val, val_reg, flags)?;
        }
        Ok(())
    }

    pub(super) fn compile_map_delete_inst(
        &mut self,
        map: &crate::compiler::mir::MapRef,
        key: VReg,
    ) -> Result<(), CompileError> {
        let key_reg = self.ensure_reg(key)?;
        self.compile_generic_map_delete(map, key, key_reg)
    }

    pub(super) fn compile_read_str_inst(
        &mut self,
        dst: StackSlotId,
        ptr: VReg,
        user_space: bool,
        max_len: usize,
    ) -> Result<(), CompileError> {
        let ptr_reg = self.ensure_reg(ptr)?;
        let offset = self.slot_offsets.get(&dst).copied().unwrap_or(0);
        self.compile_read_str(offset, ptr_reg, user_space, max_len)
    }

    pub(super) fn compile_histogram_inst(&mut self, value: VReg) -> Result<(), CompileError> {
        self.needs_histogram_map = true;
        let value_reg = self.ensure_reg(value)?;
        self.compile_histogram(value_reg)
    }

    pub(super) fn compile_start_timer_inst(&mut self) -> Result<(), CompileError> {
        self.needs_timestamp_map = true;
        self.compile_start_timer()
    }

    pub(super) fn compile_stop_timer_inst(&mut self, dst: VReg) -> Result<(), CompileError> {
        self.needs_timestamp_map = true;
        let dst_reg = self.alloc_dst_reg(dst)?;
        self.compile_stop_timer(dst_reg)
    }

    pub(super) fn compile_string_append_inst(
        &mut self,
        dst_buffer: StackSlotId,
        dst_len: VReg,
        val: &MirValue,
        val_type: &StringAppendType,
    ) -> Result<(), CompileError> {
        self.compile_string_append(dst_buffer, dst_len, val, val_type)
    }

    pub(super) fn compile_int_to_string_inst(
        &mut self,
        dst_buffer: StackSlotId,
        dst_len: VReg,
        val: VReg,
    ) -> Result<(), CompileError> {
        self.compile_int_to_string(dst_buffer, dst_len, val)
    }
}
