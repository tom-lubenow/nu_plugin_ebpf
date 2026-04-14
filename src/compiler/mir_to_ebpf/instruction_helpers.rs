use super::*;
use crate::compiler::mir::AddressSpace;
use crate::compiler::mir::CtxStoreTarget;

impl<'a> MirToEbpfCompiler<'a> {
    fn validate_counter_key_operand(&self, map_name: &str, key: VReg) -> Result<(), CompileError> {
        if map_name == COUNTER_MAP_NAME {
            if let Some(MirType::Ptr {
                pointee,
                address_space,
            }) = self.current_types.get(&key)
                && matches!(address_space, AddressSpace::Stack | AddressSpace::Map)
                && matches!(
                    pointee.as_ref(),
                    MirType::Array { .. } | MirType::Struct { .. }
                )
            {
                return Err(CompileError::UnsupportedInstruction(
                    "counters only supports scalar keys; aggregate byte-buffer keys must use bytes_counters".into(),
                ));
            }
            return Ok(());
        }

        if map_name != STRING_COUNTER_MAP_NAME && map_name != BYTES_COUNTER_MAP_NAME {
            return Ok(());
        }

        let Some(MirType::Ptr {
            pointee,
            address_space,
        }) = self.current_types.get(&key)
        else {
            return Ok(());
        };

        if !matches!(address_space, AddressSpace::Stack | AddressSpace::Map) {
            return Ok(());
        }

        match pointee.as_ref() {
            MirType::Array { .. } if pointee.byte_array_len() == Some(16) => Ok(()),
            MirType::Array { .. } | MirType::Struct { .. }
                if map_name == BYTES_COUNTER_MAP_NAME =>
            {
                Ok(())
            }
            MirType::Array { .. } | MirType::Struct { .. } => {
                Err(CompileError::UnsupportedInstruction(
                    "str_counters only supports 16-byte string keys (e.g. $ctx.comm)".into(),
                ))
            }
            _ => Ok(()),
        }
    }

    pub(super) fn compile_load_ctx_field_inst(
        &mut self,
        dst: VReg,
        field: &CtxField,
        slot: Option<StackSlotId>,
    ) -> Result<(), CompileError> {
        let dst_reg = self.alloc_dst_reg(dst)?;
        self.compile_load_ctx_field(dst_reg, field, slot)
    }

    pub(super) fn compile_store_ctx_field_inst(
        &mut self,
        target: &CtxStoreTarget,
        val: &MirValue,
        ty: &MirType,
    ) -> Result<(), CompileError> {
        let size = ty.size();
        if !matches!(size, 4 | 8) {
            return Err(CompileError::UnsupportedInstruction(format!(
                "writable context fields currently require a 4-byte or 8-byte scalar store, got {:?}",
                ty
            )));
        }
        let Some(ctx) = self.probe_ctx else {
            return Err(CompileError::UnsupportedInstruction(
                target.missing_context_error().into(),
            ));
        };
        ctx.validate_ctx_store_target(target)?;
        let val_reg = self.value_to_reg(val)?;
        let (offset, store_reg) = match target {
            CtxStoreTarget::SockOpsReply => (Self::bpf_sock_ops_args_offset(), val_reg),
            CtxStoreTarget::SockOpsReplyLong(index) => (
                Self::bpf_sock_ops_args_offset()
                    + i16::from(*index).checked_mul(4).ok_or_else(|| {
                        CompileError::UnsupportedInstruction(
                            "sock_ops replylong index overflowed".into(),
                        )
                    })?,
                val_reg,
            ),
            CtxStoreTarget::SkbTstamp => (Self::sk_buff_tstamp_offset(), val_reg),
            CtxStoreTarget::SysctlFilePos => (Self::bpf_sysctl_offsets().1, val_reg),
            CtxStoreTarget::SockoptLevel => (Self::bpf_sockopt_offsets().3, val_reg),
            CtxStoreTarget::SockoptOptname => (Self::bpf_sockopt_offsets().4, val_reg),
            CtxStoreTarget::SockoptOptlen => (Self::bpf_sockopt_offsets().5, val_reg),
            CtxStoreTarget::SockoptRetval => (Self::bpf_sockopt_offsets().6, val_reg),
            CtxStoreTarget::CgroupSockAddrUserIp4 => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R0, val_reg));
                self.instructions.push(EbpfInsn::end32_to_be(EbpfReg::R0));
                (Self::bpf_sock_addr_offsets().1, EbpfReg::R0)
            }
            CtxStoreTarget::CgroupSockAddrUserIp6Word(index) => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R0, val_reg));
                self.instructions.push(EbpfInsn::end32_to_be(EbpfReg::R0));
                (
                    Self::bpf_sock_addr_offsets().2 + i16::from(*index) * 4,
                    EbpfReg::R0,
                )
            }
            CtxStoreTarget::CgroupSockAddrUserPort => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R0, val_reg));
                self.instructions.push(EbpfInsn::lsh64_imm(EbpfReg::R0, 16));
                self.instructions.push(EbpfInsn::end32_to_be(EbpfReg::R0));
                (Self::bpf_sock_addr_offsets().3, EbpfReg::R0)
            }
            CtxStoreTarget::CgroupSockAddrMsgSrcIp4 => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R0, val_reg));
                self.instructions.push(EbpfInsn::end32_to_be(EbpfReg::R0));
                (Self::bpf_sock_addr_offsets().7, EbpfReg::R0)
            }
            CtxStoreTarget::CgroupSockAddrMsgSrcIp6Word(index) => {
                self.instructions
                    .push(EbpfInsn::mov64_reg(EbpfReg::R0, val_reg));
                self.instructions.push(EbpfInsn::end32_to_be(EbpfReg::R0));
                (
                    Self::bpf_sock_addr_offsets().8 + i16::from(*index) * 4,
                    EbpfReg::R0,
                )
            }
        };
        self.emit_store(EbpfReg::R9, offset, store_reg, size)?;
        Ok(())
    }

    pub(super) fn compile_emit_event_inst(
        &mut self,
        data: VReg,
        size: usize,
    ) -> Result<(), CompileError> {
        self.needs_ringbuf = true;
        self.register_single_emit_schema(data, size)?;
        let data_reg = self.ensure_reg(data)?;
        self.compile_emit_event(data_reg, size, self.vreg_stack_or_map_copy_size(data, size))
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

    pub(super) fn compile_load_global_inst(
        &mut self,
        dst: VReg,
        symbol: &str,
    ) -> Result<(), CompileError> {
        let dst_reg = self.alloc_dst_reg(dst)?;
        self.emit_map_fd_load(dst_reg, symbol);
        Ok(())
    }

    pub(super) fn compile_map_update_inst(
        &mut self,
        map: &crate::compiler::mir::MapRef,
        key: VReg,
        val: VReg,
        flags: u64,
    ) -> Result<(), CompileError> {
        if map.name == COUNTER_MAP_NAME {
            self.register_counter_map_kind(COUNTER_MAP_NAME, map.kind, None)?;
            self.validate_counter_key_operand(&map.name, key)?;
            let key_reg = self.ensure_reg(key)?;
            self.compile_counter_map_update(&map.name, key, key_reg)?;
        } else if map.name == STRING_COUNTER_MAP_NAME {
            self.register_counter_map_kind(STRING_COUNTER_MAP_NAME, map.kind, None)?;
            let key_reg = self.ensure_reg(key)?;
            self.validate_counter_key_operand(&map.name, key)?;
            self.compile_counter_map_update(&map.name, key, key_reg)?;
        } else if map.name == BYTES_COUNTER_MAP_NAME {
            let key_size = match self.current_types.get(&key) {
                Some(MirType::Ptr { pointee, .. }) => pointee.size().max(1) as u32,
                Some(ty) => ty.size().max(1) as u32,
                None => {
                    return Err(CompileError::UnsupportedInstruction(
                        "bytes_counters key size could not be inferred".into(),
                    ));
                }
            };
            self.register_counter_map_kind(BYTES_COUNTER_MAP_NAME, map.kind, Some(key_size))?;
            self.register_bytes_counter_key_schema(key)?;
            self.validate_counter_key_operand(&map.name, key)?;
            let key_reg = self.ensure_reg(key)?;
            self.compile_counter_map_update(&map.name, key, key_reg)?;
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

    pub(super) fn compile_map_push_inst(
        &mut self,
        map: &crate::compiler::mir::MapRef,
        val: VReg,
        flags: u64,
    ) -> Result<(), CompileError> {
        let val_reg = self.ensure_reg(val)?;
        self.compile_generic_map_push(map, val, val_reg, flags)
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
