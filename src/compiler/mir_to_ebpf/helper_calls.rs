use super::*;

impl<'a> MirToEbpfCompiler<'a> {
    /// Compile bpf_get_stackid() call to get kernel or user stack trace ID
    pub(super) fn compile_get_stackid(
        &mut self,
        dst: EbpfReg,
        map_name: &str,
        user_stack: bool,
    ) -> Result<(), CompileError> {
        // BPF_F_USER_STACK = 256, use 0 for kernel stack
        let flags: i32 = if user_stack { 256 } else { 0 };

        // R1 = ctx (restore from R9 where we saved it at program start)
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));

        // R2 = map fd (will be relocated by loader)
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R2);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: map_name.to_string(),
        });

        // R3 = flags
        self.instructions
            .push(EbpfInsn::mov64_imm(EbpfReg::R3, flags));

        // Call bpf_get_stackid
        self.instructions
            .push(EbpfInsn::call(BpfHelper::GetStackId));

        // Result (stack ID or negative error) is in R0, move to destination
        self.instructions
            .push(EbpfInsn::mov64_reg(dst, EbpfReg::R0));

        Ok(())
    }

    /// Compile bpf_tail_call(ctx, prog_array, index)
    pub(super) fn compile_tail_call(
        &mut self,
        map_name: &str,
        index: &MirValue,
    ) -> Result<(), CompileError> {
        // Load index into R3 before setting up helper args in R1/R2.
        // This avoids clobbering when the index vreg is allocated to R1/R2.
        let index_reg = self.value_to_reg(index)?;
        if index_reg != EbpfReg::R3 {
            self.instructions
                .push(EbpfInsn::mov64_reg(EbpfReg::R3, index_reg));
        }

        // R1 = ctx (restore from R9 where we saved it at program start)
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R9));

        // R2 = prog array map fd (relocated by loader)
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R2);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: map_name.to_string(),
        });

        self.instructions.push(EbpfInsn::call(BpfHelper::TailCall));
        Ok(())
    }

    /// Compile emit event to ring buffer
    pub(super) fn compile_emit_event(
        &mut self,
        data_reg: EbpfReg,
        size: usize,
    ) -> Result<(), CompileError> {
        let event_size = if size > 0 { size } else { 8 };
        self.check_stack_space(event_size as i16)?;
        // Stack grows downward - decrement first, then use offset
        self.stack_offset -= event_size as i16;
        let event_offset = self.stack_offset;

        if event_size <= 8 {
            // Store scalar data to stack
            self.instructions
                .push(EbpfInsn::stxdw(EbpfReg::R10, event_offset, data_reg));
        } else {
            if event_size % 8 != 0 {
                return Err(CompileError::UnsupportedInstruction(
                    "emit size must be 8-byte aligned for buffer output".into(),
                ));
            }
            // Copy buffer from pointer into stack
            for chunk in 0..(event_size / 8) {
                let offset = (chunk * 8) as i16;
                self.instructions
                    .push(EbpfInsn::ldxdw(EbpfReg::R0, data_reg, offset));
                self.instructions.push(EbpfInsn::stxdw(
                    EbpfReg::R10,
                    event_offset + offset,
                    EbpfReg::R0,
                ));
            }
        }

        // bpf_ringbuf_output(map, data, size, flags)
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: RINGBUF_MAP_NAME.to_string(),
        });

        // R2 = data pointer
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, event_offset as i32));

        // R3 = size
        self.instructions
            .push(EbpfInsn::mov64_imm(EbpfReg::R3, event_size as i32));

        // R4 = flags
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0));

        self.instructions
            .push(EbpfInsn::call(BpfHelper::RingbufOutput));

        Ok(())
    }

    /// Compile emit record to ring buffer
    pub(super) fn compile_emit_record(
        &mut self,
        fields: &[RecordFieldDef],
    ) -> Result<(), CompileError> {
        if fields.is_empty() {
            return Ok(());
        }

        // Build schema and calculate total size
        let mut schema_fields = Vec::new();
        let mut offset = 0usize;
        let mut total_size = 0usize;

        for field in fields {
            let (field_type, size) = self.mir_type_to_bpf_field(&field.ty);
            schema_fields.push(SchemaField {
                name: field.name.clone(),
                field_type,
                offset,
            });
            offset += size;
            total_size += size;
        }

        let new_schema = EventSchema {
            fields: schema_fields,
            total_size,
        };
        if let Some(existing) = &self.event_schema {
            if existing != &new_schema {
                return Err(CompileError::UnsupportedInstruction(
                    "emit record schema mismatch: multiple record shapes in one program".into(),
                ));
            }
        } else {
            // Store schema
            self.event_schema = Some(new_schema);
        }

        // Allocate contiguous buffer on stack
        self.check_stack_space(total_size as i16)?;
        self.stack_offset -= total_size as i16;
        let buffer_offset = self.stack_offset;

        // Copy each field value to the buffer
        let mut dest_offset = buffer_offset;
        for field in fields {
            let (_, size) = self.mir_type_to_bpf_field(&field.ty);

            // Get the field value into a register
            let field_reg = self.ensure_reg(field.value)?;

            // Store to the buffer
            // For 8-byte values, use stxdw
            if size == 8 {
                self.instructions
                    .push(EbpfInsn::stxdw(EbpfReg::R10, dest_offset, field_reg));
            } else if size == 4 {
                self.instructions
                    .push(EbpfInsn::stxw(EbpfReg::R10, dest_offset, field_reg));
            } else {
                // For larger types (like comm=16), copy in 8-byte chunks
                // The field_reg should be a pointer to the data
                for chunk in 0..(size / 8) {
                    self.instructions.push(EbpfInsn::ldxdw(
                        EbpfReg::R0,
                        field_reg,
                        (chunk * 8) as i16,
                    ));
                    self.instructions.push(EbpfInsn::stxdw(
                        EbpfReg::R10,
                        dest_offset + (chunk * 8) as i16,
                        EbpfReg::R0,
                    ));
                }
            }

            dest_offset += size as i16;
        }

        // Emit the buffer via ring buffer
        // bpf_ringbuf_output(map, data, size, flags)
        let reloc_offset = self.instructions.len() * 8;
        let [insn1, insn2] = EbpfInsn::ld_map_fd(EbpfReg::R1);
        self.instructions.push(insn1);
        self.instructions.push(insn2);
        self.relocations.push(MapRelocation {
            insn_offset: reloc_offset,
            map_name: RINGBUF_MAP_NAME.to_string(),
        });

        // R2 = pointer to buffer
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R2, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R2, buffer_offset as i32));

        // R3 = total size
        self.instructions
            .push(EbpfInsn::mov64_imm(EbpfReg::R3, total_size as i32));

        // R4 = flags
        self.instructions.push(EbpfInsn::mov64_imm(EbpfReg::R4, 0));

        self.instructions
            .push(EbpfInsn::call(BpfHelper::RingbufOutput));

        Ok(())
    }

    /// Convert MIR type to BPF field type and size
    /// Note: All sizes are aligned to 8 bytes for eBPF stack alignment requirements
    fn mir_type_to_bpf_field(&self, ty: &MirType) -> (BpfFieldType, usize) {
        match ty {
            MirType::I64 | MirType::U64 => (BpfFieldType::Int, 8),
            // I32 still uses 8 bytes for stack alignment
            MirType::I32 | MirType::U32 => (BpfFieldType::Int, 8),
            MirType::I16 | MirType::U16 => (BpfFieldType::Int, 8),
            MirType::I8 | MirType::U8 | MirType::Bool => (BpfFieldType::Int, 8),
            MirType::Array { elem, len } if matches!(elem.as_ref(), MirType::U8) && *len == 16 => {
                (BpfFieldType::Comm, 16)
            }
            MirType::Array { elem, len } if matches!(elem.as_ref(), MirType::U8) => {
                // Round up to 8-byte alignment
                let aligned_len = (*len + 7) & !7;
                (BpfFieldType::String, aligned_len)
            }
            _ => (BpfFieldType::Int, 8), // Default to 64-bit int
        }
    }

    /// Compile read string from user/kernel memory
    pub(super) fn compile_read_str(
        &mut self,
        dst_offset: i16,
        ptr_reg: EbpfReg,
        user_space: bool,
        max_len: usize,
    ) -> Result<(), CompileError> {
        // bpf_probe_read_{user,kernel}_str(dst, size, src)
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R1, EbpfReg::R10));
        self.instructions
            .push(EbpfInsn::add64_imm(EbpfReg::R1, dst_offset as i32));
        self.instructions
            .push(EbpfInsn::mov64_imm(EbpfReg::R2, max_len as i32));
        self.instructions
            .push(EbpfInsn::mov64_reg(EbpfReg::R3, ptr_reg));

        let helper = if user_space {
            BpfHelper::ProbeReadUserStr
        } else {
            BpfHelper::ProbeReadKernelStr
        };
        self.instructions.push(EbpfInsn::call(helper));

        Ok(())
    }
}
